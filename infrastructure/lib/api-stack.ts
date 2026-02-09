import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as codedeploy from "aws-cdk-lib/aws-codedeploy";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as ses from "aws-cdk-lib/aws-ses";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import * as cw_actions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { Construct } from "constructs";
import * as path from "path";

interface ApiStackProps extends cdk.StackProps {
  packagesTable: dynamodb.Table;
  apiKeysTable: dynamodb.Table;
  billingEventsTable: dynamodb.Table;
  referralEventsTable: dynamodb.Table;
  alertTopic?: sns.Topic;
  packageQueue?: sqs.Queue; // For package request API endpoint
}

export class ApiStack extends cdk.Stack {
  public readonly api: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const { packagesTable, apiKeysTable, billingEventsTable, referralEventsTable, alertTopic, packageQueue } = props;

    // ===========================================
    // Stripe Environment Variable Validation
    // ===========================================
    // Validate required Stripe price IDs at synth time for production deployments
    // Skip validation for dev and ci environments
    const isProduction = !["dev", "ci"].includes(process.env.CDK_ENV || "");
    if (isProduction) {
      const requiredStripeVars = [
        "STRIPE_PRICE_STARTER",
        "STRIPE_PRICE_PRO",
        "STRIPE_PRICE_BUSINESS",
      ];
      const missingVars = requiredStripeVars.filter((v) => !process.env[v]);
      if (missingVars.length > 0) {
        throw new Error(
          `Missing required Stripe price IDs for production: ${missingVars.join(", ")}. ` +
          `Set STRIPE_PRICE_STARTER, STRIPE_PRICE_PRO, STRIPE_PRICE_BUSINESS environment variables.`
        );
      }
    }

    // ===========================================
    // Build Identifier for Lambda Versioning
    // ===========================================
    // Use GITHUB_SHA or timestamp to ensure unique version hashes on each deployment.
    // This prevents "version already exists" errors after rollbacks.
    const buildId = process.env.GITHUB_SHA?.substring(0, 8) || Date.now().toString();

    // ===========================================
    // Secrets Manager: Stripe Secrets
    // ===========================================
    // Reference existing secrets (created manually before deployment)
    const stripeSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      "StripeSecret",
      "pkgwatch/stripe-secret"
    );

    const stripeWebhookSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      "StripeWebhookSecret",
      "pkgwatch/stripe-webhook"
    );

    // Explicit policy for Stripe secret access (fromSecretNameV2 grants don't work with suffixed ARNs)
    const stripeSecretPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["secretsmanager:GetSecretValue"],
      resources: [
        `arn:aws:secretsmanager:${this.region}:${this.account}:secret:pkgwatch/stripe-secret*`,
      ],
    });

    // ===========================================
    // Lambda: Common configuration
    // ===========================================
    const functionsDir = path.join(__dirname, "../../functions");

    // Bundle API handlers with shared module
    // Uses bundling to copy both api/ and shared/ directories
    const apiCodeWithShared = lambda.Code.fromAsset(functionsDir, {
      bundling: {
        image: lambda.Runtime.PYTHON_3_12.bundlingImage,
        command: [
          "bash",
          "-c",
          [
            // Preserve api/ directory structure for imports like 'from api.auth_callback'
            "cp -r /asset-input/api /asset-output/",
            // Copy shared/ directory
            "cp -r /asset-input/shared /asset-output/",
            // Install dependencies
            "pip install -r /asset-input/api/requirements.txt -t /asset-output/ --quiet",
          ].join(" && "),
        ],
      },
    });

    // Dev mode check for localhost CORS
    const isDevMode = process.env.CDK_ENV === "dev";

    const commonLambdaProps = {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64, // Graviton2 - ~20% cost savings
      memorySize: 512, // Increased from 256 - doubles vCPU, ~40% faster cold starts
      timeout: cdk.Duration.seconds(30),
      tracing: lambda.Tracing.ACTIVE, // Enable X-Ray tracing
      logRetention: logs.RetentionDays.TWO_WEEKS, // Prevent unbounded log storage costs
      environment: {
        PACKAGES_TABLE: packagesTable.tableName,
        API_KEYS_TABLE: apiKeysTable.tableName,
        BILLING_EVENTS_TABLE: billingEventsTable.tableName,
        REFERRAL_EVENTS_TABLE: referralEventsTable.tableName,
        STRIPE_SECRET_ARN: "pkgwatch/stripe-secret",  // Use name, not partial ARN
        STRIPE_WEBHOOK_SECRET_ARN: "pkgwatch/stripe-webhook",  // Use name, not partial ARN
        ...(isDevMode && { ALLOW_DEV_CORS: "true" }), // Allow localhost CORS in dev
      },
    };

    // ===========================================
    // Lambda: API Handlers
    // ===========================================

    // Health check handler (no auth required)
    const healthHandler = new lambda.Function(this, "HealthHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-health",
      handler: "api.health.handler",
      code: apiCodeWithShared,
      description: "API health check endpoint",
    });

    // Badge handler (no auth required - public endpoint for README embedding)
    const badgeHandler = new lambda.Function(this, "BadgeHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-badge",
      handler: "api.badge.handler",
      code: apiCodeWithShared,
      description: "SVG badge endpoint for package health scores",
    });

    packagesTable.grantReadData(badgeHandler);

    // Get package handler
    const getPackageHandler = new lambda.Function(this, "GetPackageHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-get-package",
      handler: "api.get_package.handler",
      code: apiCodeWithShared,
      description: `Get package health score [${buildId}]`,
      // Note: Removed reservedConcurrentExecutions to avoid account limit issues
    });

    packagesTable.grantReadData(getPackageHandler);
    apiKeysTable.grantReadWriteData(getPackageHandler);

    // Create alias for safe deployments with automatic rollback
    const getPackageAlias = new lambda.Alias(this, "GetPackageAlias", {
      aliasName: "live",
      version: getPackageHandler.currentVersion,
    });

    // Scan packages handler
    const scanHandler = new lambda.Function(this, "ScanHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-scan",
      handler: "api.post_scan.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.seconds(28), // API Gateway hard-limits at 29s; align Lambda to match
      memorySize: 1024, // Increased from 512 - heavy batch operations need more resources
      description: `Scan package.json for health scores [${buildId}]`,
      // Note: Removed reservedConcurrentExecutions to avoid account limit issues
      environment: {
        ...commonLambdaProps.environment,
        PACKAGE_QUEUE_URL: packageQueue?.queueUrl ?? "",
      },
    });

    packagesTable.grantReadData(scanHandler);
    apiKeysTable.grantReadWriteData(scanHandler);
    if (packageQueue) {
      packageQueue.grantSendMessages(scanHandler);
    }

    // Create alias for safe deployments with automatic rollback
    const scanAlias = new lambda.Alias(this, "ScanAlias", {
      aliasName: "live",
      version: scanHandler.currentVersion,
    });

    // Get usage handler
    const getUsageHandler = new lambda.Function(this, "GetUsageHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-get-usage",
      handler: "api.get_usage.handler",
      code: apiCodeWithShared,
      description: "Get API usage statistics",
    });

    apiKeysTable.grantReadData(getUsageHandler);

    // Stripe webhook handler
    const stripeWebhookHandler = new lambda.Function(
      this,
      "StripeWebhookHandler",
      {
        ...commonLambdaProps,
        functionName: "pkgwatch-api-stripe-webhook",
        handler: "api.stripe_webhook.handler",
        code: apiCodeWithShared,
        description: `Handle Stripe webhook events [${buildId}]`,
        environment: {
          ...commonLambdaProps.environment,
          // Stripe Price IDs for tier mapping - MUST be set to real Stripe price IDs
          STRIPE_PRICE_STARTER: process.env.STRIPE_PRICE_STARTER || "",
          STRIPE_PRICE_PRO: process.env.STRIPE_PRICE_PRO || "",
          STRIPE_PRICE_BUSINESS: process.env.STRIPE_PRICE_BUSINESS || "",
          // SNS topic for dispute/chargeback admin notifications
          ...(alertTopic && { ALERT_TOPIC_ARN: alertTopic.topicArn }),
          LOGIN_EMAIL_SENDER: "noreply@pkgwatch.dev",
        },
      }
    );

    apiKeysTable.grantReadWriteData(stripeWebhookHandler);
    billingEventsTable.grantReadWriteData(stripeWebhookHandler);
    stripeSecret.grantRead(stripeWebhookHandler);
    stripeWebhookSecret.grantRead(stripeWebhookHandler);
    if (alertTopic) {
      alertTopic.grantPublish(stripeWebhookHandler);
    }

    // Create alias for safe deployments with automatic rollback
    const stripeWebhookAlias = new lambda.Alias(this, "StripeWebhookAlias", {
      aliasName: "live",
      version: stripeWebhookHandler.currentVersion,
    });

    // Monthly usage reset handler (scheduled) - resets FREE tier users
    // Paid users with billing cycle data are skipped (reset via invoice.paid webhook)
    const resetUsageHandler = new lambda.Function(this, "ResetUsageHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-reset-usage",
      handler: "api.reset_usage.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.minutes(5), // Table scan may take time
      description: "Reset monthly usage counters on 1st of each month (free tier only)",
      environment: {
        ...commonLambdaProps.environment,
        BILLING_CYCLE_RESET_ENABLED: "true", // Set to "false" to disable per-user billing cycles
      },
    });

    apiKeysTable.grantReadWriteData(resetUsageHandler);

    // EventBridge rule for monthly reset at midnight UTC on 1st
    const resetRule = new events.Rule(this, "MonthlyUsageReset", {
      ruleName: "pkgwatch-monthly-usage-reset",
      schedule: events.Schedule.cron({
        minute: "0",
        hour: "0",
        day: "1",
        month: "*",
        year: "*",
      }),
      description: "Trigger monthly usage counter reset (free tier users)",
    });

    resetRule.addTarget(new targets.LambdaFunction(resetUsageHandler));

    // Backup usage reset handler (daily) - catches missed billing cycle resets
    const backupResetUsageHandler = new lambda.Function(
      this,
      "BackupResetUsageHandler",
      {
        ...commonLambdaProps,
        functionName: "pkgwatch-api-backup-reset-usage",
        handler: "api.reset_usage_backup.handler",
        code: apiCodeWithShared,
        timeout: cdk.Duration.minutes(5), // Table scan may take time
        description: "Daily backup reset for missed billing cycle resets",
      }
    );

    apiKeysTable.grantReadWriteData(backupResetUsageHandler);

    // EventBridge rule for daily backup reset at 00:05 UTC
    const backupResetRule = new events.Rule(this, "DailyBackupUsageReset", {
      ruleName: "pkgwatch-daily-backup-usage-reset",
      schedule: events.Schedule.cron({
        minute: "5",
        hour: "0",
        day: "*",
        month: "*",
        year: "*",
      }),
      description: "Daily backup trigger for missed billing cycle resets",
    });

    backupResetRule.addTarget(new targets.LambdaFunction(backupResetUsageHandler));

    // ===========================================
    // Auth/Signup Handlers
    // ===========================================

    // Session secret for JWT tokens - reference existing secret
    const sessionSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      "SessionSecret",
      "pkgwatch/session-secret"
    );

    // Explicit policy for session secret access (fromSecretNameV2 grants don't work with suffixed ARNs)
    const sessionSecretPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["secretsmanager:GetSecretValue"],
      resources: [
        `arn:aws:secretsmanager:${this.region}:${this.account}:secret:pkgwatch/session-secret*`,
      ],
    });

    // Create checkout session handler
    const createCheckoutHandler = new lambda.Function(
      this,
      "CreateCheckoutHandler",
      {
        ...commonLambdaProps,
        functionName: "pkgwatch-api-create-checkout",
        handler: "api.create_checkout.handler",
        code: apiCodeWithShared,
        description: "Create Stripe checkout session for upgrades",
        environment: {
          ...commonLambdaProps.environment,
          STRIPE_PRICE_STARTER: process.env.STRIPE_PRICE_STARTER || "",
          STRIPE_PRICE_PRO: process.env.STRIPE_PRICE_PRO || "",
          STRIPE_PRICE_BUSINESS: process.env.STRIPE_PRICE_BUSINESS || "",
          BASE_URL: "https://pkgwatch.dev",
          SESSION_SECRET_ARN: "pkgwatch/session-secret",
        },
      }
    );

    apiKeysTable.grantReadData(createCheckoutHandler);
    createCheckoutHandler.addToRolePolicy(stripeSecretPolicy);
    createCheckoutHandler.addToRolePolicy(sessionSecretPolicy);

    // Create billing portal session handler
    const createBillingPortalHandler = new lambda.Function(
      this,
      "CreateBillingPortalHandler",
      {
        ...commonLambdaProps,
        functionName: "pkgwatch-api-create-billing-portal",
        handler: "api.create_billing_portal.handler",
        code: apiCodeWithShared,
        description: "Create Stripe billing portal session for subscription management",
        environment: {
          ...commonLambdaProps.environment,
          BASE_URL: "https://pkgwatch.dev",
          SESSION_SECRET_ARN: "pkgwatch/session-secret",
        },
      }
    );

    apiKeysTable.grantReadData(createBillingPortalHandler);
    createBillingPortalHandler.addToRolePolicy(stripeSecretPolicy);
    createBillingPortalHandler.addToRolePolicy(sessionSecretPolicy);

    // Upgrade preview handler - preview prorated subscription upgrade
    const upgradePreviewHandler = new lambda.Function(
      this,
      "UpgradePreviewHandler",
      {
        ...commonLambdaProps,
        functionName: "pkgwatch-api-upgrade-preview",
        handler: "api.upgrade_preview.handler",
        code: apiCodeWithShared,
        description: "Preview prorated subscription upgrade",
        environment: {
          ...commonLambdaProps.environment,
          STRIPE_PRICE_STARTER: process.env.STRIPE_PRICE_STARTER || "",
          STRIPE_PRICE_PRO: process.env.STRIPE_PRICE_PRO || "",
          STRIPE_PRICE_BUSINESS: process.env.STRIPE_PRICE_BUSINESS || "",
          SESSION_SECRET_ARN: "pkgwatch/session-secret",
        },
      }
    );

    apiKeysTable.grantReadData(upgradePreviewHandler);
    upgradePreviewHandler.addToRolePolicy(stripeSecretPolicy);
    upgradePreviewHandler.addToRolePolicy(sessionSecretPolicy);

    // Upgrade confirm handler - execute prorated subscription upgrade
    const upgradeConfirmHandler = new lambda.Function(
      this,
      "UpgradeConfirmHandler",
      {
        ...commonLambdaProps,
        functionName: "pkgwatch-api-upgrade-confirm",
        handler: "api.upgrade_confirm.handler",
        code: apiCodeWithShared,
        description: "Execute prorated subscription upgrade",
        environment: {
          ...commonLambdaProps.environment,
          STRIPE_PRICE_STARTER: process.env.STRIPE_PRICE_STARTER || "",
          STRIPE_PRICE_PRO: process.env.STRIPE_PRICE_PRO || "",
          STRIPE_PRICE_BUSINESS: process.env.STRIPE_PRICE_BUSINESS || "",
          SESSION_SECRET_ARN: "pkgwatch/session-secret",
        },
      }
    );

    apiKeysTable.grantReadWriteData(upgradeConfirmHandler);
    upgradeConfirmHandler.addToRolePolicy(stripeSecretPolicy);
    upgradeConfirmHandler.addToRolePolicy(sessionSecretPolicy);

    // Common props for auth handlers
    const authLambdaProps = {
      ...commonLambdaProps,
      environment: {
        ...commonLambdaProps.environment,
        BASE_URL: "https://pkgwatch.dev",
        API_URL: "https://api.pkgwatch.dev",  // Used for magic link callbacks
        SESSION_SECRET_ARN: "pkgwatch/session-secret",  // Use name, not partial ARN
        VERIFICATION_EMAIL_SENDER: "noreply@pkgwatch.dev",
        LOGIN_EMAIL_SENDER: "noreply@pkgwatch.dev",
      },
    };

    // POST /signup - Create pending account
    const signupHandler = new lambda.Function(this, "SignupHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-signup",
      handler: "api.signup.handler",
      code: apiCodeWithShared,
      description: "User signup - creates pending account and sends verification email",
    });

    apiKeysTable.grantReadWriteData(signupHandler);

    // ===========================================
    // SES: Email Identity for domain verification
    // ===========================================
    const emailIdentity = new ses.EmailIdentity(this, "PkgWatchEmailIdentity", {
      identity: ses.Identity.domain("pkgwatch.dev"),
    });

    // Output DKIM tokens for DNS configuration
    new cdk.CfnOutput(this, "SesDkimTokens", {
      value: cdk.Fn.join(",", emailIdentity.dkimRecords.map(r => r.name)),
      description: "DKIM CNAME record names for DNS configuration",
    });

    // Grant SES permissions for email sending
    const sesPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["ses:SendEmail", "ses:SendRawEmail"],
      resources: [
        // Domain-level identity allows sending from any address @pkgwatch.dev
        `arn:aws:ses:${this.region}:${this.account}:identity/pkgwatch.dev`,
      ],
    });

    signupHandler.addToRolePolicy(sesPolicy);
    stripeWebhookHandler.addToRolePolicy(sesPolicy);

    // GET /verify - Verify email and create API key
    const verifyHandler = new lambda.Function(this, "VerifyEmailHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-verify-email",
      handler: "api.verify_email.handler",
      code: apiCodeWithShared,
      description: "Verify email and activate user account",
    });

    apiKeysTable.grantReadWriteData(verifyHandler);
    verifyHandler.addToRolePolicy(sessionSecretPolicy);

    // POST /auth/magic-link - Send login link
    const magicLinkHandler = new lambda.Function(this, "MagicLinkHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-magic-link",
      handler: "api.magic_link.handler",
      code: apiCodeWithShared,
      description: "Send magic link for passwordless authentication",
    });

    apiKeysTable.grantReadWriteData(magicLinkHandler);
    magicLinkHandler.addToRolePolicy(sesPolicy);

    // GET /auth/callback - Create session from magic link
    const authCallbackHandler = new lambda.Function(this, "AuthCallbackHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-auth-callback",
      handler: "api.auth_callback.handler",
      code: apiCodeWithShared,
      description: "Handle magic link callback and create session",
    });

    apiKeysTable.grantReadWriteData(authCallbackHandler);
    authCallbackHandler.addToRolePolicy(sessionSecretPolicy);

    // GET /auth/me - Get current user info
    const authMeHandler = new lambda.Function(this, "AuthMeHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-auth-me",
      handler: "api.auth_me.handler",
      code: apiCodeWithShared,
      description: "Get current authenticated user info",
    });

    apiKeysTable.grantReadData(authMeHandler);
    authMeHandler.addToRolePolicy(sessionSecretPolicy);

    // POST /auth/logout - Clear session cookie
    const logoutHandler = new lambda.Function(this, "LogoutHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-logout",
      handler: "api.logout.handler",
      code: apiCodeWithShared,
      description: "Clear session cookie to log out user",
    });
    // Logout doesn't need table access - just clears cookie

    // GET /auth/pending-key - Get newly created API key for one-time display
    const getPendingKeyHandler = new lambda.Function(this, "GetPendingKeyHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-get-pending-key",
      handler: "api.get_pending_key.handler",
      code: apiCodeWithShared,
      description: "Get pending API key for one-time display after verification",
    });

    apiKeysTable.grantReadWriteData(getPendingKeyHandler);
    getPendingKeyHandler.addToRolePolicy(sessionSecretPolicy);

    // GET /auth/pending-recovery-codes - Get newly generated recovery codes for one-time display
    const getPendingRecoveryCodesHandler = new lambda.Function(this, "GetPendingRecoveryCodesHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-get-pending-recovery-codes",
      handler: "api.auth_pending_recovery_codes.handler",
      code: apiCodeWithShared,
      description: "Get pending recovery codes for one-time display after verification",
    });

    apiKeysTable.grantReadWriteData(getPendingRecoveryCodesHandler);
    getPendingRecoveryCodesHandler.addToRolePolicy(sessionSecretPolicy);

    // POST /auth/resend-verification - Resend verification email with cooldown
    const resendVerificationHandler = new lambda.Function(this, "ResendVerificationHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-resend-verification",
      handler: "api.resend_verification.handler",
      code: apiCodeWithShared,
      description: "Resend verification email for pending signups",
    });

    apiKeysTable.grantReadWriteData(resendVerificationHandler);
    resendVerificationHandler.addToRolePolicy(sesPolicy);

    // GET /api-keys - List user's API keys
    const getApiKeysHandler = new lambda.Function(this, "GetApiKeysHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-get-api-keys",
      handler: "api.get_api_keys.handler",
      code: apiCodeWithShared,
      description: "List all API keys for authenticated user",
    });

    apiKeysTable.grantReadData(getApiKeysHandler);
    getApiKeysHandler.addToRolePolicy(sessionSecretPolicy);

    // POST /api-keys - Create new API key
    const createApiKeyHandler = new lambda.Function(this, "CreateApiKeyHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-create-api-key",
      handler: "api.create_api_key.handler",
      code: apiCodeWithShared,
      description: "Create new API key for authenticated user",
    });

    apiKeysTable.grantReadWriteData(createApiKeyHandler);
    createApiKeyHandler.addToRolePolicy(sessionSecretPolicy);

    // DELETE /api-keys/{key_id} - Revoke API key
    const revokeApiKeyHandler = new lambda.Function(this, "RevokeApiKeyHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-revoke-api-key",
      handler: "api.revoke_api_key.handler",
      code: apiCodeWithShared,
      description: "Revoke API key for authenticated user",
    });

    apiKeysTable.grantReadWriteData(revokeApiKeyHandler);
    revokeApiKeyHandler.addToRolePolicy(sessionSecretPolicy);

    // ===========================================
    // Package Request Handler (with collectors for validation)
    // ===========================================

    // Bundle API code with collectors for package validation
    const apiWithCollectorsCode = lambda.Code.fromAsset(functionsDir, {
      bundling: {
        image: lambda.Runtime.PYTHON_3_12.bundlingImage,
        command: [
          "bash",
          "-c",
          [
            "cp -r /asset-input/api /asset-output/",
            "cp -r /asset-input/shared /asset-output/",
            "cp -r /asset-input/collectors /asset-output/",
            "pip install -r /asset-input/collectors/requirements.txt -t /asset-output/ --quiet",
          ].join(" && "),
        ],
      },
    });

    // POST /packages/request - Request new package to be tracked
    const requestPackageHandler = new lambda.Function(this, "RequestPackageHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-request-package",
      handler: "api.request_package.handler",
      code: apiWithCollectorsCode,
      description: "Request a new package to be tracked",
      environment: {
        ...commonLambdaProps.environment,
        PACKAGE_QUEUE_URL: packageQueue?.queueUrl ?? "",
      },
    });

    packagesTable.grantReadWriteData(requestPackageHandler);
    apiKeysTable.grantReadWriteData(requestPackageHandler); // For rate limiting
    if (packageQueue) {
      packageQueue.grantSendMessages(requestPackageHandler);
    }

    // ===========================================
    // API Gateway
    // ===========================================
    this.api = new apigateway.RestApi(this, "PkgWatchApi", {
      restApiName: "PkgWatch API",
      description: "Package Watch API",
      minimumCompressionSize: 1024, // Compress responses > 1KB (60-80% reduction)
      deployOptions: {
        stageName: "v1",
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
        loggingLevel: apigateway.MethodLoggingLevel.ERROR, // ERROR only - INFO may log API keys in headers
        dataTraceEnabled: false,
        metricsEnabled: true,
        tracingEnabled: true, // Enable X-Ray tracing for end-to-end traces
        cachingEnabled: false,
        cacheClusterEnabled: false,
        // Cache disabled to save ~$14/month - not cost-effective at current traffic levels
        // Per-method settings (caching disabled globally)
        methodOptions: {
          "/packages/{ecosystem}/{name}/GET": {
            cachingEnabled: false,
          },
          // Disable caching for user-specific endpoints that change frequently
          "/auth/me/GET": {
            cachingEnabled: false,
          },
          "/api-keys/GET": {
            cachingEnabled: false,
          },
          "/api-keys/POST": {
            cachingEnabled: false,
          },
          "/api-keys/{key_id}/DELETE": {
            cachingEnabled: false,
          },
          "/usage/GET": {
            cachingEnabled: false,
          },
          "/scan/POST": {
            cachingEnabled: false,
          },
          "/checkout/create/POST": {
            cachingEnabled: false,
          },
          "/billing-portal/create/POST": {
            cachingEnabled: false,
          },
          "/upgrade/preview/POST": {
            cachingEnabled: false,
          },
          "/upgrade/confirm/POST": {
            cachingEnabled: false,
          },
        },
      },
      defaultCorsPreflightOptions: {
        // CORS origins - localhost only allowed in dev mode
        allowOrigins: isDevMode
          ? [
              "https://pkgwatch.dev",
              "http://localhost:3000", // For local development
              "http://localhost:4321", // Astro dev server
            ]
          : ["https://pkgwatch.dev"],
        allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
        allowHeaders: [
          "Content-Type",
          "X-API-Key",
          "X-Amz-Date",
          "Authorization",
          "Cookie",
        ],
        allowCredentials: true, // Required for cookies to be sent
      },
    });

    // ===========================================
    // Gateway Responses (CORS headers for API Gateway errors)
    // ===========================================
    // When API Gateway returns errors (e.g., validation failures), these ensure
    // CORS headers are included so the browser can read the error message.

    const corsResponseHeaders = {
      "Access-Control-Allow-Origin": "'https://pkgwatch.dev'",
      "Access-Control-Allow-Headers":
        "'Content-Type,X-API-Key,Authorization,Cookie'",
      "Access-Control-Allow-Methods": "'GET,POST,DELETE,OPTIONS'",
      "Access-Control-Allow-Credentials": "'true'",
    };

    // 4XX errors (client errors like validation failures)
    this.api.addGatewayResponse("Default4XX", {
      type: apigateway.ResponseType.DEFAULT_4XX,
      responseHeaders: corsResponseHeaders,
    });

    // 5XX errors (server errors)
    this.api.addGatewayResponse("Default5XX", {
      type: apigateway.ResponseType.DEFAULT_5XX,
      responseHeaders: corsResponseHeaders,
    });

    // Specific: Bad request body (validation failures)
    this.api.addGatewayResponse("BadRequestBody", {
      type: apigateway.ResponseType.BAD_REQUEST_BODY,
      responseHeaders: corsResponseHeaders,
      templates: {
        "application/json": JSON.stringify({
          error: {
            code: "validation_error",
            message: "$context.error.validationErrorString",
          },
        }),
      },
    });

    // ===========================================
    // Request Validators & Models (Security - validate POST bodies before Lambda)
    // ===========================================

    // Request validator for body validation
    const bodyValidator = new apigateway.RequestValidator(this, "BodyValidator", {
      restApi: this.api,
      requestValidatorName: "validate-body",
      validateRequestBody: true,
      validateRequestParameters: false,
    });

    // Model for /scan endpoint
    // Handler accepts either: {"content": "<package.json string>"} or {"dependencies": {...}}
    // JSON Schema cannot express "at least one of" - handler validates this and returns clear error
    const scanModel = new apigateway.Model(this, "ScanModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "ScanRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        properties: {
          content: {
            type: apigateway.JsonSchemaType.STRING,
            description: "package.json content as string",
          },
          dependencies: {
            type: apigateway.JsonSchemaType.OBJECT,
            description: "Dependencies object from package.json or requirements",
          },
          devDependencies: {
            type: apigateway.JsonSchemaType.OBJECT,
            description: "Dev dependencies object from package.json",
          },
          ecosystem: {
            type: apigateway.JsonSchemaType.STRING,
            description: "Package ecosystem: npm or pypi",
            enum: ["npm", "pypi"],
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /signup endpoint
    const signupModel = new apigateway.Model(this, "SignupModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "SignupRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["email"],
        properties: {
          email: {
            type: apigateway.JsonSchemaType.STRING,
            format: "email",
            minLength: 5,
            maxLength: 254,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /auth/magic-link endpoint
    const magicLinkModel = new apigateway.Model(this, "MagicLinkModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "MagicLinkRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["email"],
        properties: {
          email: {
            type: apigateway.JsonSchemaType.STRING,
            format: "email",
            minLength: 5,
            maxLength: 254,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /auth/resend-verification endpoint
    const resendVerificationModel = new apigateway.Model(this, "ResendVerificationModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "ResendVerificationRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["email"],
        properties: {
          email: {
            type: apigateway.JsonSchemaType.STRING,
            format: "email",
            minLength: 5,
            maxLength: 254,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /checkout/create endpoint
    const createCheckoutModel = new apigateway.Model(this, "CreateCheckoutModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "CreateCheckoutRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["tier"],
        properties: {
          tier: {
            type: apigateway.JsonSchemaType.STRING,
            enum: ["starter", "pro", "business"],
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /upgrade/confirm endpoint
    const upgradeConfirmModel = new apigateway.Model(this, "UpgradeConfirmModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "UpgradeConfirmRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["tier", "proration_date"],
        properties: {
          tier: {
            type: apigateway.JsonSchemaType.STRING,
            enum: ["pro", "business"],
          },
          proration_date: {
            type: apigateway.JsonSchemaType.INTEGER,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /api-keys POST endpoint
    // Note: name is optional - handler defaults to "Key {n}" if not provided
    const createApiKeyModel = new apigateway.Model(this, "CreateApiKeyModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "CreateApiKeyRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        properties: {
          name: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 100,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /packages/request endpoint
    const requestPackageModel = new apigateway.Model(this, "RequestPackageModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "RequestPackageRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["name"],
        properties: {
          name: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 256,
            description: "Package name to request tracking for",
          },
          ecosystem: {
            type: apigateway.JsonSchemaType.STRING,
            enum: ["npm", "pypi"],
            description: "Package ecosystem (defaults to npm)",
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /recovery/initiate endpoint
    const recoveryInitiateModel = new apigateway.Model(this, "RecoveryInitiateModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "RecoveryInitiateRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["email"],
        properties: {
          email: {
            type: apigateway.JsonSchemaType.STRING,
            format: "email",
            minLength: 5,
            maxLength: 254,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /recovery/verify-api-key endpoint
    const recoveryVerifyApiKeyModel = new apigateway.Model(this, "RecoveryVerifyApiKeyModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "RecoveryVerifyApiKeyRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["recovery_session_id", "api_key"],
        properties: {
          recovery_session_id: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 100,
          },
          api_key: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 100,
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /recovery/verify-code endpoint
    const recoveryVerifyCodeModel = new apigateway.Model(this, "RecoveryVerifyCodeModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "RecoveryVerifyCodeRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["recovery_session_id", "recovery_code"],
        properties: {
          recovery_session_id: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 100,
          },
          recovery_code: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 50,
            description: "Recovery code in format XXXX-XXXX-XXXX-XXXX",
          },
        },
        additionalProperties: false,
      },
    });

    // Model for /recovery/update-email endpoint
    const recoveryUpdateEmailModel = new apigateway.Model(this, "RecoveryUpdateEmailModel", {
      restApi: this.api,
      contentType: "application/json",
      modelName: "RecoveryUpdateEmailRequest",
      schema: {
        type: apigateway.JsonSchemaType.OBJECT,
        required: ["recovery_token", "new_email"],
        properties: {
          recovery_token: {
            type: apigateway.JsonSchemaType.STRING,
            minLength: 1,
            maxLength: 100,
          },
          new_email: {
            type: apigateway.JsonSchemaType.STRING,
            format: "email",
            minLength: 5,
            maxLength: 254,
          },
        },
        additionalProperties: false,
      },
    });

    // ===========================================
    // API Routes
    // ===========================================

    // GET /health (no auth)
    const healthResource = this.api.root.addResource("health");
    healthResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(healthHandler)
    );

    // GET /badge/{ecosystem}/{name} (no auth - public SVG badge)
    const badgeResource = this.api.root.addResource("badge");
    const badgeEcosystemResource = badgeResource.addResource("{ecosystem}");
    const badgeNameResource = badgeEcosystemResource.addResource("{name}");
    badgeNameResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(badgeHandler)
    );

    // GET /packages/{ecosystem}/{name}
    const packagesResource = this.api.root.addResource("packages");
    const ecosystemResource = packagesResource.addResource("{ecosystem}");
    const packageNameResource = ecosystemResource.addResource("{name}");
    packageNameResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getPackageAlias, {
        // Include path parameters and Origin header in cache key
        // Origin is required so CORS headers are cached correctly per origin
        cacheKeyParameters: [
          "method.request.path.ecosystem",
          "method.request.path.name",
          "method.request.header.Origin",
        ],
      }),
      {
        // Map path parameters and Origin header for cache key
        requestParameters: {
          "method.request.path.ecosystem": true,
          "method.request.path.name": true,
          "method.request.header.Origin": false, // false = optional (not required)
        },
      }
    );

    // POST /packages/request - Request new package tracking
    const requestResource = packagesResource.addResource("request");
    requestResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(requestPackageHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": requestPackageModel,
        },
      }
    );

    // POST /scan (with request validation)
    const scanResource = this.api.root.addResource("scan");
    scanResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(scanAlias),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": scanModel,
        },
      }
    );

    // GET /usage
    const usageResource = this.api.root.addResource("usage");
    usageResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getUsageHandler)
    );

    // POST /webhooks/stripe (no auth - uses Stripe signature)
    const webhooksResource = this.api.root.addResource("webhooks");
    const stripeWebhookResource = webhooksResource.addResource("stripe");
    stripeWebhookResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(stripeWebhookAlias)
    );

    // POST /checkout/create (session auth)
    const checkoutResource = this.api.root.addResource("checkout");
    const createCheckoutResource = checkoutResource.addResource("create");
    createCheckoutResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(createCheckoutHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": createCheckoutModel,
        },
      }
    );

    // POST /billing-portal/create (session auth - no body required)
    const billingPortalResource = this.api.root.addResource("billing-portal");
    const createBillingPortalResource = billingPortalResource.addResource("create");
    createBillingPortalResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(createBillingPortalHandler)
    );

    // ===========================================
    // Upgrade Routes (prorated subscription upgrades)
    // ===========================================

    const upgradeResource = this.api.root.addResource("upgrade");

    // POST /upgrade/preview - Preview prorated upgrade cost
    const upgradePreviewResource = upgradeResource.addResource("preview");
    upgradePreviewResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(upgradePreviewHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": createCheckoutModel, // Same schema: { tier: string }
        },
      }
    );

    // POST /upgrade/confirm - Execute prorated upgrade
    const upgradeConfirmResource = upgradeResource.addResource("confirm");
    upgradeConfirmResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(upgradeConfirmHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": upgradeConfirmModel,
        },
      }
    );

    // ===========================================
    // Auth/Signup Routes
    // ===========================================

    // POST /signup (with request validation)
    const signupResource = this.api.root.addResource("signup");
    signupResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(signupHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": signupModel,
        },
      }
    );

    // GET /verify?token=xxx
    const verifyResource = this.api.root.addResource("verify");
    verifyResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(verifyHandler)
    );

    // /auth routes
    const authResource = this.api.root.addResource("auth");

    // POST /auth/magic-link (with request validation)
    const magicLinkResource = authResource.addResource("magic-link");
    magicLinkResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(magicLinkHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": magicLinkModel,
        },
      }
    );

    // GET /auth/callback?token=xxx
    const callbackResource = authResource.addResource("callback");
    callbackResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(authCallbackHandler)
    );

    // GET /auth/me
    const meResource = authResource.addResource("me");
    meResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(authMeHandler)
    );

    // POST /auth/logout
    const logoutResource = authResource.addResource("logout");
    logoutResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(logoutHandler)
    );

    // GET /auth/pending-key
    const pendingKeyResource = authResource.addResource("pending-key");
    pendingKeyResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getPendingKeyHandler)
    );

    // GET /auth/pending-recovery-codes
    const pendingRecoveryCodesResource = authResource.addResource("pending-recovery-codes");
    pendingRecoveryCodesResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getPendingRecoveryCodesHandler)
    );

    // POST /auth/resend-verification
    const resendVerificationResource = authResource.addResource("resend-verification");
    resendVerificationResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(resendVerificationHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": resendVerificationModel,
        },
      }
    );

    // /api-keys routes
    const apiKeysResource = this.api.root.addResource("api-keys");

    // GET /api-keys
    apiKeysResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getApiKeysHandler)
    );

    // POST /api-keys (with request validation)
    apiKeysResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(createApiKeyHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": createApiKeyModel,
        },
      }
    );

    // DELETE /api-keys/{key_id}
    const apiKeyIdResource = apiKeysResource.addResource("{key_id}");
    apiKeyIdResource.addMethod(
      "DELETE",
      new apigateway.LambdaIntegration(revokeApiKeyHandler)
    );

    // ===========================================
    // Account Recovery Handlers
    // ===========================================

    // Account recovery codes handler (authenticated)
    const accountRecoveryCodesHandler = new lambda.Function(this, "AccountRecoveryCodesHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-account-recovery-codes",
      handler: "api.account_recovery_codes.handler",
      code: apiCodeWithShared,
      description: "Manage recovery codes for account recovery",
    });

    apiKeysTable.grantReadWriteData(accountRecoveryCodesHandler);
    accountRecoveryCodesHandler.addToRolePolicy(sessionSecretPolicy);

    // Recovery initiate handler (unauthenticated)
    const recoveryInitiateHandler = new lambda.Function(this, "RecoveryInitiateHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-recovery-initiate",
      handler: "api.recovery_initiate.handler",
      code: apiCodeWithShared,
      description: "Start account recovery flow",
    });

    apiKeysTable.grantReadWriteData(recoveryInitiateHandler);

    // Recovery verify API key handler (unauthenticated)
    const recoveryVerifyApiKeyHandler = new lambda.Function(this, "RecoveryVerifyApiKeyHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-recovery-verify-api-key",
      handler: "api.recovery_verify_api_key.handler",
      code: apiCodeWithShared,
      description: "Verify recovery via API key (sends magic link)",
    });

    apiKeysTable.grantReadWriteData(recoveryVerifyApiKeyHandler);
    recoveryVerifyApiKeyHandler.addToRolePolicy(sesPolicy);

    // Recovery verify code handler (unauthenticated)
    const recoveryVerifyCodeHandler = new lambda.Function(this, "RecoveryVerifyCodeHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-recovery-verify-code",
      handler: "api.recovery_verify_code.handler",
      code: apiCodeWithShared,
      description: "Verify recovery via recovery code",
    });

    apiKeysTable.grantReadWriteData(recoveryVerifyCodeHandler);

    // Recovery update email handler (unauthenticated, requires recovery token)
    const recoveryUpdateEmailHandler = new lambda.Function(this, "RecoveryUpdateEmailHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-recovery-update-email",
      handler: "api.recovery_update_email.handler",
      code: apiCodeWithShared,
      description: "Update email address after recovery code verification",
    });

    apiKeysTable.grantReadWriteData(recoveryUpdateEmailHandler);
    recoveryUpdateEmailHandler.addToRolePolicy(sesPolicy);

    // Recovery confirm email handler (GET callback)
    const recoveryConfirmEmailHandler = new lambda.Function(this, "RecoveryConfirmEmailHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-recovery-confirm-email",
      handler: "api.recovery_confirm_email.handler",
      code: apiCodeWithShared,
      description: "Confirm email change and complete recovery",
    });

    apiKeysTable.grantReadWriteData(recoveryConfirmEmailHandler);
    recoveryConfirmEmailHandler.addToRolePolicy(sessionSecretPolicy);
    recoveryConfirmEmailHandler.addToRolePolicy(sesPolicy);

    // ===========================================
    // Lambda: Referral Handlers
    // ===========================================

    // GET /referral/status - Get referral program status
    const referralStatusHandler = new lambda.Function(this, "ReferralStatusHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-referral-status",
      handler: "api.referral_status.handler",
      code: apiCodeWithShared,
      description: "Get referral program status and stats",
    });

    apiKeysTable.grantReadWriteData(referralStatusHandler);
    referralEventsTable.grantReadData(referralStatusHandler);
    referralStatusHandler.addToRolePolicy(sessionSecretPolicy);

    // GET /r/{code} - Referral URL redirect
    const referralRedirectHandler = new lambda.Function(this, "ReferralRedirectHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-referral-redirect",
      handler: "api.referral_redirect.handler",
      code: apiCodeWithShared,
      description: "Redirect referral URLs to start page",
    });

    // POST /referral/add-code - Add referral code (late entry)
    const addReferralCodeHandler = new lambda.Function(this, "AddReferralCodeHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-add-referral-code",
      handler: "api.add_referral_code.handler",
      code: apiCodeWithShared,
      description: "Add referral code within 14 days of signup",
    });

    apiKeysTable.grantReadWriteData(addReferralCodeHandler);
    referralEventsTable.grantReadWriteData(addReferralCodeHandler);
    addReferralCodeHandler.addToRolePolicy(sessionSecretPolicy);

    // Scheduled: Referral retention check (daily at 1:30 AM UTC)
    const referralRetentionHandler = new lambda.Function(this, "ReferralRetentionHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-referral-retention",
      handler: "api.referral_retention_check.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.minutes(5),
      description: "Check and award retention bonuses for referrals",
    });

    apiKeysTable.grantReadWriteData(referralRetentionHandler);
    referralEventsTable.grantReadWriteData(referralRetentionHandler);
    referralRetentionHandler.addToRolePolicy(stripeSecretPolicy);

    new events.Rule(this, "DailyReferralRetention", {
      ruleName: "pkgwatch-referral-retention-check",
      description: "Daily check for referral retention bonuses",
      schedule: events.Schedule.cron({ minute: "30", hour: "1" }),
      targets: [new targets.LambdaFunction(referralRetentionHandler)],
    });

    // Scheduled: Referral cleanup (daily at 2:00 AM UTC)
    const referralCleanupHandler = new lambda.Function(this, "ReferralCleanupHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-referral-cleanup",
      handler: "api.referral_cleanup.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.minutes(5),
      description: "Clean up stale pending referrals",
    });

    apiKeysTable.grantReadWriteData(referralCleanupHandler);

    new events.Rule(this, "DailyReferralCleanup", {
      ruleName: "pkgwatch-referral-cleanup",
      description: "Daily cleanup of stale pending referrals",
      schedule: events.Schedule.cron({ minute: "0", hour: "2" }),
      targets: [new targets.LambdaFunction(referralCleanupHandler)],
    });

    // ===========================================
    // Account Recovery Routes
    // ===========================================

    // /account routes
    const accountResource = this.api.root.addResource("account");

    // /account/recovery-codes - GET/POST/DELETE
    const recoveryCodesResource = accountResource.addResource("recovery-codes");
    recoveryCodesResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(accountRecoveryCodesHandler)
    );
    recoveryCodesResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(accountRecoveryCodesHandler)
    );
    recoveryCodesResource.addMethod(
      "DELETE",
      new apigateway.LambdaIntegration(accountRecoveryCodesHandler)
    );

    // /recovery routes (unauthenticated)
    const recoveryResource = this.api.root.addResource("recovery");

    // POST /recovery/initiate (with request validation)
    const recoveryInitiateResource = recoveryResource.addResource("initiate");
    recoveryInitiateResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(recoveryInitiateHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": recoveryInitiateModel,
        },
      }
    );

    // POST /recovery/verify-api-key (with request validation)
    const recoveryVerifyApiKeyResource = recoveryResource.addResource("verify-api-key");
    recoveryVerifyApiKeyResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(recoveryVerifyApiKeyHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": recoveryVerifyApiKeyModel,
        },
      }
    );

    // POST /recovery/verify-code (with request validation)
    const recoveryVerifyCodeResource = recoveryResource.addResource("verify-code");
    recoveryVerifyCodeResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(recoveryVerifyCodeHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": recoveryVerifyCodeModel,
        },
      }
    );

    // POST /recovery/update-email (with request validation)
    const recoveryUpdateEmailResource = recoveryResource.addResource("update-email");
    recoveryUpdateEmailResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(recoveryUpdateEmailHandler),
      {
        requestValidator: bodyValidator,
        requestModels: {
          "application/json": recoveryUpdateEmailModel,
        },
      }
    );

    // GET /recovery/confirm-email?token=xxx
    const recoveryConfirmEmailResource = recoveryResource.addResource("confirm-email");
    recoveryConfirmEmailResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(recoveryConfirmEmailHandler)
    );

    // ===========================================
    // Referral Routes
    // ===========================================

    // /referral routes
    const referralResource = this.api.root.addResource("referral");

    // GET /referral/status
    const referralStatusResource = referralResource.addResource("status");
    referralStatusResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(referralStatusHandler)
    );

    // POST /referral/add-code
    const addCodeResource = referralResource.addResource("add-code");
    addCodeResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(addReferralCodeHandler)
    );

    // GET /r/{code} - Clean referral URL redirect
    const rResource = this.api.root.addResource("r");
    const codeResource = rResource.addResource("{code}");
    codeResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(referralRedirectHandler)
    );

    // ===========================================
    // WAF: Web Application Firewall
    // ===========================================
    const webAcl = new wafv2.CfnWebACL(this, "ApiWaf", {
      name: "pkgwatch-api-waf",
      defaultAction: { allow: {} },
      scope: "REGIONAL",
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "PkgWatchApiWaf",
        sampledRequestsEnabled: true,
      },
      rules: [
        // AWS Managed Rules - Common Rule Set
        {
          name: "AWSManagedRulesCommonRuleSet",
          priority: 10,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesCommonRuleSet",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "CommonRuleSet",
            sampledRequestsEnabled: true,
          },
        },
        // AWS Managed Rules - Known Bad Inputs
        {
          name: "AWSManagedRulesKnownBadInputsRuleSet",
          priority: 20,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesKnownBadInputsRuleSet",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "KnownBadInputsRuleSet",
            sampledRequestsEnabled: true,
          },
        },
        // AWS Managed Rules - IP Reputation
        {
          name: "AWSManagedRulesAmazonIpReputationList",
          priority: 25,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesAmazonIpReputationList",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "IpReputationList",
            sampledRequestsEnabled: true,
          },
        },
        // AWS Managed Rules - SQL Injection Protection
        {
          name: "AWSManagedRulesSQLiRuleSet",
          priority: 27,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesSQLiRuleSet",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "SQLiRuleSet",
            sampledRequestsEnabled: true,
          },
        },
        // Rate Limiting - 500 requests per 5 minutes per IP (100/min)
        // CI/CD pipelines scanning large repos need headroom; app-level quotas enforce tier limits
        {
          name: "RateLimitRule",
          priority: 30,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 500, // 100/min per IP; app-level quotas enforce business limits
              aggregateKeyType: "IP",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "RateLimitRule",
            sampledRequestsEnabled: true,
          },
        },
      ],
    });

    // Associate WAF with API Gateway stage
    new wafv2.CfnWebACLAssociation(this, "WafAssociation", {
      resourceArn: this.api.deploymentStage.stageArn,
      webAclArn: webAcl.attrArn,
    });

    // ===========================================
    // CloudWatch Alarms for API Lambdas
    // ===========================================

    // Helper to create standard Lambda alarms
    // Returns { allAlarms, errorAlarm } so error alarm can be used for CodeDeploy rollback
    const createLambdaAlarms = (
      fn: lambda.Function,
      name: string
    ): { allAlarms: cloudwatch.Alarm[]; errorAlarm: cloudwatch.Alarm } => {
      const alarms: cloudwatch.Alarm[] = [];

      // Error rate alarm (> 5% errors over 5 minutes)
      const errorAlarm = new cloudwatch.Alarm(this, `${name}ErrorAlarm`, {
        alarmName: `pkgwatch-api-${name.toLowerCase()}-errors`,
        alarmDescription: `High error rate on ${name} Lambda`,
        metric: fn.metricErrors({
          period: cdk.Duration.minutes(5),
          statistic: "Sum",
        }),
        threshold: 5,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarms.push(errorAlarm);

      // Duration alarm (P99 > 80% of timeout)
      const timeoutMs = fn.timeout?.toMilliseconds() ?? 30000;
      const durationAlarm = new cloudwatch.Alarm(this, `${name}DurationAlarm`, {
        alarmName: `pkgwatch-api-${name.toLowerCase()}-duration`,
        alarmDescription: `High latency on ${name} Lambda (approaching timeout)`,
        metric: fn.metricDuration({
          period: cdk.Duration.minutes(5),
          statistic: "p99",
        }),
        threshold: timeoutMs * 0.8,
        evaluationPeriods: 2,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarms.push(durationAlarm);

      // Throttle alarm (any throttles)
      const throttleAlarm = new cloudwatch.Alarm(this, `${name}ThrottleAlarm`, {
        alarmName: `pkgwatch-api-${name.toLowerCase()}-throttles`,
        alarmDescription: `Throttling detected on ${name} Lambda`,
        metric: fn.metricThrottles({
          period: cdk.Duration.minutes(5),
          statistic: "Sum",
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarms.push(throttleAlarm);

      // Wire up to SNS if provided (both alarm and recovery notifications)
      if (alertTopic) {
        alarms.forEach((alarm) => {
          alarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
          alarm.addOkAction(new cw_actions.SnsAction(alertTopic));
        });
      }

      return { allAlarms: alarms, errorAlarm };
    };

    // Create alarms for all API endpoints
    // Store error alarms from critical handlers for CodeDeploy rollback
    createLambdaAlarms(healthHandler, "Health");
    createLambdaAlarms(badgeHandler, "Badge");
    const getPackageAlarms = createLambdaAlarms(getPackageHandler, "GetPackage");
    const scanAlarms = createLambdaAlarms(scanHandler, "Scan");
    createLambdaAlarms(getUsageHandler, "GetUsage");
    const stripeWebhookAlarms = createLambdaAlarms(stripeWebhookHandler, "StripeWebhook");
    createLambdaAlarms(createCheckoutHandler, "CreateCheckout");
    createLambdaAlarms(createBillingPortalHandler, "CreateBillingPortal");
    createLambdaAlarms(upgradePreviewHandler, "UpgradePreview");
    createLambdaAlarms(upgradeConfirmHandler, "UpgradeConfirm");
    createLambdaAlarms(resetUsageHandler, "ResetUsage");

    // Auth/signup Lambda alarms - critical for user access
    createLambdaAlarms(signupHandler, "Signup");
    createLambdaAlarms(verifyHandler, "VerifyEmail");
    createLambdaAlarms(magicLinkHandler, "MagicLink");
    createLambdaAlarms(authCallbackHandler, "AuthCallback");
    createLambdaAlarms(authMeHandler, "AuthMe");
    createLambdaAlarms(getPendingKeyHandler, "GetPendingKey");
    createLambdaAlarms(getPendingRecoveryCodesHandler, "GetPendingRecoveryCodes");
    createLambdaAlarms(resendVerificationHandler, "ResendVerification");
    createLambdaAlarms(getApiKeysHandler, "GetApiKeys");
    createLambdaAlarms(createApiKeyHandler, "CreateApiKey");
    createLambdaAlarms(revokeApiKeyHandler, "RevokeApiKey");
    createLambdaAlarms(requestPackageHandler, "RequestPackage");

    // Account recovery Lambda alarms
    createLambdaAlarms(accountRecoveryCodesHandler, "AccountRecoveryCodes");
    createLambdaAlarms(recoveryInitiateHandler, "RecoveryInitiate");
    createLambdaAlarms(recoveryVerifyApiKeyHandler, "RecoveryVerifyApiKey");
    createLambdaAlarms(recoveryVerifyCodeHandler, "RecoveryVerifyCode");
    createLambdaAlarms(recoveryUpdateEmailHandler, "RecoveryUpdateEmail");
    createLambdaAlarms(recoveryConfirmEmailHandler, "RecoveryConfirmEmail");

    // Referral program Lambda alarms
    createLambdaAlarms(referralStatusHandler, "ReferralStatus");
    createLambdaAlarms(referralRedirectHandler, "ReferralRedirect");
    createLambdaAlarms(addReferralCodeHandler, "AddReferralCode");
    createLambdaAlarms(referralRetentionHandler, "ReferralRetention");
    createLambdaAlarms(referralCleanupHandler, "ReferralCleanup");

    // API Gateway 5XX alarm
    const api5xxAlarm = new cloudwatch.Alarm(this, "Api5xxAlarm", {
      alarmName: "pkgwatch-api-5xx-errors",
      alarmDescription: "High 5XX error rate on API Gateway",
      metric: this.api.metricServerError({
        period: cdk.Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 10,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // API Gateway 4XX alarm (high client errors might indicate issues)
    const api4xxAlarm = new cloudwatch.Alarm(this, "Api4xxAlarm", {
      alarmName: "pkgwatch-api-4xx-errors",
      alarmDescription: "High 4XX error rate on API Gateway",
      metric: this.api.metricClientError({
        period: cdk.Duration.minutes(5),
        statistic: "Sum",
      }),
      threshold: 100, // Higher threshold - some 4xx is expected
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    if (alertTopic) {
      api5xxAlarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
      api5xxAlarm.addOkAction(new cw_actions.SnsAction(alertTopic));
      api4xxAlarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
      api4xxAlarm.addOkAction(new cw_actions.SnsAction(alertTopic));
    }

    // API Gateway P95 latency alarm
    const apiLatencyAlarm = new cloudwatch.Alarm(this, "ApiLatencyAlarm", {
      alarmName: "pkgwatch-api-latency-p95",
      alarmDescription: "API P95 latency exceeds 2 seconds",
      metric: this.api.metricLatency({
        statistic: "p95",
        period: cdk.Duration.minutes(5),
      }),
      threshold: 2000, // 2 seconds
      evaluationPeriods: 3,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    if (alertTopic) {
      apiLatencyAlarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
      apiLatencyAlarm.addOkAction(new cw_actions.SnsAction(alertTopic));
    }

    // Billing Events Table Throttling Alarm (CRITICAL - webhook failures)
    const billingEventsThrottleAlarm = new cloudwatch.Alarm(this, "BillingEventsThrottleAlarm", {
      alarmName: "pkgwatch-billing-events-throttling",
      alarmDescription: "Billing events table throttling - Stripe webhooks may fail",
      metric: billingEventsTable.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.QUERY,
        ],
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1, // Any throttle is critical for billing
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    if (alertTopic) {
      billingEventsThrottleAlarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
      billingEventsThrottleAlarm.addOkAction(new cw_actions.SnsAction(alertTopic));
    }

    // SES Bounce Rate Alarm (CRITICAL - high bounce rate can suspend email)
    const sesBounceAlarm = new cloudwatch.Alarm(this, "SesBounceAlarm", {
      alarmName: "pkgwatch-ses-bounce-rate",
      alarmDescription: "SES bounce rate high - email delivery at risk",
      metric: new cloudwatch.Metric({
        namespace: "AWS/SES",
        metricName: "Reputation.BounceRate",
        statistic: "Average",
        period: cdk.Duration.hours(1),
      }),
      threshold: 0.05, // 5% bounce rate
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    if (alertTopic) {
      sesBounceAlarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
      sesBounceAlarm.addOkAction(new cw_actions.SnsAction(alertTopic));
    }

    // SES Complaint Rate Alarm
    const sesComplaintAlarm = new cloudwatch.Alarm(this, "SesComplaintAlarm", {
      alarmName: "pkgwatch-ses-complaint-rate",
      alarmDescription: "SES complaint rate high - email delivery at risk",
      metric: new cloudwatch.Metric({
        namespace: "AWS/SES",
        metricName: "Reputation.ComplaintRate",
        statistic: "Average",
        period: cdk.Duration.hours(1),
      }),
      threshold: 0.001, // 0.1% complaint rate (AWS recommends < 0.1%)
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    if (alertTopic) {
      sesComplaintAlarm.addAlarmAction(new cw_actions.SnsAction(alertTopic));
      sesComplaintAlarm.addOkAction(new cw_actions.SnsAction(alertTopic));
    }

    // ===========================================
    // CodeDeploy: Safe Lambda Deployments with Auto-Rollback
    // ===========================================
    // Canary deployment: 10% traffic for 5 minutes, then 100%
    // Auto-rollback on CloudWatch alarm (errors) or failed deployment

    new codedeploy.LambdaDeploymentGroup(this, "GetPackageDeploymentGroup", {
      alias: getPackageAlias,
      deploymentConfig: codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES,
      alarms: [getPackageAlarms.errorAlarm],
      autoRollback: {
        failedDeployment: true,
        deploymentInAlarm: true,
      },
    });

    new codedeploy.LambdaDeploymentGroup(this, "ScanDeploymentGroup", {
      alias: scanAlias,
      deploymentConfig: codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES,
      alarms: [scanAlarms.errorAlarm],
      autoRollback: {
        failedDeployment: true,
        deploymentInAlarm: true,
      },
    });

    new codedeploy.LambdaDeploymentGroup(this, "StripeWebhookDeploymentGroup", {
      alias: stripeWebhookAlias,
      deploymentConfig: codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES,
      alarms: [stripeWebhookAlarms.errorAlarm],
      autoRollback: {
        failedDeployment: true,
        deploymentInAlarm: true,
      },
    });

    // Comprehensive API Dashboard
    new cloudwatch.Dashboard(this, "ApiDashboard", {
      dashboardName: "PkgWatch-API",
      widgets: [
        // Row 1: Request metrics
        [
          new cloudwatch.GraphWidget({
            title: "API Request Count",
            left: [this.api.metricCount()],
            width: 8,
          }),
          new cloudwatch.GraphWidget({
            title: "API Errors (4XX/5XX)",
            left: [
              this.api.metricClientError(),
              this.api.metricServerError(),
            ],
            width: 8,
          }),
          new cloudwatch.GraphWidget({
            title: "API Latency Percentiles",
            left: [
              this.api.metricLatency({ statistic: "p50" }),
              this.api.metricLatency({ statistic: "p90" }),
              this.api.metricLatency({ statistic: "p99" }),
            ],
            width: 8,
          }),
        ],
        // Row 2: Lambda metrics for key endpoints
        [
          new cloudwatch.GraphWidget({
            title: "GetPackage Lambda",
            left: [
              getPackageHandler.metricInvocations(),
              getPackageHandler.metricErrors(),
            ],
            width: 8,
          }),
          new cloudwatch.GraphWidget({
            title: "Scan Lambda",
            left: [
              scanHandler.metricInvocations(),
              scanHandler.metricErrors(),
            ],
            width: 8,
          }),
          new cloudwatch.GraphWidget({
            title: "Stripe Webhook Lambda",
            left: [
              stripeWebhookHandler.metricInvocations(),
              stripeWebhookHandler.metricErrors(),
            ],
            width: 8,
          }),
        ],
        // Row 3: Auth and billing metrics
        [
          new cloudwatch.GraphWidget({
            title: "Auth Lambdas",
            left: [
              signupHandler.metricInvocations(),
              magicLinkHandler.metricInvocations(),
              authCallbackHandler.metricInvocations(),
            ],
            width: 12,
          }),
          new cloudwatch.GraphWidget({
            title: "Billing Lambdas",
            left: [
              createCheckoutHandler.metricInvocations(),
              upgradeConfirmHandler.metricInvocations(),
            ],
            width: 12,
          }),
        ],
      ],
    });

    // ===========================================
    // Custom Domain: api.pkgwatch.dev
    // ===========================================
    const apiDomainName = "api.pkgwatch.dev";

    // Create ACM certificate for API domain
    const apiCertificate = new acm.Certificate(this, "ApiCertificate", {
      domainName: apiDomainName,
      validation: acm.CertificateValidation.fromDns(),
      certificateName: "PkgWatch API Certificate",
    });

    // Create custom domain for API Gateway
    const customDomain = new apigateway.DomainName(this, "ApiCustomDomain", {
      domainName: apiDomainName,
      certificate: apiCertificate,
      endpointType: apigateway.EndpointType.REGIONAL,
      securityPolicy: apigateway.SecurityPolicy.TLS_1_2,
    });

    // Map the custom domain to API Gateway stage
    new apigateway.BasePathMapping(this, "ApiBasePathMapping", {
      domainName: customDomain,
      restApi: this.api,
      stage: this.api.deploymentStage,
    });

    // Output the target domain for DNS configuration
    new cdk.CfnOutput(this, "ApiCustomDomainTarget", {
      value: customDomain.domainNameAliasDomainName,
      description: "Target domain for api.pkgwatch.dev CNAME record",
      exportName: "PkgWatchApiCustomDomainTarget",
    });

    new cdk.CfnOutput(this, "ApiCertificateArn", {
      value: apiCertificate.certificateArn,
      description: "API Certificate ARN (check validation status in ACM console)",
      exportName: "PkgWatchApiCertificateArn",
    });

    // ===========================================
    // Outputs
    // ===========================================
    new cdk.CfnOutput(this, "ApiUrl", {
      value: this.api.url,
      description: "API Gateway URL",
      exportName: "PkgWatchApiUrl",
    });

    new cdk.CfnOutput(this, "StripeSecretArn", {
      value: stripeSecret.secretArn,
      description: "Stripe secret ARN (set value manually)",
      exportName: "PkgWatchStripeSecretArn",
    });

    new cdk.CfnOutput(this, "StripeWebhookSecretArn", {
      value: stripeWebhookSecret.secretArn,
      description: "Stripe webhook secret ARN (set value manually)",
      exportName: "PkgWatchStripeWebhookSecretArn",
    });
  }
}
