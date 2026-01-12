import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as ses from "aws-cdk-lib/aws-ses";
import * as sns from "aws-cdk-lib/aws-sns";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import * as cw_actions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { Construct } from "constructs";
import * as path from "path";

interface ApiStackProps extends cdk.StackProps {
  packagesTable: dynamodb.Table;
  apiKeysTable: dynamodb.Table;
  alertTopic?: sns.Topic;
}

export class ApiStack extends cdk.Stack {
  public readonly api: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const { packagesTable, apiKeysTable, alertTopic } = props;

    // ===========================================
    // Stripe Environment Variable Validation
    // ===========================================
    // Validate required Stripe price IDs at synth time for production deployments
    const isProduction = process.env.CDK_ENV !== "dev";
    if (isProduction) {
      const requiredStripeVars = [
        "STRIPE_PRICE_STARTER",
        "STRIPE_PRICE_PRO",
        "STRIPE_PRICE_BUSINESS",
      ];
      const missingVars = requiredStripeVars.filter((v) => !process.env[v]);
      if (missingVars.length > 0) {
        console.warn(
          `WARNING: Missing Stripe price IDs for production: ${missingVars.join(", ")}. ` +
          `Stripe webhook handler will not be able to map subscriptions to tiers.`
        );
      }
    }

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
      memorySize: 512, // Increased from 256 - doubles vCPU, ~40% faster cold starts
      timeout: cdk.Duration.seconds(30),
      tracing: lambda.Tracing.ACTIVE, // Enable X-Ray tracing
      logRetention: logs.RetentionDays.TWO_WEEKS, // Prevent unbounded log storage costs
      environment: {
        PACKAGES_TABLE: packagesTable.tableName,
        API_KEYS_TABLE: apiKeysTable.tableName,
        STRIPE_SECRET_ARN: stripeSecret.secretArn,
        STRIPE_WEBHOOK_SECRET_ARN: stripeWebhookSecret.secretArn,
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

    // Get package handler
    const getPackageHandler = new lambda.Function(this, "GetPackageHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-get-package",
      handler: "api.get_package.handler",
      code: apiCodeWithShared,
      description: "Get package health score",
      // Note: Removed reservedConcurrentExecutions to avoid account limit issues
    });

    packagesTable.grantReadData(getPackageHandler);
    apiKeysTable.grantReadWriteData(getPackageHandler);

    // Note: Provisioned concurrency removed due to AWS account concurrent execution limits.
    // To re-enable when traffic justifies it:
    // 1. Request quota increase: https://console.aws.amazon.com/servicequotas/
    // 2. Uncomment the alias below with provisionedConcurrentExecutions
    // 3. Update the API Gateway integration to use getPackageAlias instead of getPackageHandler

    // Scan packages handler
    const scanHandler = new lambda.Function(this, "ScanHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-scan",
      handler: "api.post_scan.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.seconds(90), // Increased from 60s for batch operations
      memorySize: 1024, // Increased from 512 - heavy batch operations need more resources
      description: "Scan package.json for health scores",
      // Note: Removed reservedConcurrentExecutions to avoid account limit issues
    });

    packagesTable.grantReadData(scanHandler);
    apiKeysTable.grantReadWriteData(scanHandler);

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
        description: "Handle Stripe webhook events",
        environment: {
          ...commonLambdaProps.environment,
          // Stripe Price IDs for tier mapping - MUST be set to real Stripe price IDs
          STRIPE_PRICE_STARTER: process.env.STRIPE_PRICE_STARTER || "",
          STRIPE_PRICE_PRO: process.env.STRIPE_PRICE_PRO || "",
          STRIPE_PRICE_BUSINESS: process.env.STRIPE_PRICE_BUSINESS || "",
        },
      }
    );

    apiKeysTable.grantReadWriteData(stripeWebhookHandler);
    stripeSecret.grantRead(stripeWebhookHandler);
    stripeWebhookSecret.grantRead(stripeWebhookHandler);

    // Monthly usage reset handler (scheduled)
    const resetUsageHandler = new lambda.Function(this, "ResetUsageHandler", {
      ...commonLambdaProps,
      functionName: "pkgwatch-api-reset-usage",
      handler: "api.reset_usage.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.minutes(5), // Table scan may take time
      description: "Reset monthly usage counters on 1st of each month",
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
      description: "Trigger monthly usage counter reset",
    });

    resetRule.addTarget(new targets.LambdaFunction(resetUsageHandler));

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

    // Common props for auth handlers
    const authLambdaProps = {
      ...commonLambdaProps,
      environment: {
        ...commonLambdaProps.environment,
        BASE_URL: "https://pkgwatch.laranjo.dev",
        API_URL: "https://api.pkgwatch.laranjo.dev",  // Used for magic link callbacks
        SESSION_SECRET_ARN: "pkgwatch/session-secret",  // Use name, not partial ARN
        VERIFICATION_EMAIL_SENDER: "noreply@pkgwatch.laranjo.dev",
        LOGIN_EMAIL_SENDER: "noreply@pkgwatch.laranjo.dev",
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
      identity: ses.Identity.domain("pkgwatch.laranjo.dev"),
    });

    // Output DKIM tokens for DNS configuration
    new cdk.CfnOutput(this, "SesDkimTokens", {
      value: cdk.Fn.join(",", emailIdentity.dkimRecords.map(r => r.name)),
      description: "DKIM CNAME record names for DNS configuration",
    });

    // Grant SES permissions for email sending
    // SECURITY: Restrict to domain identity only (no wildcard)
    // Note: If still in SES sandbox mode, emails can only be sent to verified identities.
    // Request production access at: https://console.aws.amazon.com/ses/home#/account
    const sesPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["ses:SendEmail", "ses:SendRawEmail"],
      resources: [
        // Domain-level identity allows sending from any address @pkgwatch.laranjo.dev
        `arn:aws:ses:${this.region}:${this.account}:identity/pkgwatch.laranjo.dev`,
      ],
    });

    signupHandler.addToRolePolicy(sesPolicy);

    // GET /verify - Verify email and create API key
    const verifyHandler = new lambda.Function(this, "VerifyEmailHandler", {
      ...authLambdaProps,
      functionName: "pkgwatch-api-verify-email",
      handler: "api.verify_email.handler",
      code: apiCodeWithShared,
      description: "Verify email and activate user account",
    });

    apiKeysTable.grantReadWriteData(verifyHandler);

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
        cachingEnabled: true,
        cacheClusterEnabled: true,
        cacheClusterSize: "0.5", // 0.5 GB cache (~$15-20/month)
        cacheTtl: cdk.Duration.minutes(5),
        // Per-method cache settings (path parameters must be explicitly added via cacheKeyParameters)
        methodOptions: {
          "/packages/{ecosystem}/{name}/GET": {
            cachingEnabled: true,
            cacheTtl: cdk.Duration.minutes(5),
            cacheDataEncrypted: true,
          },
        },
      },
      defaultCorsPreflightOptions: {
        // CORS origins - localhost only allowed in dev mode
        allowOrigins: isDevMode
          ? [
              "https://pkgwatch.laranjo.dev",
              "https://app.pkgwatch.laranjo.dev",
              "http://localhost:3000", // For local development
              "http://localhost:4321", // Astro dev server
            ]
          : [
              "https://pkgwatch.laranjo.dev",
              "https://app.pkgwatch.laranjo.dev",
            ],
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
            description: "Dependencies object from package.json",
          },
          devDependencies: {
            type: apigateway.JsonSchemaType.OBJECT,
            description: "Dev dependencies object from package.json",
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

    // ===========================================
    // API Routes
    // ===========================================

    // GET /health (no auth)
    const healthResource = this.api.root.addResource("health");
    healthResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(healthHandler)
    );

    // GET /packages/{ecosystem}/{name}
    const packagesResource = this.api.root.addResource("packages");
    const ecosystemResource = packagesResource.addResource("{ecosystem}");
    const packageNameResource = ecosystemResource.addResource("{name}");
    packageNameResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getPackageHandler, {
        // Include path parameters in cache key so different packages get different cache entries
        cacheKeyParameters: [
          "method.request.path.ecosystem",
          "method.request.path.name",
        ],
      }),
      {
        // Map path parameters for cache key
        requestParameters: {
          "method.request.path.ecosystem": true,
          "method.request.path.name": true,
        },
      }
    );

    // POST /scan (with request validation)
    const scanResource = this.api.root.addResource("scan");
    scanResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(scanHandler),
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
      new apigateway.LambdaIntegration(stripeWebhookHandler)
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

    // GET /auth/pending-key
    const pendingKeyResource = authResource.addResource("pending-key");
    pendingKeyResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getPendingKeyHandler)
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
        // Rate Limiting - 100 requests per 5 minutes per IP (20/min)
        // Legitimate CI/CD usage is ~10-20 requests/minute
        {
          name: "RateLimitRule",
          priority: 30,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: 100, // Reduced from 500 - previous limit was too permissive
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
    const createLambdaAlarms = (
      fn: lambda.Function,
      name: string
    ): cloudwatch.Alarm[] => {
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

      return alarms;
    };

    // Create alarms for all API endpoints
    createLambdaAlarms(healthHandler, "Health");
    createLambdaAlarms(getPackageHandler, "GetPackage");
    createLambdaAlarms(scanHandler, "Scan");
    createLambdaAlarms(getUsageHandler, "GetUsage");
    createLambdaAlarms(stripeWebhookHandler, "StripeWebhook");
    createLambdaAlarms(resetUsageHandler, "ResetUsage");

    // Auth/signup Lambda alarms - critical for user access
    createLambdaAlarms(signupHandler, "Signup");
    createLambdaAlarms(verifyHandler, "VerifyEmail");
    createLambdaAlarms(magicLinkHandler, "MagicLink");
    createLambdaAlarms(authCallbackHandler, "AuthCallback");
    createLambdaAlarms(authMeHandler, "AuthMe");
    createLambdaAlarms(getPendingKeyHandler, "GetPendingKey");
    createLambdaAlarms(resendVerificationHandler, "ResendVerification");
    createLambdaAlarms(getApiKeysHandler, "GetApiKeys");
    createLambdaAlarms(createApiKeyHandler, "CreateApiKey");
    createLambdaAlarms(revokeApiKeyHandler, "RevokeApiKey");

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

    // API Latency Dashboard
    new cloudwatch.Dashboard(this, "ApiLatencyDashboard", {
      dashboardName: "PkgWatch-API-Latency",
      widgets: [
        [
          new cloudwatch.GraphWidget({
            title: "API Latency Percentiles",
            left: [
              this.api.metricLatency({ statistic: "p50" }),
              this.api.metricLatency({ statistic: "p90" }),
              this.api.metricLatency({ statistic: "p99" }),
            ],
            width: 24,
          }),
        ],
      ],
    });

    // ===========================================
    // Custom Domain: api.pkgwatch.laranjo.dev
    // ===========================================
    const apiDomainName = "api.pkgwatch.laranjo.dev";

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
      description: "Target domain for api.pkgwatch.laranjo.dev CNAME record",
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
