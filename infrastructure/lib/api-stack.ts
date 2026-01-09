import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sns from "aws-cdk-lib/aws-sns";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import * as cw_actions from "aws-cdk-lib/aws-cloudwatch-actions";
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
    // Secrets Manager: Stripe Secrets
    // ===========================================
    const stripeSecret = new secretsmanager.Secret(this, "StripeSecret", {
      secretName: "dephealth/stripe-secret",
      description: "Stripe API secret key",
    });

    const stripeWebhookSecret = new secretsmanager.Secret(
      this,
      "StripeWebhookSecret",
      {
        secretName: "dephealth/stripe-webhook",
        description: "Stripe webhook signing secret",
      }
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
            "cp -r /asset-input/api/* /asset-output/",
            "cp -r /asset-input/shared /asset-output/",
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
      functionName: "dephealth-api-health",
      handler: "health.handler",
      code: apiCodeWithShared,
      description: "API health check endpoint",
    });

    // Get package handler
    const getPackageHandler = new lambda.Function(this, "GetPackageHandler", {
      ...commonLambdaProps,
      functionName: "dephealth-api-get-package",
      handler: "get_package.handler",
      code: apiCodeWithShared,
      description: "Get package health score",
      // Note: Removed reservedConcurrentExecutions to avoid account limit issues
    });

    packagesTable.grantReadData(getPackageHandler);
    apiKeysTable.grantReadWriteData(getPackageHandler);

    // Provisioned concurrency for GetPackageHandler (most called endpoint)
    // Eliminates cold starts for 95%+ of requests (~$35/month for 5 instances)
    // Using currentVersion publishes a new version on each deploy (required for provisioned concurrency)
    const getPackageAlias = new lambda.Alias(this, "GetPackageAlias", {
      aliasName: "live",
      version: getPackageHandler.currentVersion,
      provisionedConcurrentExecutions: 5,
    });

    // Scan packages handler
    const scanHandler = new lambda.Function(this, "ScanHandler", {
      ...commonLambdaProps,
      functionName: "dephealth-api-scan",
      handler: "post_scan.handler",
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
      functionName: "dephealth-api-get-usage",
      handler: "get_usage.handler",
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
        functionName: "dephealth-api-stripe-webhook",
        handler: "stripe_webhook.handler",
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
      functionName: "dephealth-api-reset-usage",
      handler: "reset_usage.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.minutes(5), // Table scan may take time
      description: "Reset monthly usage counters on 1st of each month",
    });

    apiKeysTable.grantReadWriteData(resetUsageHandler);

    // EventBridge rule for monthly reset at midnight UTC on 1st
    const resetRule = new events.Rule(this, "MonthlyUsageReset", {
      ruleName: "dephealth-monthly-usage-reset",
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

    // Session secret for JWT tokens
    const sessionSecret = new secretsmanager.Secret(this, "SessionSecret", {
      secretName: "dephealth/session-secret",
      description: "Secret key for signing session tokens",
      generateSecretString: {
        secretStringTemplate: "{}",
        generateStringKey: "secret",
        excludePunctuation: true,
        passwordLength: 64,
      },
    });

    // Common props for auth handlers
    const authLambdaProps = {
      ...commonLambdaProps,
      environment: {
        ...commonLambdaProps.environment,
        BASE_URL: "https://dephealth.laranjo.dev",
        SESSION_SECRET_ARN: sessionSecret.secretArn,
        VERIFICATION_EMAIL_SENDER: "noreply@dephealth.laranjo.dev",
        LOGIN_EMAIL_SENDER: "noreply@dephealth.laranjo.dev",
      },
    };

    // POST /signup - Create pending account
    const signupHandler = new lambda.Function(this, "SignupHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-signup",
      handler: "signup.handler",
      code: apiCodeWithShared,
      description: "User signup - creates pending account and sends verification email",
    });

    apiKeysTable.grantReadWriteData(signupHandler);
    // Note: SES permissions need to be granted via IAM policy or identity verification

    // GET /verify - Verify email and create API key
    const verifyHandler = new lambda.Function(this, "VerifyEmailHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-verify-email",
      handler: "verify_email.handler",
      code: apiCodeWithShared,
      description: "Verify email and activate user account",
    });

    apiKeysTable.grantReadWriteData(verifyHandler);

    // POST /auth/magic-link - Send login link
    const magicLinkHandler = new lambda.Function(this, "MagicLinkHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-magic-link",
      handler: "magic_link.handler",
      code: apiCodeWithShared,
      description: "Send magic link for passwordless authentication",
    });

    apiKeysTable.grantReadWriteData(magicLinkHandler);

    // GET /auth/callback - Create session from magic link
    const authCallbackHandler = new lambda.Function(this, "AuthCallbackHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-auth-callback",
      handler: "auth_callback.handler",
      code: apiCodeWithShared,
      description: "Handle magic link callback and create session",
    });

    apiKeysTable.grantReadWriteData(authCallbackHandler);
    sessionSecret.grantRead(authCallbackHandler);

    // GET /auth/me - Get current user info
    const authMeHandler = new lambda.Function(this, "AuthMeHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-auth-me",
      handler: "auth_me.handler",
      code: apiCodeWithShared,
      description: "Get current authenticated user info",
    });

    apiKeysTable.grantReadData(authMeHandler);
    sessionSecret.grantRead(authMeHandler);

    // GET /api-keys - List user's API keys
    const getApiKeysHandler = new lambda.Function(this, "GetApiKeysHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-get-api-keys",
      handler: "get_api_keys.handler",
      code: apiCodeWithShared,
      description: "List all API keys for authenticated user",
    });

    apiKeysTable.grantReadData(getApiKeysHandler);
    sessionSecret.grantRead(getApiKeysHandler);

    // POST /api-keys - Create new API key
    const createApiKeyHandler = new lambda.Function(this, "CreateApiKeyHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-create-api-key",
      handler: "create_api_key.handler",
      code: apiCodeWithShared,
      description: "Create new API key for authenticated user",
    });

    apiKeysTable.grantReadWriteData(createApiKeyHandler);
    sessionSecret.grantRead(createApiKeyHandler);

    // DELETE /api-keys/{key_id} - Revoke API key
    const revokeApiKeyHandler = new lambda.Function(this, "RevokeApiKeyHandler", {
      ...authLambdaProps,
      functionName: "dephealth-api-revoke-api-key",
      handler: "revoke_api_key.handler",
      code: apiCodeWithShared,
      description: "Revoke API key for authenticated user",
    });

    apiKeysTable.grantReadWriteData(revokeApiKeyHandler);
    sessionSecret.grantRead(revokeApiKeyHandler);

    // ===========================================
    // API Gateway
    // ===========================================
    this.api = new apigateway.RestApi(this, "DepHealthApi", {
      restApiName: "DepHealth API",
      description: "Dependency Health Intelligence API",
      minimumCompressionSize: 1024, // Compress responses > 1KB (60-80% reduction)
      deployOptions: {
        stageName: "v1",
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: false,
        metricsEnabled: true,
        tracingEnabled: true, // Enable X-Ray tracing for end-to-end traces
        cachingEnabled: true,
        cacheClusterEnabled: true,
        cacheClusterSize: "0.5", // 0.5 GB cache (~$15-20/month)
        cacheTtl: cdk.Duration.minutes(5),
        // Per-method cache settings (path parameters are included by default)
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
              "https://dephealth.laranjo.dev",
              "https://app.dephealth.laranjo.dev",
              "http://localhost:3000", // For local development
              "http://localhost:4321", // Astro dev server
            ]
          : [
              "https://dephealth.laranjo.dev",
              "https://app.dephealth.laranjo.dev",
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
      new apigateway.LambdaIntegration(getPackageAlias) // Use alias with provisioned concurrency
    );

    // POST /scan
    const scanResource = this.api.root.addResource("scan");
    scanResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(scanHandler)
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

    // POST /signup
    const signupResource = this.api.root.addResource("signup");
    signupResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(signupHandler)
    );

    // GET /verify?token=xxx
    const verifyResource = this.api.root.addResource("verify");
    verifyResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(verifyHandler)
    );

    // /auth routes
    const authResource = this.api.root.addResource("auth");

    // POST /auth/magic-link
    const magicLinkResource = authResource.addResource("magic-link");
    magicLinkResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(magicLinkHandler)
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

    // /api-keys routes
    const apiKeysResource = this.api.root.addResource("api-keys");

    // GET /api-keys
    apiKeysResource.addMethod(
      "GET",
      new apigateway.LambdaIntegration(getApiKeysHandler)
    );

    // POST /api-keys
    apiKeysResource.addMethod(
      "POST",
      new apigateway.LambdaIntegration(createApiKeyHandler)
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
      name: "dephealth-api-waf",
      defaultAction: { allow: {} },
      scope: "REGIONAL",
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "DepHealthApiWaf",
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
        alarmName: `dephealth-api-${name.toLowerCase()}-errors`,
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
        alarmName: `dephealth-api-${name.toLowerCase()}-duration`,
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
        alarmName: `dephealth-api-${name.toLowerCase()}-throttles`,
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

    // API Gateway 5XX alarm
    const api5xxAlarm = new cloudwatch.Alarm(this, "Api5xxAlarm", {
      alarmName: "dephealth-api-5xx-errors",
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
      alarmName: "dephealth-api-4xx-errors",
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
      alarmName: "dephealth-api-latency-p95",
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
      dashboardName: "DepHealth-API-Latency",
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
    // Outputs
    // ===========================================
    new cdk.CfnOutput(this, "ApiUrl", {
      value: this.api.url,
      description: "API Gateway URL",
      exportName: "DepHealthApiUrl",
    });

    new cdk.CfnOutput(this, "StripeSecretArn", {
      value: stripeSecret.secretArn,
      description: "Stripe secret ARN (set value manually)",
      exportName: "DepHealthStripeSecretArn",
    });

    new cdk.CfnOutput(this, "StripeWebhookSecretArn", {
      value: stripeWebhookSecret.secretArn,
      description: "Stripe webhook secret ARN (set value manually)",
      exportName: "DepHealthStripeWebhookSecretArn",
    });
  }
}
