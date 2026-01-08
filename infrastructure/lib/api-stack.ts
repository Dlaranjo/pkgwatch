import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sns from "aws-cdk-lib/aws-sns";
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

    const commonLambdaProps = {
      runtime: lambda.Runtime.PYTHON_3_12,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      tracing: lambda.Tracing.ACTIVE, // Enable X-Ray tracing
      environment: {
        PACKAGES_TABLE: packagesTable.tableName,
        API_KEYS_TABLE: apiKeysTable.tableName,
        STRIPE_SECRET_ARN: stripeSecret.secretArn,
        STRIPE_WEBHOOK_SECRET_ARN: stripeWebhookSecret.secretArn,
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
    });

    packagesTable.grantReadData(getPackageHandler);
    apiKeysTable.grantReadWriteData(getPackageHandler);

    // Scan packages handler
    const scanHandler = new lambda.Function(this, "ScanHandler", {
      ...commonLambdaProps,
      functionName: "dephealth-api-scan",
      handler: "post_scan.handler",
      code: apiCodeWithShared,
      timeout: cdk.Duration.seconds(60),
      memorySize: 512,
      description: "Scan package.json for health scores",
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
      }
    );

    apiKeysTable.grantReadWriteData(stripeWebhookHandler);
    stripeSecret.grantRead(stripeWebhookHandler);
    stripeWebhookSecret.grantRead(stripeWebhookHandler);

    // ===========================================
    // API Gateway
    // ===========================================
    this.api = new apigateway.RestApi(this, "DepHealthApi", {
      restApiName: "DepHealth API",
      description: "Dependency Health Intelligence API",
      deployOptions: {
        stageName: "v1",
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: false,
        metricsEnabled: true,
        tracingEnabled: true, // Enable X-Ray tracing for end-to-end traces
      },
      defaultCorsPreflightOptions: {
        // Restrict CORS to specific origins in production
        // Update these URLs after deployment
        allowOrigins: [
          "https://dephealth.laranjo.dev",
          "https://app.dephealth.laranjo.dev",
          "http://localhost:3000", // For local development
          "http://localhost:4321", // Astro dev server
        ],
        allowMethods: ["GET", "POST", "OPTIONS"],
        allowHeaders: [
          "Content-Type",
          "X-API-Key",
          "X-Amz-Date",
          "Authorization",
        ],
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
      new apigateway.LambdaIntegration(getPackageHandler)
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
