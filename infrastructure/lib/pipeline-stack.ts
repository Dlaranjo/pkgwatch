import * as cdk from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sns from "aws-cdk-lib/aws-sns";
import * as snsSubscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import { Construct } from "constructs";
import * as path from "path";

interface PipelineStackProps extends cdk.StackProps {
  packagesTable: dynamodb.Table;
  rawDataBucket: s3.Bucket;
  publicDataBucket: s3.Bucket; // For public data like top-npm-packages.json
  apiKeysTable: dynamodb.Table; // For global GitHub rate limiting with sharded counters
  alertEmail?: string; // Email address for SNS alert notifications
}

export class PipelineStack extends cdk.Stack {
  public readonly alertTopic: sns.Topic;
  public readonly packageQueue: sqs.Queue;

  constructor(scope: Construct, id: string, props: PipelineStackProps) {
    super(scope, id, props);

    const { packagesTable, rawDataBucket, publicDataBucket, apiKeysTable, alertEmail } = props;

    // ===========================================
    // Secrets Manager: GitHub Token
    // ===========================================
    // Reference existing secret (created manually before deployment)
    const githubTokenSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      "GitHubTokenSecret",
      "pkgwatch/github-token"
    );

    // ===========================================
    // SQS: Package Processing Queues
    // ===========================================

    // Dead letter queue for failed messages
    const dlq = new sqs.Queue(this, "PackageQueueDLQ", {
      queueName: "pkgwatch-package-dlq",
      retentionPeriod: cdk.Duration.days(14),
      encryption: sqs.QueueEncryption.SQS_MANAGED, // Enable encryption at rest
    });

    // Main queue for package processing jobs
    // Visibility timeout should be 6x Lambda timeout to prevent message reprocessing
    this.packageQueue = new sqs.Queue(this, "PackageQueue", {
      queueName: "pkgwatch-package-queue",
      visibilityTimeout: cdk.Duration.minutes(30), // 6x Lambda timeout (5 min) per AWS best practices
      retentionPeriod: cdk.Duration.days(14), // Match DLQ retention for consistency
      encryption: sqs.QueueEncryption.SQS_MANAGED, // Enable encryption at rest
      deadLetterQueue: {
        queue: dlq,
        maxReceiveCount: 3,
      },
    });
    const packageQueue = this.packageQueue; // Alias for local usage

    // Dead letter queue for discovery queue failures
    const discoveryDlq = new sqs.Queue(this, "DiscoveryQueueDLQ", {
      queueName: "pkgwatch-discovery-dlq",
      retentionPeriod: cdk.Duration.days(14),
      encryption: sqs.QueueEncryption.SQS_MANAGED,
    });

    // Discovery queue for graph expansion workers
    // Used by graph_expander_dispatcher to distribute package processing
    const discoveryQueue = new sqs.Queue(this, "DiscoveryQueue", {
      queueName: "pkgwatch-discovery-queue",
      visibilityTimeout: cdk.Duration.minutes(30), // 6x Lambda timeout (5 min) per AWS best practices
      retentionPeriod: cdk.Duration.days(1),
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      deadLetterQueue: {
        queue: discoveryDlq,
        maxReceiveCount: 3,
      },
    });

    // ===========================================
    // Lambda: Common configuration
    // ===========================================
    const functionsDir = path.join(__dirname, "../../functions");

    // Bundle collectors with dependencies
    const collectorsCode = lambda.Code.fromAsset(functionsDir, {
      bundling: {
        image: lambda.Runtime.PYTHON_3_12.bundlingImage,
        command: [
          "bash",
          "-c",
          [
            "cp -r /asset-input/collectors/* /asset-output/",
            "cp -r /asset-input/shared/* /asset-output/",
            "cp -r /asset-input/shared /asset-output/",
            "pip install -r /asset-input/collectors/requirements.txt -t /asset-output/ --quiet",
          ].join(" && "),
        ],
      },
    });

    // Bundle scoring with dependencies
    const scoringCode = lambda.Code.fromAsset(functionsDir, {
      bundling: {
        image: lambda.Runtime.PYTHON_3_12.bundlingImage,
        command: [
          "bash",
          "-c",
          [
            "cp -r /asset-input/scoring/* /asset-output/",
            "cp -r /asset-input/shared/* /asset-output/",
            "cp -r /asset-input/shared /asset-output/",
            "pip install -r /asset-input/scoring/requirements.txt -t /asset-output/ --quiet",
          ].join(" && "),
        ],
      },
    });

    // Bundle admin functions
    const adminCode = lambda.Code.fromAsset(functionsDir, {
      bundling: {
        image: lambda.Runtime.PYTHON_3_12.bundlingImage,
        command: [
          "bash",
          "-c",
          [
            "cp -r /asset-input/admin/* /asset-output/",
            "cp -r /asset-input/shared/* /asset-output/",
            "cp -r /asset-input/shared /asset-output/",
          ].join(" && "),
        ],
      },
    });

    // Bundle discovery functions (graph expander, publish top packages, npmsio audit)
    const discoveryCode = lambda.Code.fromAsset(functionsDir, {
      bundling: {
        image: lambda.Runtime.PYTHON_3_12.bundlingImage,
        command: [
          "bash",
          "-c",
          [
            "cp -r /asset-input/discovery/* /asset-output/",
            "cp -r /asset-input/collectors/* /asset-output/",
            "cp -r /asset-input/shared/* /asset-output/",
            "cp -r /asset-input/shared /asset-output/",
            "cp -r /asset-input/collectors /asset-output/",
            "pip install -r /asset-input/collectors/requirements.txt -t /asset-output/ --quiet",
          ].join(" && "),
        ],
      },
    });

    const commonLambdaProps = {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64, // Graviton2 - ~20% cost savings
      memorySize: 512, // Increased from 256 - doubles vCPU, ~40% faster cold starts
      timeout: cdk.Duration.minutes(2),
      logRetention: logs.RetentionDays.ONE_MONTH, // Prevent unbounded CloudWatch costs
      tracing: lambda.Tracing.ACTIVE, // X-Ray tracing for debugging pipeline issues
      environment: {
        PACKAGES_TABLE: packagesTable.tableName,
        RAW_DATA_BUCKET: rawDataBucket.bucketName,
        GITHUB_TOKEN_SECRET_ARN: githubTokenSecret.secretArn,
        PACKAGE_QUEUE_URL: packageQueue.queueUrl,
        API_KEYS_TABLE: apiKeysTable.tableName, // For global GitHub rate limiting
      },
    };

    // ===========================================
    // Lambda: Refresh Dispatcher
    // ===========================================
    // Triggered by EventBridge schedule, enqueues packages for refresh
    const refreshDispatcher = new lambda.Function(this, "RefreshDispatcher", {
      ...commonLambdaProps,
      functionName: "pkgwatch-refresh-dispatcher",
      handler: "refresh_dispatcher.handler",
      code: collectorsCode,
      description: "Dispatches package refresh jobs to SQS based on tier",
    });

    packagesTable.grantReadData(refreshDispatcher);
    packageQueue.grantSendMessages(refreshDispatcher);

    // ===========================================
    // Lambda: Package Collector
    // ===========================================
    // Processes packages from SQS queue
    const packageCollector = new lambda.Function(this, "PackageCollector", {
      ...commonLambdaProps,
      functionName: "pkgwatch-package-collector",
      handler: "package_collector.handler",
      code: collectorsCode,
      timeout: cdk.Duration.minutes(5),
      description: "Collects data from deps.dev, npm, and GitHub",
    });

    packagesTable.grantReadWriteData(packageCollector);
    rawDataBucket.grantWrite(packageCollector);
    githubTokenSecret.grantRead(packageCollector);
    apiKeysTable.grantReadWriteData(packageCollector); // For global GitHub rate limiting

    // Connect collector to SQS queue
    // Increased from maxConcurrency=2 to improve throughput
    // With semaphore of 5 per Lambda: 10 * 5 = max 50 concurrent GitHub calls
    // GitHub allows 5000/hour = ~83/minute, so 50 concurrent is safe
    packageCollector.addEventSource(
      new lambdaEventSources.SqsEventSource(packageQueue, {
        batchSize: 10, // Increased from 5
        maxConcurrency: 10, // Increased from 2 (conservative to avoid GitHub rate limits)
        maxBatchingWindow: cdk.Duration.seconds(30), // Allow batching for efficiency
      })
    );

    // ===========================================
    // Lambda: Score Calculator
    // ===========================================
    // Calculates health scores after data collection
    // Triggered by DynamoDB Streams when package data is updated
    const scoreCalculator = new lambda.Function(this, "ScoreCalculator", {
      ...commonLambdaProps,
      functionName: "pkgwatch-score-calculator",
      handler: "score_package.handler",
      code: scoringCode,
      description: "Calculates health scores for packages",
      environment: {
        ...commonLambdaProps.environment,
        IDEMPOTENCY_WINDOW_SECONDS: "60", // Defense in depth for infinite loop prevention
      },
    });

    packagesTable.grantReadWriteData(scoreCalculator);

    // DLQ for DynamoDB Streams failures
    const streamsDlq = new sqs.Queue(this, "StreamsDLQ", {
      queueName: "pkgwatch-streams-dlq",
      retentionPeriod: cdk.Duration.days(14),
      encryption: sqs.QueueEncryption.SQS_MANAGED, // Enable encryption at rest
    });

    // Add DynamoDB Streams trigger to calculate scores after data collection
    // Loop prevention: Lambda checks if record has collected_at (collectors set this)
    // Score updates only set scored_at, so they don't trigger re-processing
    scoreCalculator.addEventSource(
      new lambdaEventSources.DynamoEventSource(packagesTable, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        retryAttempts: 3,
        reportBatchItemFailures: true,
        onFailure: new lambdaEventSources.SqsDlq(streamsDlq),
      })
    );

    // CloudWatch alarm for streams DLQ
    const streamsDlqAlarm = new cloudwatch.Alarm(this, "StreamsDlqAlarm", {
      alarmName: "pkgwatch-streams-dlq-messages",
      alarmDescription: "Messages in Streams DLQ - score calculation failing",
      metric: streamsDlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10,
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    // Note: Alarm action added after alertTopic is defined (see CloudWatch section)

    // ===========================================
    // Lambda: Seed Packages (Admin)
    // ===========================================
    // One-time/on-demand Lambda to populate database with top packages
    const seedPackages = new lambda.Function(this, "SeedPackages", {
      ...commonLambdaProps,
      functionName: "pkgwatch-seed-packages",
      handler: "seed_packages.handler",
      code: adminCode,
      timeout: cdk.Duration.minutes(10), // Longer timeout for fetching package lists
      memorySize: 1024, // More memory for parallel processing
      description: "Seeds database with top npm and PyPI packages",
      environment: {
        ...commonLambdaProps.environment,
        REFRESH_DISPATCHER_ARN: refreshDispatcher.functionArn,
      },
    });

    packagesTable.grantReadWriteData(seedPackages);
    refreshDispatcher.grantInvoke(seedPackages);

    // ===========================================
    // EventBridge: Scheduled Triggers
    // ===========================================

    // Daily refresh at 2:00 AM UTC
    new events.Rule(this, "DailyRefreshRule", {
      ruleName: "pkgwatch-daily-refresh",
      schedule: events.Schedule.cron({ hour: "2", minute: "0" }),
      description: "Triggers daily package refresh for Tier 1 packages",
      targets: [
        new targets.LambdaFunction(refreshDispatcher, {
          event: events.RuleTargetInput.fromObject({
            tier: 1,
            reason: "daily_refresh",
          }),
        }),
      ],
    });

    // Every 3 days refresh (Tier 2) - runs at 3:00 AM on days 1, 4, 7, 10, 13, 16, 19, 22, 25, 28
    new events.Rule(this, "ThreeDayRefreshRule", {
      ruleName: "pkgwatch-three-day-refresh",
      schedule: events.Schedule.expression(
        "cron(0 3 1,4,7,10,13,16,19,22,25,28 * ? *)"
      ),
      description: "Triggers 3-day package refresh for Tier 2 packages",
      targets: [
        new targets.LambdaFunction(refreshDispatcher, {
          event: events.RuleTargetInput.fromObject({
            tier: 2,
            reason: "three_day_refresh",
          }),
        }),
      ],
    });

    // Weekly refresh (Tier 3) - runs at 4:00 AM on Sundays
    new events.Rule(this, "WeeklyRefreshRule", {
      ruleName: "pkgwatch-weekly-refresh",
      schedule: events.Schedule.cron({
        hour: "4",
        minute: "0",
        weekDay: "SUN",
      }),
      description: "Triggers weekly package refresh for Tier 3 packages",
      targets: [
        new targets.LambdaFunction(refreshDispatcher, {
          event: events.RuleTargetInput.fromObject({
            tier: 3,
            reason: "weekly_refresh",
          }),
        }),
      ],
    });

    // ===========================================
    // Lambda: DLQ Processor
    // ===========================================
    // Reprocesses failed messages with exponential backoff and retry tracking
    const dlqProcessor = new lambda.Function(this, "DLQProcessor", {
      ...commonLambdaProps,
      functionName: "pkgwatch-dlq-processor",
      handler: "dlq_processor.handler",
      code: collectorsCode,
      description: "Processes failed messages from DLQ with retry tracking",
      // Note: Removed reservedConcurrentExecutions to avoid account limit issues
      environment: {
        ...commonLambdaProps.environment,
        DLQ_URL: dlq.queueUrl,
        MAIN_QUEUE_URL: packageQueue.queueUrl,
        MAX_DLQ_RETRIES: "5",
      },
    });

    // Grant permissions
    dlq.grantConsumeMessages(dlqProcessor);
    packageQueue.grantSendMessages(dlqProcessor);
    packagesTable.grantWriteData(dlqProcessor); // For storing permanent failures

    // Schedule to run every 15 minutes
    new events.Rule(this, "DLQProcessorSchedule", {
      ruleName: "pkgwatch-dlq-processor",
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      description: "Triggers DLQ processor to reprocess failed messages",
      targets: [new targets.LambdaFunction(dlqProcessor)],
    });

    // ===========================================
    // Lambda: Retry Dispatcher (for incomplete data)
    // ===========================================
    // Finds packages with incomplete data and re-queues them for collection
    const retryDispatcher = new lambda.Function(this, "RetryDispatcher", {
      ...commonLambdaProps,
      functionName: "pkgwatch-retry-dispatcher",
      handler: "retry_dispatcher.handler",
      code: collectorsCode,
      timeout: cdk.Duration.minutes(2),
      description: "Dispatches retry jobs for packages with incomplete data",
    });

    // Grant permissions
    packagesTable.grantReadWriteData(retryDispatcher); // Read for query, write for retry_dispatched_at
    packageQueue.grantSendMessages(retryDispatcher);

    // Schedule retry dispatcher every 30 minutes
    new events.Rule(this, "RetryDispatcherSchedule", {
      ruleName: "pkgwatch-retry-dispatcher",
      schedule: events.Schedule.rate(cdk.Duration.minutes(30)),
      description: "Triggers retry dispatcher for incomplete packages",
      targets: [new targets.LambdaFunction(retryDispatcher)],
    });

    // ===========================================
    // Lambda: Graph Expander Dispatcher
    // ===========================================
    // Dispatches top packages to discovery queue for dependency crawling
    const graphExpanderDispatcher = new lambda.Function(this, "GraphExpanderDispatcher", {
      ...commonLambdaProps,
      functionName: "pkgwatch-graph-expander-dispatcher",
      handler: "graph_expander_dispatcher.handler",
      code: discoveryCode,
      timeout: cdk.Duration.minutes(5),
      description: "Dispatches top packages for dependency discovery",
      environment: {
        ...commonLambdaProps.environment,
        DISCOVERY_QUEUE_URL: discoveryQueue.queueUrl,
      },
    });

    packagesTable.grantReadData(graphExpanderDispatcher);
    discoveryQueue.grantSendMessages(graphExpanderDispatcher);

    // Tuesday 1:00 AM UTC (weekly) - Moved from Sunday to avoid collision with weekly refresh
    new events.Rule(this, "GraphExpanderDispatcherSchedule", {
      ruleName: "pkgwatch-graph-expander-dispatcher",
      schedule: events.Schedule.cron({ hour: "1", minute: "0", weekDay: "TUE" }),
      description: "Weekly dependency graph expansion for package discovery",
      targets: [new targets.LambdaFunction(graphExpanderDispatcher)],
    });

    // ===========================================
    // Lambda: Graph Expander Worker
    // ===========================================
    // Processes packages from discovery queue, discovers new packages
    const graphExpanderWorker = new lambda.Function(this, "GraphExpanderWorker", {
      ...commonLambdaProps,
      functionName: "pkgwatch-graph-expander-worker",
      handler: "graph_expander_worker.handler",
      code: discoveryCode,
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024, // More memory for async HTTP calls
      description: "Discovers new packages through dependency crawling",
      environment: {
        ...commonLambdaProps.environment,
      },
    });

    packagesTable.grantReadWriteData(graphExpanderWorker);
    rawDataBucket.grantReadWrite(graphExpanderWorker); // For deps cache
    packageQueue.grantSendMessages(graphExpanderWorker);

    // Connect worker to discovery queue
    graphExpanderWorker.addEventSource(
      new lambdaEventSources.SqsEventSource(discoveryQueue, {
        batchSize: 1, // Process one batch at a time for safety
        maxConcurrency: 5,
      })
    );

    // ===========================================
    // Lambda: Publish Top Packages
    // ===========================================
    // Exports download-ranked package list to public S3
    const publishTopPackages = new lambda.Function(this, "PublishTopPackages", {
      ...commonLambdaProps,
      functionName: "pkgwatch-publish-top-packages",
      handler: "publish_top_packages.handler",
      code: discoveryCode,
      timeout: cdk.Duration.minutes(5),
      description: "Publishes top-npm-packages.json to public S3",
      environment: {
        ...commonLambdaProps.environment,
        PUBLIC_BUCKET: publicDataBucket.bucketName,
      },
    });

    packagesTable.grantReadData(publishTopPackages);
    publicDataBucket.grantWrite(publishTopPackages, "data/*");

    // Monday 5:00 AM UTC (weekly)
    new events.Rule(this, "PublishTopPackagesSchedule", {
      ruleName: "pkgwatch-publish-top-packages",
      schedule: events.Schedule.cron({ hour: "5", minute: "0", weekDay: "MON" }),
      description: "Weekly publish of top npm packages list",
      targets: [new targets.LambdaFunction(publishTopPackages)],
    });

    // ===========================================
    // Lambda: npms.io Audit
    // ===========================================
    // Quarterly audit to find missing popular packages
    const npmsioAudit = new lambda.Function(this, "NpmsioAudit", {
      ...commonLambdaProps,
      functionName: "pkgwatch-npmsio-audit",
      handler: "npmsio_audit.handler",
      code: discoveryCode,
      timeout: cdk.Duration.minutes(10),
      memorySize: 1024,
      description: "Quarterly audit against npms.io to find missing packages",
    });

    packagesTable.grantReadWriteData(npmsioAudit);
    packageQueue.grantSendMessages(npmsioAudit);

    // Quarterly: 1st of Jan, Apr, Jul, Oct at 2:00 AM UTC
    new events.Rule(this, "NpmsioAuditSchedule", {
      ruleName: "pkgwatch-npmsio-audit",
      schedule: events.Schedule.expression("cron(0 2 1 1,4,7,10 ? *)"),
      description: "Quarterly audit of package coverage against npms.io",
      targets: [new targets.LambdaFunction(npmsioAudit)],
    });

    // ===========================================
    // CloudWatch Alarms & Monitoring
    // ===========================================

    // SNS Topic for alerts
    this.alertTopic = new sns.Topic(this, "AlertTopic", {
      topicName: "pkgwatch-alerts",
      displayName: "PkgWatch Alerts",
    });

    // CRITICAL: Subscribe email to alerts - without this, all alarms go nowhere
    if (alertEmail) {
      this.alertTopic.addSubscription(
        new snsSubscriptions.EmailSubscription(alertEmail)
      );
    }

    // Note: For Slack integration, use AWS Chatbot (recommended) instead of direct webhooks.
    // SNS message format is incompatible with Slack webhook expectations.
    // To set up AWS Chatbot:
    // 1. Go to AWS Chatbot console and authorize your Slack workspace
    // 2. Create a Slack channel configuration pointing to this.alertTopic
    // 3. AWS Chatbot will format CloudWatch alarm messages nicely for Slack

    // 1. DLQ Messages Alarm (Critical - indicates processing failures)
    const dlqAlarm = new cloudwatch.Alarm(this, "DlqAlarm", {
      alarmName: "pkgwatch-dlq-messages",
      alarmDescription:
        "Messages in DLQ - package collection failing after retries",
      metric: dlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    dlqAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    dlqAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // Streams DLQ alarm (defined earlier, action added here after alertTopic exists)
    streamsDlqAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    streamsDlqAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // Discovery DLQ alarm - alerts when graph expansion is failing
    const discoveryDlqAlarm = new cloudwatch.Alarm(this, "DiscoveryDlqAlarm", {
      alarmName: "pkgwatch-discovery-dlq-messages",
      alarmDescription: "Messages in Discovery DLQ - graph expansion failing",
      metric: discoveryDlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
      }),
      threshold: 5, // Allow a few transient failures before alerting
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    discoveryDlqAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    discoveryDlqAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // Package Queue Backlog Alarm - detects processing stalls
    const queueBacklogAlarm = new cloudwatch.Alarm(this, "PackageQueueBacklogAlarm", {
      alarmName: "pkgwatch-package-queue-backlog",
      alarmDescription: "Package queue backing up - collection may be stalled",
      metric: packageQueue.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
      }),
      threshold: 2000, // Allow for seed operations and batch processing
      evaluationPeriods: 2,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    queueBacklogAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    queueBacklogAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // Package Queue Message Age Alarm - detects stuck messages
    const messageAgeAlarm = new cloudwatch.Alarm(this, "PackageQueueAgeAlarm", {
      alarmName: "pkgwatch-package-queue-message-age",
      alarmDescription: "Messages stuck in queue for >30 minutes",
      metric: packageQueue.metricApproximateAgeOfOldestMessage({
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1800, // 30 minutes in seconds
      evaluationPeriods: 2,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    messageAgeAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    messageAgeAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 2. Refresh Dispatcher Error Alarm (Critical - single point of failure)
    const dispatcherErrorAlarm = new cloudwatch.Alarm(
      this,
      "DispatcherErrorAlarm",
      {
        alarmName: "pkgwatch-dispatcher-errors",
        alarmDescription:
          "Refresh dispatcher failing - pipeline not triggering",
        metric: refreshDispatcher.metricErrors({
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }
    );
    dispatcherErrorAlarm.addAlarmAction(
      new cloudwatchActions.SnsAction(this.alertTopic)
    );
    dispatcherErrorAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 3. Package Collector Error Rate
    const collectorErrorAlarm = new cloudwatch.Alarm(
      this,
      "CollectorErrorAlarm",
      {
        alarmName: "pkgwatch-collector-errors",
        alarmDescription: "High error rate in package collector Lambda",
        metric: packageCollector.metricErrors({
          period: cdk.Duration.minutes(5),
        }),
        threshold: 5,
        evaluationPeriods: 2,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }
    );
    collectorErrorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    collectorErrorAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 3b. Retry Dispatcher Error Alarm
    const retryDispatcherErrorAlarm = new cloudwatch.Alarm(
      this,
      "RetryDispatcherErrorAlarm",
      {
        alarmName: "pkgwatch-retry-dispatcher-errors",
        alarmDescription:
          "Retry dispatcher failing - incomplete packages not being retried",
        metric: retryDispatcher.metricErrors({
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 2,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }
    );
    retryDispatcherErrorAlarm.addAlarmAction(
      new cloudwatchActions.SnsAction(this.alertTopic)
    );
    retryDispatcherErrorAlarm.addOkAction(
      new cloudwatchActions.SnsAction(this.alertTopic)
    );

    // 4. Score Calculator Error Rate
    const scoreErrorAlarm = new cloudwatch.Alarm(this, "ScoreErrorAlarm", {
      alarmName: "pkgwatch-score-calculator-errors",
      alarmDescription: "High error rate in score calculator Lambda",
      metric: scoreCalculator.metricErrors({
        period: cdk.Duration.minutes(5),
      }),
      threshold: 5,
      evaluationPeriods: 2,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    scoreErrorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    scoreErrorAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 5. DynamoDB Throttling Alarm (packages table)
    const throttleAlarm = new cloudwatch.Alarm(this, "DynamoThrottleAlarm", {
      alarmName: "pkgwatch-dynamo-throttling",
      alarmDescription: "DynamoDB throttling detected - may need capacity increase",
      metric: packagesTable.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.QUERY,
        ],
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10,
      evaluationPeriods: 2,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    throttleAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    throttleAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 6. API Keys Table Throttling Alarm (CRITICAL - auth failures go silent without this)
    const apiKeysThrottleAlarm = new cloudwatch.Alarm(this, "ApiKeysThrottleAlarm", {
      alarmName: "pkgwatch-apikeys-throttling",
      alarmDescription: "API Keys table throttling - authentication requests may fail",
      metric: apiKeysTable.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.QUERY,
          dynamodb.Operation.UPDATE_ITEM,
        ],
        period: cdk.Duration.minutes(5),
      }),
      threshold: 5, // Lower threshold - auth failures are critical
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    apiKeysThrottleAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    apiKeysThrottleAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 7. Scheduled Job Execution Alarm (CRITICAL - detects when dispatcher stops running)
    // If dispatcher hasn't been invoked in 24 hours, something is wrong with scheduling
    // Note: Using 24h (86400s) which is the max standard CloudWatch period
    const dispatcherNotRunningAlarm = new cloudwatch.Alarm(this, "DispatcherNotRunningAlarm", {
      alarmName: "pkgwatch-dispatcher-not-running",
      alarmDescription: "Refresh dispatcher has not run in 24 hours - data staleness risk",
      metric: refreshDispatcher.metricInvocations({
        period: cdk.Duration.hours(24), // Max standard CloudWatch period
        statistic: "Sum",
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING, // No data = job didn't run
    });
    dispatcherNotRunningAlarm.addAlarmAction(new cloudwatchActions.SnsAction(this.alertTopic));
    dispatcherNotRunningAlarm.addOkAction(new cloudwatchActions.SnsAction(this.alertTopic));

    // 6. Operations Dashboard
    new cloudwatch.Dashboard(this, "OperationsDashboard", {
      dashboardName: "PkgWatch-Operations",
      widgets: [
        // Row 1: Queue metrics
        [
          new cloudwatch.GraphWidget({
            title: "SQS Queue Depth",
            left: [
              packageQueue.metricApproximateNumberOfMessagesVisible(),
              dlq.metricApproximateNumberOfMessagesVisible(),
            ],
            width: 12,
          }),
          new cloudwatch.GraphWidget({
            title: "Messages Processed",
            left: [packageQueue.metricNumberOfMessagesReceived()],
            width: 12,
          }),
        ],
        // Row 2: Lambda metrics
        [
          new cloudwatch.GraphWidget({
            title: "Lambda Invocations",
            left: [
              packageCollector.metricInvocations(),
              scoreCalculator.metricInvocations(),
              refreshDispatcher.metricInvocations(),
            ],
            width: 8,
          }),
          new cloudwatch.GraphWidget({
            title: "Lambda Errors",
            left: [
              packageCollector.metricErrors(),
              scoreCalculator.metricErrors(),
            ],
            width: 8,
          }),
          new cloudwatch.GraphWidget({
            title: "Lambda Duration (P99)",
            left: [
              packageCollector.metricDuration({ statistic: "p99" }),
              scoreCalculator.metricDuration({ statistic: "p99" }),
            ],
            width: 8,
          }),
        ],
        // Row 3: DynamoDB metrics
        [
          new cloudwatch.GraphWidget({
            title: "DynamoDB Consumed Capacity",
            left: [
              packagesTable.metricConsumedReadCapacityUnits(),
              packagesTable.metricConsumedWriteCapacityUnits(),
            ],
            width: 12,
          }),
          new cloudwatch.GraphWidget({
            title: "DynamoDB Throttled Requests",
            left: [
              packagesTable.metricThrottledRequestsForOperations({
                operations: [
                  dynamodb.Operation.PUT_ITEM,
                  dynamodb.Operation.GET_ITEM,
                  dynamodb.Operation.QUERY,
                ],
              }),
            ],
            width: 12,
          }),
        ],
      ],
    })

    // ===========================================
    // Outputs
    // ===========================================
    new cdk.CfnOutput(this, "PackageQueueUrl", {
      value: packageQueue.queueUrl,
      description: "SQS queue URL for package processing",
      exportName: "PkgWatchPackageQueueUrl",
    });

    new cdk.CfnOutput(this, "GitHubTokenSecretArn", {
      value: githubTokenSecret.secretArn,
      description: "GitHub token secret ARN (set value manually)",
      exportName: "PkgWatchGitHubTokenSecretArn",
    });

    new cdk.CfnOutput(this, "AlertTopicArn", {
      value: this.alertTopic.topicArn,
      description: "SNS topic ARN for alerts (subscribe email/Slack)",
      exportName: "PkgWatchAlertTopicArn",
    });
  }
}
