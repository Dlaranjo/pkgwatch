import * as cdk from "aws-cdk-lib";
import * as backup from "aws-cdk-lib/aws-backup";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as events from "aws-cdk-lib/aws-events";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct } from "constructs";

export class StorageStack extends cdk.Stack {
  public readonly packagesTable: dynamodb.Table;
  public readonly apiKeysTable: dynamodb.Table;
  public readonly billingEventsTable: dynamodb.Table;
  public readonly referralEventsTable: dynamodb.Table;
  public readonly rawDataBucket: s3.Bucket;
  public readonly accessLogsBucket: s3.Bucket;
  public readonly publicDataBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ===========================================
    // S3: Access Logs Bucket (must be created first)
    // ===========================================
    this.accessLogsBucket = new s3.Bucket(this, "AccessLogsBucket", {
      bucketName: `pkgwatch-access-logs-${this.account}`,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      lifecycleRules: [
        {
          // Retain access logs for 90 days for audit purposes
          expiration: cdk.Duration.days(90),
          enabled: true,
        },
      ],
    });

    // ===========================================
    // DynamoDB: Packages Table
    // ===========================================
    // PK: ecosystem#name (e.g., "npm#lodash")
    // SK: "LATEST" or version number
    // GSI: risk-level-index for querying risky packages
    this.packagesTable = new dynamodb.Table(this, "PackagesTable", {
      tableName: "pkgwatch-packages",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      encryption: dynamodb.TableEncryption.AWS_MANAGED, // Use AWS-managed CMK for encryption
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      deletionProtection: true, // Prevent accidental table deletion
      // Enable streams for score calculation trigger
      // NEW_AND_OLD_IMAGES allows loop prevention by comparing old/new collected_at
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
    });

    // GSI for querying packages by risk level
    // Allows: "Get all CRITICAL packages sorted by last_updated"
    this.packagesTable.addGlobalSecondaryIndex({
      indexName: "risk-level-index",
      partitionKey: { name: "risk_level", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "last_updated", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for querying packages by refresh tier
    // Allows efficient selection of packages due for refresh
    this.packagesTable.addGlobalSecondaryIndex({
      indexName: "tier-index",
      partitionKey: { name: "tier", type: dynamodb.AttributeType.NUMBER },
      sortKey: { name: "last_updated", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // GSI for querying packages by data completeness status
    // Used by retry_dispatcher.py to find incomplete packages due for retry
    // NOTE: AWS has data-status-index-v2 but CloudFormation state has data-status-index
    // Keeping as data-status-index to match CFN state until drift is resolved
    // TODO: Sync CloudFormation state with AWS reality, then update to v2 with INCLUDE projection
    this.packagesTable.addGlobalSecondaryIndex({
      indexName: "data-status-index",
      partitionKey: { name: "data_status", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "next_retry_at", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // TODO: Deploy these GSIs one at a time after data-status-index-v2 rename syncs
    // GSI for querying packages by downloads (for public top-npm-packages list)
    // Used by publish_top_packages.py to export download-ranked package list
    // this.packagesTable.addGlobalSecondaryIndex({
    //   indexName: "downloads-index",
    //   partitionKey: { name: "ecosystem", type: dynamodb.AttributeType.STRING },
    //   sortKey: { name: "weekly_downloads", type: dynamodb.AttributeType.NUMBER },
    //   projectionType: dynamodb.ProjectionType.INCLUDE,
    //   nonKeyAttributes: ["name", "health_score", "risk_level"],
    // });

    // GSI for tracking package discovery source
    // Used for analytics on how packages were discovered (graph_expansion, user_request, etc.)
    // this.packagesTable.addGlobalSecondaryIndex({
    //   indexName: "source-index",
    //   partitionKey: { name: "source", type: dynamodb.AttributeType.STRING },
    //   sortKey: { name: "created_at", type: dynamodb.AttributeType.STRING },
    //   projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    // });

    // ===========================================
    // DynamoDB: API Keys Table
    // ===========================================
    // PK: user_id
    // SK: key_hash (SHA-256 of API key)
    // GSI: key-hash-index for O(1) key validation lookups
    this.apiKeysTable = new dynamodb.Table(this, "ApiKeysTable", {
      tableName: "pkgwatch-api-keys",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      encryption: dynamodb.TableEncryption.AWS_MANAGED, // Use AWS-managed CMK for encryption
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      deletionProtection: true, // Prevent accidental table deletion
      timeToLiveAttribute: "ttl", // Enable TTL for auto-expiring PENDING records
    });

    // GSI for looking up API key by hash
    // This allows O(1) lookup when validating incoming API keys
    // key_hash is duplicated as both SK and GSI PK
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "key-hash-index",
      partitionKey: { name: "key_hash", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for looking up user by email
    // Required for signup duplicate check and Stripe webhook tier updates
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "email-index",
      partitionKey: { name: "email", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for looking up pending signups by verification token
    // Replaces O(n) table scan with O(1) query for email verification
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "verification-token-index",
      partitionKey: {
        name: "verification_token",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // GSI for looking up user by Stripe customer ID
    // Required for subscription webhooks (upgrades/downgrades/cancellations)
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "stripe-customer-index",
      partitionKey: {
        name: "stripe_customer_id",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for looking up user by magic token
    // Replaces O(n) table scan with O(1) query for passwordless login
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "magic-token-index",
      partitionKey: {
        name: "magic_token",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // GSI for looking up user by referral code
    // Used to validate referral codes and credit referrers
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "referral-code-index",
      partitionKey: {
        name: "referral_code",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.INCLUDE,
      nonKeyAttributes: ["pk", "email"], // Include email for self-referral check
    });

    // GSI for looking up recovery sessions by session ID
    // Replaces O(n) table scan with O(1) query in recovery_verify_code.py
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "recovery-session-index",
      partitionKey: {
        name: "recovery_session_id",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for looking up recovery sessions by recovery token
    // Replaces O(n) table scan with O(1) query in recovery_update_email.py
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "recovery-token-index",
      partitionKey: {
        name: "recovery_token",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.INCLUDE,
      nonKeyAttributes: ["email", "ttl", "verified", "recovery_method", "email_change_initiated"],
    });

    // GSI for looking up email change records by change token
    // Replaces O(n) table scan with O(1) query in recovery_confirm_email.py
    this.apiKeysTable.addGlobalSecondaryIndex({
      indexName: "change-token-index",
      partitionKey: {
        name: "change_token",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.INCLUDE,
      nonKeyAttributes: ["old_email", "new_email", "ttl", "recovery_session_sk"],
    });

    // ===========================================
    // DynamoDB: Billing Events Table
    // ===========================================
    // Audit table for Stripe webhook deduplication and dispute investigation
    // PK: event_id (Stripe's unique ID) - ensures reliable deduplication
    // SK: event_type
    // GSI: customer-index for querying events by Stripe customer
    this.billingEventsTable = new dynamodb.Table(this, "BillingEventsTable", {
      tableName: "pkgwatch-billing-events",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      deletionProtection: true, // Prevent accidental table deletion
      timeToLiveAttribute: "ttl", // Auto-expire events after 90 days
    });

    // GSI for querying events by Stripe customer ID
    // Useful for investigating billing issues and disputes
    this.billingEventsTable.addGlobalSecondaryIndex({
      indexName: "customer-index",
      partitionKey: {
        name: "customer_id",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: "processed_at",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===========================================
    // DynamoDB: Referral Events Table
    // ===========================================
    // Tracks referral relationships and reward events
    // PK: referrer_id (user who made the referral)
    // SK: referred_id#event_type (e.g., "user_abc123#signup", "user_abc123#paid")
    // TTL: 90 days for pending referrals that never convert
    this.referralEventsTable = new dynamodb.Table(this, "ReferralEventsTable", {
      tableName: "pkgwatch-referral-events",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      deletionProtection: true,
      timeToLiveAttribute: "ttl",
    });

    // GSI for querying referrals needing retention check
    // Allows scheduled Lambda to efficiently find referrals due for 2-month retention bonus
    this.referralEventsTable.addGlobalSecondaryIndex({
      indexName: "retention-due-index",
      partitionKey: {
        name: "needs_retention_check",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: "retention_check_date",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ===========================================
    // S3: Raw Data Bucket
    // ===========================================
    // Stores raw API responses for debugging and reprocessing
    this.rawDataBucket = new s3.Bucket(this, "RawDataBucket", {
      bucketName: `pkgwatch-raw-data-${this.account}`,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      serverAccessLogsBucket: this.accessLogsBucket, // Enable access logging for audit
      serverAccessLogsPrefix: "raw-data-bucket/",
      versioned: true, // Enable versioning for recovery from accidental overwrites
      lifecycleRules: [
        {
          // Delete raw data after 7 days (we only need it for debugging)
          // Reduced from 30 days for cost optimization
          expiration: cdk.Duration.days(7),
          enabled: true,
        },
        {
          // Clean up old versions to prevent storage cost explosion
          noncurrentVersionExpiration: cdk.Duration.days(7),
          enabled: true,
        },
      ],
    });

    // ===========================================
    // S3: Public Data Bucket
    // ===========================================
    // Hosts public data files like top-npm-packages.json
    // Used by publish_top_packages.py for community benefit
    this.publicDataBucket = new s3.Bucket(this, "PublicDataBucket", {
      bucketName: `pkgwatch-public-data-${this.account}`,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true, // Enable versioning for recovery from bad publishes
      // Allow public read for the data files (unlike other buckets)
      blockPublicAccess: new s3.BlockPublicAccess({
        blockPublicAcls: false,
        ignorePublicAcls: false,
        blockPublicPolicy: false,
        restrictPublicBuckets: false,
      }),
      websiteIndexDocument: "index.html",
      lifecycleRules: [
        {
          // Clean up old versions after 30 days
          noncurrentVersionExpiration: cdk.Duration.days(30),
          enabled: true,
        },
      ],
    });

    // Bucket policy for public read access to data/* prefix only
    this.publicDataBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetObject"],
        resources: [this.publicDataBucket.arnForObjects("data/*")],
        principals: [new iam.AnyPrincipal()],
      })
    );

    // ===========================================
    // AWS Backup: DynamoDB Backup Plan
    // ===========================================
    // Daily backups with 35-day retention for disaster recovery
    const backupVault = new backup.BackupVault(this, "BackupVault", {
      backupVaultName: "pkgwatch-backup-vault",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const backupPlan = new backup.BackupPlan(this, "DynamoBackupPlan", {
      backupPlanName: "pkgwatch-daily-backup",
      backupPlanRules: [
        new backup.BackupPlanRule({
          ruleName: "DailyBackup",
          scheduleExpression: events.Schedule.cron({ hour: "5", minute: "0" }),
          startWindow: cdk.Duration.hours(1),
          completionWindow: cdk.Duration.hours(2),
          deleteAfter: cdk.Duration.days(35),
          backupVault: backupVault,
        }),
      ],
    });

    backupPlan.addSelection("DynamoTables", {
      resources: [
        backup.BackupResource.fromDynamoDbTable(this.packagesTable),
        backup.BackupResource.fromDynamoDbTable(this.apiKeysTable),
        backup.BackupResource.fromDynamoDbTable(this.billingEventsTable),
        backup.BackupResource.fromDynamoDbTable(this.referralEventsTable),
      ],
    });

    // ===========================================
    // Outputs
    // ===========================================
    new cdk.CfnOutput(this, "PackagesTableName", {
      value: this.packagesTable.tableName,
      description: "DynamoDB packages table name",
      exportName: "PkgWatchPackagesTable",
    });

    new cdk.CfnOutput(this, "ApiKeysTableName", {
      value: this.apiKeysTable.tableName,
      description: "DynamoDB API keys table name",
      exportName: "PkgWatchApiKeysTable",
    });

    new cdk.CfnOutput(this, "BillingEventsTableName", {
      value: this.billingEventsTable.tableName,
      description: "DynamoDB billing events table name",
      exportName: "PkgWatchBillingEventsTable",
    });

    new cdk.CfnOutput(this, "ReferralEventsTableName", {
      value: this.referralEventsTable.tableName,
      description: "DynamoDB referral events table name",
      exportName: "PkgWatchReferralEventsTable",
    });

    new cdk.CfnOutput(this, "RawDataBucketName", {
      value: this.rawDataBucket.bucketName,
      description: "S3 raw data bucket name",
      exportName: "PkgWatchRawDataBucket",
    });

    new cdk.CfnOutput(this, "PublicDataBucketName", {
      value: this.publicDataBucket.bucketName,
      description: "S3 public data bucket name",
      exportName: "PkgWatchPublicDataBucket",
    });
  }
}
