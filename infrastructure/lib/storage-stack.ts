import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct } from "constructs";

export class StorageStack extends cdk.Stack {
  public readonly packagesTable: dynamodb.Table;
  public readonly apiKeysTable: dynamodb.Table;
  public readonly rawDataBucket: s3.Bucket;
  public readonly accessLogsBucket: s3.Bucket;

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
      lifecycleRules: [
        {
          // Delete raw data after 7 days (we only need it for debugging)
          // Reduced from 30 days for cost optimization
          expiration: cdk.Duration.days(7),
          enabled: true,
        },
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

    new cdk.CfnOutput(this, "RawDataBucketName", {
      value: this.rawDataBucket.bucketName,
      description: "S3 raw data bucket name",
      exportName: "PkgWatchRawDataBucket",
    });
  }
}
