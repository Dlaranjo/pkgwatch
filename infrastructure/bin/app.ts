#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { StorageStack } from "../lib/storage-stack";
import { PipelineStack } from "../lib/pipeline-stack";
import { ApiStack } from "../lib/api-stack";
import { BudgetStack } from "../lib/budget-stack";

const app = new cdk.App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || "us-east-1",
};

// Storage stack (DynamoDB + S3)
const storageStack = new StorageStack(app, "PkgWatchStorage", {
  env,
  description: "PkgWatch storage resources (DynamoDB tables, S3 buckets)",
});

// Pipeline stack (EventBridge + SQS + Lambda collectors)
// IMPORTANT: Set ALERT_EMAIL env var to receive CloudWatch alarm notifications
const alertEmail = process.env.ALERT_EMAIL?.trim() || undefined;
const environment = process.env.CDK_ENV || "production";

if (!alertEmail) {
  if (environment === "production") {
    throw new Error(
      "ALERT_EMAIL is required for production deployments. " +
      "Set ALERT_EMAIL=your@email.com to receive CloudWatch alarm notifications."
    );
  } else {
    console.warn(
      "WARNING: ALERT_EMAIL not set. CloudWatch alarms will not send notifications. " +
      "Set ALERT_EMAIL=your@email.com to receive alerts."
    );
  }
}

const pipelineStack = new PipelineStack(app, "PkgWatchPipeline", {
  env,
  description: "PkgWatch data collection pipeline",
  packagesTable: storageStack.packagesTable,
  rawDataBucket: storageStack.rawDataBucket,
  publicDataBucket: storageStack.publicDataBucket, // For public data like top-npm-packages.json
  apiKeysTable: storageStack.apiKeysTable, // For global GitHub rate limiting
  alertEmail, // Email for SNS alert notifications
});

// API stack (API Gateway + Lambda handlers)
const apiStack = new ApiStack(app, "PkgWatchApi", {
  env,
  description: "PkgWatch REST API",
  packagesTable: storageStack.packagesTable,
  apiKeysTable: storageStack.apiKeysTable,
  billingEventsTable: storageStack.billingEventsTable,
  referralEventsTable: storageStack.referralEventsTable,
  alertTopic: pipelineStack.alertTopic,
  packageQueue: pipelineStack.packageQueue, // For package request API endpoint
});

// Budget stack (cost monitoring and alerting)
const budgetStack = new BudgetStack(app, "PkgWatchBudgets", {
  env,
  description: "PkgWatch cost monitoring",
  alertTopic: pipelineStack.alertTopic,
  monthlyBudget: 200, // Alert at 80% of $200
});
budgetStack.addDependency(pipelineStack);

// Add tags to all resources (environment already defined above)
cdk.Tags.of(app).add("Project", "PkgWatch");
cdk.Tags.of(app).add("Environment", environment);
cdk.Tags.of(app).add("ManagedBy", "CDK");
