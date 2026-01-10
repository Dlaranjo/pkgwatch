#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { StorageStack } from "../lib/storage-stack";
import { PipelineStack } from "../lib/pipeline-stack";
import { ApiStack } from "../lib/api-stack";

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
if (!alertEmail) {
  console.warn(
    "WARNING: ALERT_EMAIL not set. CloudWatch alarms will not send notifications. " +
    "Set ALERT_EMAIL=your@email.com to receive alerts."
  );
}

const pipelineStack = new PipelineStack(app, "PkgWatchPipeline", {
  env,
  description: "PkgWatch data collection pipeline",
  packagesTable: storageStack.packagesTable,
  rawDataBucket: storageStack.rawDataBucket,
  apiKeysTable: storageStack.apiKeysTable, // For global GitHub rate limiting
  alertEmail, // Email for SNS alert notifications
});

// API stack (API Gateway + Lambda handlers)
const apiStack = new ApiStack(app, "PkgWatchApi", {
  env,
  description: "PkgWatch REST API",
  packagesTable: storageStack.packagesTable,
  apiKeysTable: storageStack.apiKeysTable,
  alertTopic: pipelineStack.alertTopic,
});

// Add tags to all resources
const environment = process.env.CDK_ENV || "production";
cdk.Tags.of(app).add("Project", "PkgWatch");
cdk.Tags.of(app).add("Environment", environment);
cdk.Tags.of(app).add("ManagedBy", "CDK");
