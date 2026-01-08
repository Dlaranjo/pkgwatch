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
const storageStack = new StorageStack(app, "DepHealthStorage", {
  env,
  description: "DepHealth storage resources (DynamoDB tables, S3 buckets)",
});

// Pipeline stack (EventBridge + SQS + Lambda collectors)
const pipelineStack = new PipelineStack(app, "DepHealthPipeline", {
  env,
  description: "DepHealth data collection pipeline",
  packagesTable: storageStack.packagesTable,
  rawDataBucket: storageStack.rawDataBucket,
  apiKeysTable: storageStack.apiKeysTable, // For global GitHub rate limiting
});

// API stack (API Gateway + Lambda handlers)
const apiStack = new ApiStack(app, "DepHealthApi", {
  env,
  description: "DepHealth REST API",
  packagesTable: storageStack.packagesTable,
  apiKeysTable: storageStack.apiKeysTable,
});

// Add tags to all resources
cdk.Tags.of(app).add("Project", "DepHealth");
cdk.Tags.of(app).add("Environment", "production");
