"""
Publish Top Packages - Exports download-ranked package list to public S3.

Triggered by EventBridge every Monday at 5:00 AM UTC (weekly).

Creates a public JSON file similar to hugovk's top-pypi-packages list.
Community benefit + can be used for future self-seeding.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PUBLIC_BUCKET = os.environ.get("PUBLIC_BUCKET")
MAX_PACKAGES = 10000


def handler(event, context):
    """Publish top npm packages to public S3 bucket."""
    if not PUBLIC_BUCKET:
        logger.error("PUBLIC_BUCKET not configured")
        return {"statusCode": 500, "error": "PUBLIC_BUCKET not configured"}

    table = dynamodb.Table(PACKAGES_TABLE)
    packages = []

    # Query using downloads-index GSI
    # Partition by ecosystem, sorted by weekly_downloads DESC
    try:
        # DynamoDB can't do DESC sort on numbers in key condition
        # So we query all and sort in memory
        response = table.query(
            IndexName="downloads-index",
            KeyConditionExpression=Key("ecosystem").eq("npm"),
            ScanIndexForward=False,  # Descending order
            Limit=MAX_PACKAGES,
        )
        packages = response.get("Items", [])

        # Handle pagination if needed
        while "LastEvaluatedKey" in response and len(packages) < MAX_PACKAGES:
            response = table.query(
                IndexName="downloads-index",
                KeyConditionExpression=Key("ecosystem").eq("npm"),
                ScanIndexForward=False,
                Limit=MAX_PACKAGES - len(packages),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            packages.extend(response.get("Items", []))

    except Exception as e:
        logger.error(f"Failed to query packages: {e}")
        return {"statusCode": 500, "error": str(e)}

    logger.info(f"Found {len(packages)} npm packages")

    if not packages:
        return {
            "statusCode": 200,
            "body": json.dumps({"published": 0}),
        }

    # Format output similar to hugovk's top-pypi-packages
    now = datetime.now(timezone.utc)
    output = {
        "last_update": now.isoformat(),
        "query": {
            "ecosystem": "npm",
            "sorted_by": "weekly_downloads",
            "limit": MAX_PACKAGES,
        },
        "rows": [],
    }

    for pkg in packages:
        weekly_downloads = pkg.get("weekly_downloads")
        if weekly_downloads is None:
            continue

        # Convert Decimal to int for JSON serialization
        health_score = pkg.get("health_score")
        if health_score is not None:
            health_score = int(health_score)

        output["rows"].append(
            {
                "project": pkg.get("name"),
                "download_count": int(weekly_downloads),
                "health_score": health_score,
                "risk_level": pkg.get("risk_level"),
            }
        )

    # Upload to public S3
    try:
        s3.put_object(
            Bucket=PUBLIC_BUCKET,
            Key="data/top-npm-packages.json",
            Body=json.dumps(output, indent=2),
            ContentType="application/json",
            CacheControl="max-age=3600",  # 1 hour cache
        )
        logger.info(f"Published {len(output['rows'])} packages to S3")
    except Exception as e:
        logger.error(f"Failed to upload to S3: {e}")
        return {"statusCode": 500, "error": str(e)}

    # Also publish a smaller "top 100" file for quick access
    top_100 = {
        "last_update": now.isoformat(),
        "query": {
            "ecosystem": "npm",
            "sorted_by": "weekly_downloads",
            "limit": 100,
        },
        "rows": output["rows"][:100],
    }

    try:
        s3.put_object(
            Bucket=PUBLIC_BUCKET,
            Key="data/top-100-npm-packages.json",
            Body=json.dumps(top_100, indent=2),
            ContentType="application/json",
            CacheControl="max-age=3600",
        )
    except Exception as e:
        logger.warning(f"Failed to upload top-100 file: {e}")

    # Emit metrics
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "PublishTopPackagesCount", "value": len(output["rows"])},
            ]
        )
    except ImportError:
        pass

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "published": len(output["rows"]),
                "bucket": PUBLIC_BUCKET,
                "key": "data/top-npm-packages.json",
            }
        ),
    }
