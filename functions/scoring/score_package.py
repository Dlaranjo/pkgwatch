"""
Score Package - Lambda handler for calculating and storing scores.

Can be triggered:
1. After data collection (via SQS/SNS)
2. On-demand for specific packages
3. Batch processing for all packages
"""

import json
import logging
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

from health_score import calculate_health_score
from abandonment_risk import calculate_abandonment_risk

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Defense in depth: skip scoring if package was scored recently
# This prevents infinite loops if the DynamoDB Streams filter doesn't work as expected
IDEMPOTENCY_WINDOW_SECONDS = int(os.environ.get("IDEMPOTENCY_WINDOW_SECONDS", "60"))


def to_decimal(obj):
    """Convert floats to Decimal for DynamoDB compatibility."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [to_decimal(v) for v in obj]
    return obj


def from_decimal(obj):
    """Convert Decimals to floats for math operations."""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: from_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [from_decimal(v) for v in obj]
    return obj

dynamodb = boto3.resource("dynamodb")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "dephealth-packages")


def handler(event, context):
    """
    Lambda handler for score calculation.

    Event formats:
    1. Single package: {"ecosystem": "npm", "name": "lodash"}
    2. SQS batch: {"Records": [...]}
    3. Recalculate all: {"action": "recalculate_all"}
    """
    if "Records" in event:
        # SQS batch processing
        return _process_sqs_batch(event)
    elif event.get("action") == "recalculate_all":
        # Batch recalculation
        return _recalculate_all()
    else:
        # Single package
        return _score_single_package(event)


def _score_single_package(event: dict) -> dict:
    """Score a single package."""
    ecosystem = event.get("ecosystem", "npm")
    name = event.get("name")

    if not name:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Package name is required"}),
        }

    table = dynamodb.Table(PACKAGES_TABLE)

    # Fetch package data
    try:
        response = table.get_item(Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"})
        item = response.get("Item")

        if not item:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": f"Package {name} not found"}),
            }
    except Exception as e:
        logger.error(f"Error fetching package: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }

    # Convert Decimals to floats for math operations
    item = from_decimal(item)

    # Defense in depth: skip if recently scored (prevents infinite loop)
    if IDEMPOTENCY_WINDOW_SECONDS > 0:
        scored_at = item.get("scored_at")
        if scored_at:
            try:
                scored_time = datetime.fromisoformat(
                    scored_at.replace("Z", "+00:00") if isinstance(scored_at, str) else scored_at
                )
                seconds_since_scored = (datetime.now(timezone.utc) - scored_time).total_seconds()
                if seconds_since_scored < IDEMPOTENCY_WINDOW_SECONDS:
                    logger.debug(f"Skipping {name} - scored {seconds_since_scored:.1f}s ago")
                    return {
                        "statusCode": 200,
                        "body": json.dumps({"skipped": True, "reason": "recently_scored"}),
                    }
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse scored_at for {name}: {e}")
                # Continue with scoring if we can't parse the timestamp

    # Calculate scores
    health_result = calculate_health_score(item)
    abandonment_result = calculate_abandonment_risk(item)

    # Update package with scores
    now = datetime.now(timezone.utc).isoformat()
    try:
        table.update_item(
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            UpdateExpression="""
                SET health_score = :hs,
                    risk_level = :rl,
                    score_components = :sc,
                    confidence = :conf,
                    abandonment_risk = :ar,
                    scored_at = :now
            """,
            ExpressionAttributeValues={
                ":hs": to_decimal(health_result["health_score"]),
                ":rl": health_result["risk_level"],
                ":sc": to_decimal(health_result["components"]),
                ":conf": to_decimal(health_result["confidence"]),
                ":ar": to_decimal(abandonment_result),
                ":now": now,
            },
        )
    except Exception as e:
        logger.error(f"Error updating package scores: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }

    return {
        "statusCode": 200,
        "body": json.dumps({
            "package": name,
            "ecosystem": ecosystem,
            "health_score": health_result["health_score"],
            "risk_level": health_result["risk_level"],
            "components": health_result["components"],
            "confidence": health_result["confidence"],
            "abandonment_risk": abandonment_result,
        }),
    }


def _process_sqs_batch(event: dict) -> dict:
    """Process a batch of packages from SQS."""
    successes = 0
    failures = 0

    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])
            result = _score_single_package(message)

            if result["statusCode"] == 200:
                successes += 1
            else:
                failures += 1
                logger.warning(f"Failed to score package: {result}")

        except Exception as e:
            logger.error(f"Error processing record: {e}")
            failures += 1

    return {
        "statusCode": 200,
        "body": json.dumps({
            "processed": successes + failures,
            "successes": successes,
            "failures": failures,
        }),
    }


def _recalculate_all() -> dict:
    """Recalculate scores for all packages."""
    table = dynamodb.Table(PACKAGES_TABLE)

    recalculated = 0
    errors = 0

    # Scan all packages - only need pk to extract ecosystem and name
    response = table.scan(
        FilterExpression="sk = :latest",
        ExpressionAttributeValues={":latest": "LATEST"},
        ProjectionExpression="pk",
    )

    packages = response.get("Items", [])

    while "LastEvaluatedKey" in response:
        response = table.scan(
            FilterExpression="sk = :latest",
            ExpressionAttributeValues={":latest": "LATEST"},
            ProjectionExpression="pk",
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        packages.extend(response.get("Items", []))

    logger.info(f"Recalculating scores for {len(packages)} packages")

    for pkg in packages:
        try:
            # Extract ecosystem and name from pk (format: "ecosystem#name")
            pk = pkg.get("pk", "")
            if "#" not in pk:
                logger.warning(f"Invalid pk format: {pk}")
                errors += 1
                continue

            ecosystem, name = pk.split("#", 1)

            result = _score_single_package({
                "ecosystem": ecosystem,
                "name": name,
            })

            if result["statusCode"] == 200:
                recalculated += 1
            else:
                errors += 1

        except Exception as e:
            logger.error(f"Error recalculating {pkg.get('pk')}: {e}")
            errors += 1

    return {
        "statusCode": 200,
        "body": json.dumps({
            "recalculated": recalculated,
            "errors": errors,
            "total": len(packages),
        }),
    }
