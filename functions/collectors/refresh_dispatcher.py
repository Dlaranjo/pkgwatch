"""
Refresh Dispatcher - Triggered by EventBridge schedules.

Dispatches package refresh jobs to SQS based on tier:
- Tier 1: Top 100 packages (daily refresh)
- Tier 2: Top 500 packages (every 3 days)
- Tier 3: All 2,500 packages (weekly)
"""

import json
import logging
import os
import random
import zlib
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")

# Configurable jitter by tier (in seconds)
JITTER_MAX_SECONDS = {
    1: int(os.environ.get("TIER1_JITTER_MAX", "300")),  # 5 minutes default
    2: int(os.environ.get("TIER2_JITTER_MAX", "600")),  # 10 minutes default
    3: int(os.environ.get("TIER3_JITTER_MAX", "900")),  # 15 minutes max (SQS limit)
}

# SQS DelaySeconds maximum is 900 seconds (15 minutes)
SQS_MAX_DELAY_SECONDS = 900


def handler(event, context):
    """
    Lambda handler for refresh dispatcher.

    Event format (from EventBridge):
    {
        "tier": 1,           # Which tier to refresh (1, 2, or 3)
        "reason": "daily_refresh"
    }
    """
    # Validate required environment variables early
    if not PACKAGE_QUEUE_URL:
        logger.error("PACKAGE_QUEUE_URL environment variable not configured")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "PACKAGE_QUEUE_URL not configured"}),
        }

    tier = event.get("tier", 3)  # Default to all packages
    reason = event.get("reason", "manual")

    # Validate tier is valid
    if tier not in (1, 2, 3):
        logger.warning(f"Invalid tier {tier}, defaulting to 3")
        tier = 3

    logger.info(f"Starting refresh dispatch for tier {tier}, reason: {reason}")

    table = dynamodb.Table(PACKAGES_TABLE)

    # Query packages by tier using GSI
    packages_to_refresh = []

    try:
        # Use tier-index GSI to efficiently query packages by tier
        # Each tier refresh ONLY refreshes that specific tier's packages
        # - Tier 1 (daily): top 100 packages
        # - Tier 2 (every 3 days): packages 101-500
        # - Tier 3 (weekly): packages 501-2500
        # This prevents duplicate refreshes across schedules
        tiers_to_refresh = [tier]  # Only the requested tier

        for t in tiers_to_refresh:
            response = table.query(
                IndexName="tier-index",
                KeyConditionExpression=Key("tier").eq(t),
                ProjectionExpression="pk",  # Only need the partition key
            )
            packages_to_refresh.extend(item["pk"] for item in response.get("Items", []))

            # Handle pagination
            while "LastEvaluatedKey" in response:
                response = table.query(
                    IndexName="tier-index",
                    KeyConditionExpression=Key("tier").eq(t),
                    ProjectionExpression="pk",
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                packages_to_refresh.extend(item["pk"] for item in response.get("Items", []))

    except Exception as e:
        logger.error(f"Error querying packages: {e}")
        raise

    # Sub-batch filtering for spreading collection across hours/days
    sub_batch = event.get("sub_batch")
    total_sub_batches = event.get("total_sub_batches")
    if sub_batch is not None and total_sub_batches:
        if sub_batch < 0 or sub_batch >= total_sub_batches:
            logger.error(f"Invalid sub_batch config: sub_batch ({sub_batch}) >= total_sub_batches ({total_sub_batches})")
            return {"statusCode": 400, "body": "Invalid sub_batch configuration"}
        packages_to_refresh = [
            pk for pk in packages_to_refresh if zlib.crc32(pk.encode()) % total_sub_batches == sub_batch
        ]
        logger.info(f"Sub-batch {sub_batch}/{total_sub_batches}: filtered to {len(packages_to_refresh)} packages")
    else:
        logger.info(f"Found {len(packages_to_refresh)} packages to refresh")

    force_refresh = event.get("force_refresh", False)

    if not packages_to_refresh:
        logger.warning("No packages found for refresh")
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "No packages to refresh",
                    "tier": tier,
                }
            ),
        }

    # Send messages to SQS in batches of 10
    batch_size = 10
    messages_sent = 0
    errors = []

    for i in range(0, len(packages_to_refresh), batch_size):
        batch = packages_to_refresh[i : i + batch_size]

        entries = []
        for j, pk in enumerate(batch):
            # pk format is "ecosystem#name", e.g., "npm#lodash"
            # Validate pk format before splitting
            if "#" not in pk:
                logger.warning(f"Malformed pk (missing #): {pk}, skipping")
                continue

            ecosystem, name = pk.split("#", 1)
            if not ecosystem or not name:
                logger.warning(f"Malformed pk (empty ecosystem or name): {pk}, skipping")
                continue

            # Add random jitter to spread load (tier-based)
            # Cap at SQS maximum of 900 seconds
            jitter_max = min(JITTER_MAX_SECONDS.get(tier, 60), SQS_MAX_DELAY_SECONDS)
            jitter = random.randint(0, jitter_max)

            message_body = {
                "ecosystem": ecosystem,
                "name": name,
                "tier": tier,
                "reason": reason,
                "dispatched_at": datetime.now(timezone.utc).isoformat(),
            }
            if force_refresh:
                message_body["force_refresh"] = True

            entries.append(
                {
                    "Id": str(i + j),
                    "MessageBody": json.dumps(message_body),
                    "DelaySeconds": jitter,
                }
            )

        try:
            response = sqs.send_message_batch(
                QueueUrl=PACKAGE_QUEUE_URL,
                Entries=entries,
            )
            messages_sent += len(response.get("Successful", []))

            if response.get("Failed"):
                for failure in response["Failed"]:
                    logger.error(f"Failed to send message: {failure}")
                    errors.append(failure)

        except Exception as e:
            logger.error(f"Error sending batch to SQS: {e}")
            errors.append(str(e))

    logger.info(f"Dispatched {messages_sent} packages for refresh")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": f"Dispatched {messages_sent} packages for refresh",
                "tier": tier,
                "total_packages": len(packages_to_refresh),
                "messages_sent": messages_sent,
                "errors": len(errors),
            }
        ),
    }
