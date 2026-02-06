"""
Graph Expander Worker - Processes packages for dependency discovery.

Triggered by SQS Discovery Queue.
For each package, fetches dependencies and adds new popular packages to DB.

This is the core workhorse of the sustainable discovery system.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")
s3 = boto3.client("s3")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
RAW_DATA_BUCKET = os.environ.get("RAW_DATA_BUCKET")
DEPENDENTS_THRESHOLD = 100  # Only add packages with this many dependents
CACHE_TTL_DAYS = 7


def handler(event, context):
    """Process a batch of packages for dependency discovery."""
    table = dynamodb.Table(PACKAGES_TABLE)
    total_discovered = 0
    total_processed = 0

    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])
            packages = message.get("packages", [])
            ecosystem = message.get("ecosystem", "npm")

            for pkg_name in packages:
                discovered = asyncio.run(process_package(table, pkg_name, ecosystem))
                total_discovered += discovered
                total_processed += 1

        except Exception as e:
            logger.error(f"Failed to process record: {e}")

    # Emit metrics
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "GraphExpanderProcessed", "value": total_processed},
                {"metric_name": "GraphExpanderDiscovered", "value": total_discovered},
            ]
        )
    except ImportError:
        pass  # Metrics not available in test environment

    logger.info(f"Processed {total_processed} packages, discovered {total_discovered} new")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "processed": total_processed,
                "discovered": total_discovered,
            }
        ),
    }


async def process_package(table, pkg_name: str, ecosystem: str) -> int:
    """Process a single package for dependency discovery."""
    discovered = 0

    try:
        # Try S3 cache first (reduces deps.dev calls)
        deps = get_cached_dependencies(ecosystem, pkg_name)

        if deps is None:
            # Fetch from deps.dev
            from collectors.depsdev_collector import get_dependencies, get_package_info

            deps = await get_dependencies(pkg_name, ecosystem)

            # Cache result
            if deps:
                cache_dependencies(ecosystem, pkg_name, deps)

        if not deps:
            return 0

        # Check each dependency
        for dep_name in deps:
            # Skip if already in DB
            if package_exists(table, ecosystem, dep_name):
                continue

            # Check if popular enough (has many dependents)
            from collectors.depsdev_collector import get_package_info

            info = await get_package_info(dep_name, ecosystem)
            if not info:
                continue

            dependents_count = info.get("dependents_count", 0)
            if dependents_count < DEPENDENTS_THRESHOLD:
                continue

            # Add to database
            now = datetime.now(timezone.utc).isoformat()
            try:
                table.put_item(
                    Item={
                        "pk": f"{ecosystem}#{dep_name}",
                        "sk": "LATEST",
                        "name": dep_name,
                        "ecosystem": ecosystem,
                        "tier": 3,  # New packages start at tier 3
                        "source": "graph_expansion",
                        "created_at": now,
                        "last_updated": now,
                        "data_status": "pending",
                    },
                    ConditionExpression="attribute_not_exists(pk)",
                )
                discovered += 1
                logger.info(f"Discovered new package: {dep_name} ({dependents_count} dependents)")

                # Queue for collection
                queue_for_collection(ecosystem, dep_name)

            except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
                # Already exists (race condition)
                pass

    except Exception as e:
        logger.error(f"Error processing {pkg_name}: {e}")

    return discovered


def package_exists(table, ecosystem: str, name: str) -> bool:
    """Check if package already exists in database."""
    try:
        response = table.get_item(
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            ProjectionExpression="pk",
        )
        return "Item" in response
    except Exception:
        return False


def queue_for_collection(ecosystem: str, name: str):
    """Queue package for data collection."""
    if not PACKAGE_QUEUE_URL:
        return

    try:
        sqs.send_message(
            QueueUrl=PACKAGE_QUEUE_URL,
            MessageBody=json.dumps(
                {
                    "ecosystem": ecosystem,
                    "name": name,
                    "tier": 3,
                    "reason": "graph_expansion_discovery",
                }
            ),
        )
    except Exception as e:
        logger.error(f"Failed to queue {name} for collection: {e}")


def get_cached_dependencies(ecosystem: str, name: str) -> list[str] | None:
    """Check S3 cache for dependencies (7-day TTL)."""
    if not RAW_DATA_BUCKET:
        return None

    try:
        response = s3.get_object(
            Bucket=RAW_DATA_BUCKET,
            Key=f"deps-cache/{ecosystem}/{name}.json",
        )
        data = json.loads(response["Body"].read())
        cached_at = datetime.fromisoformat(data["cached_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - cached_at < timedelta(days=CACHE_TTL_DAYS):
            return data["dependencies"]
    except s3.exceptions.NoSuchKey:
        pass
    except Exception as e:
        logger.debug(f"Cache miss for {name}: {e}")

    return None


def cache_dependencies(ecosystem: str, name: str, deps: list[str]):
    """Store dependencies in S3 cache."""
    if not RAW_DATA_BUCKET:
        return

    try:
        s3.put_object(
            Bucket=RAW_DATA_BUCKET,
            Key=f"deps-cache/{ecosystem}/{name}.json",
            Body=json.dumps(
                {
                    "cached_at": datetime.now(timezone.utc).isoformat(),
                    "dependencies": deps,
                }
            ),
            ContentType="application/json",
        )
    except Exception as e:
        logger.warning(f"Failed to cache dependencies for {name}: {e}")
