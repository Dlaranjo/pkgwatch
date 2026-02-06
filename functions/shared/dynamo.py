"""
DynamoDB helpers for package operations.
"""

import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from .aws_clients import get_dynamodb
from .constants import THROTTLING_ERRORS
from .types import PackageData

logger = logging.getLogger(__name__)

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")


def get_package(ecosystem: str, name: str, max_retries: int = 3) -> Optional[PackageData]:
    """
    Get package data from DynamoDB with retry for throttling.

    Args:
        ecosystem: Package ecosystem (e.g., "npm")
        name: Package name (e.g., "lodash")
        max_retries: Maximum number of retry attempts for throttling errors

    Returns:
        Package data dict or None if not found
    """
    table = get_dynamodb().Table(PACKAGES_TABLE)

    for attempt in range(max_retries):
        try:
            response = table.get_item(Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"})
            return response.get("Item")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in THROTTLING_ERRORS:
                if attempt < max_retries - 1:
                    # Exponential backoff with jitter to prevent thundering herd
                    base_delay = min(0.1 * (2 ** attempt), 2.0)
                    jitter = random.uniform(0, base_delay * 0.5)
                    delay = base_delay + jitter
                    logger.warning(
                        f"DynamoDB throttled for {ecosystem}/{name}, "
                        f"retry {attempt + 1}/{max_retries} in {delay:.2f}s"
                    )
                    time.sleep(delay)
                    continue
            # Non-throttling ClientError - don't retry
            logger.error(f"Error fetching package {ecosystem}/{name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching package {ecosystem}/{name}: {e}")
            return None

    # Max retries exceeded
    logger.error(f"Max retries exceeded for {ecosystem}/{name}")
    return None


def put_package(ecosystem: str, name: str, data: dict, tier: int = 3) -> None:
    """
    Store or update package data in DynamoDB.

    Args:
        ecosystem: Package ecosystem
        name: Package name
        data: Package data to store
        tier: Refresh tier (1=daily, 2=3-day, 3=weekly)
    """
    table = get_dynamodb().Table(PACKAGES_TABLE)

    item = {
        "pk": f"{ecosystem}#{name}",
        "sk": "LATEST",
        "ecosystem": ecosystem,
        "name": name,
        "tier": tier,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        **data,
    }

    # Remove None values and empty strings (DynamoDB rejects empty strings by default)
    item = {k: v for k, v in item.items() if v is not None and v != ""}

    table.put_item(Item=item)


def query_packages_by_risk(risk_level: str, limit: int = 100) -> list[dict]:
    """
    Query packages by risk level using GSI.

    Args:
        risk_level: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
        limit: Maximum number of results

    Returns:
        List of packages sorted by last_updated (newest first)
    """
    table = get_dynamodb().Table(PACKAGES_TABLE)

    response = table.query(
        IndexName="risk-level-index",
        KeyConditionExpression=Key("risk_level").eq(risk_level),
        ScanIndexForward=False,  # Newest first
        Limit=limit,
    )

    return response.get("Items", [])


def query_packages_by_tier(tier: int) -> list[dict]:
    """
    Query packages by refresh tier using GSI.

    Args:
        tier: Refresh tier (1, 2, or 3)

    Returns:
        List of package keys for refresh
    """
    table = get_dynamodb().Table(PACKAGES_TABLE)

    packages = []
    response = table.query(
        IndexName="tier-index",
        KeyConditionExpression=Key("tier").eq(tier),
        ProjectionExpression="pk",
    )
    packages.extend(response.get("Items", []))

    # Handle pagination
    while "LastEvaluatedKey" in response:
        response = table.query(
            IndexName="tier-index",
            KeyConditionExpression=Key("tier").eq(tier),
            ProjectionExpression="pk",
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        packages.extend(response.get("Items", []))

    return packages


def update_package_tier(ecosystem: str, name: str, new_tier: int) -> None:
    """
    Update a package's refresh tier.

    Args:
        ecosystem: Package ecosystem
        name: Package name
        new_tier: New tier (1, 2, or 3)
    """
    table = get_dynamodb().Table(PACKAGES_TABLE)

    table.update_item(
        Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
        UpdateExpression="SET tier = :tier",
        ExpressionAttributeValues={":tier": new_tier},
    )


def update_package_scores(
    ecosystem: str,
    name: str,
    health_score: float,
    risk_level: str,
    components: dict,
    confidence: dict,
    abandonment_risk: dict,
) -> None:
    """
    Update package scores after calculation.

    Args:
        ecosystem: Package ecosystem
        name: Package name
        health_score: Calculated health score (0-100)
        risk_level: Risk level string
        components: Score component breakdown
        confidence: Confidence information
        abandonment_risk: Abandonment risk calculation
    """
    table = get_dynamodb().Table(PACKAGES_TABLE)

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
            ":hs": health_score,
            ":rl": risk_level,
            ":sc": components,
            ":conf": confidence,
            ":ar": abandonment_risk,
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )


def batch_get_packages(ecosystem: str, names: list[str]) -> dict[str, dict]:
    """
    Get multiple packages in a batch operation with proper UnprocessedKeys handling.

    Args:
        ecosystem: Package ecosystem
        names: List of package names

    Returns:
        Dict mapping package names to their data
    """
    if not names:
        return {}

    results = {}
    batch_size = 25  # DynamoDB BatchGetItem limit
    max_retries = 5

    for i in range(0, len(names), batch_size):
        batch_names = names[i : i + batch_size]
        keys = [{"pk": f"{ecosystem}#{name}", "sk": "LATEST"} for name in batch_names]

        request_items = {PACKAGES_TABLE: {"Keys": keys}}
        retry_count = 0

        while request_items and retry_count < max_retries:
            response = get_dynamodb().batch_get_item(RequestItems=request_items)

            # Process returned items
            for item in response.get("Responses", {}).get(PACKAGES_TABLE, []):
                name = item["pk"].split("#", 1)[1]
                results[name] = item

            # Handle UnprocessedKeys with exponential backoff
            unprocessed = response.get("UnprocessedKeys", {})
            if unprocessed:
                retry_count += 1
                unprocessed_count = len(unprocessed.get(PACKAGES_TABLE, {}).get("Keys", []))

                if retry_count >= max_retries:
                    logger.error(f"Max retries ({max_retries}) exceeded for {unprocessed_count} unprocessed keys")
                    break

                # Exponential backoff with jitter to prevent thundering herd
                base_delay = min(0.1 * (2 ** retry_count), 2.0)
                jitter = random.uniform(0, base_delay * 0.5)
                delay = base_delay + jitter
                logger.warning(f"Retry {retry_count}/{max_retries}: {unprocessed_count} unprocessed keys (delay: {delay:.2f}s)")
                time.sleep(delay)
                request_items = unprocessed
            else:
                request_items = None

    return results
