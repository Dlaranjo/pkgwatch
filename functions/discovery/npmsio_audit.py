"""
npms.io Quarterly Audit - Finds popular packages we're missing.

Triggered by EventBridge quarterly (1st of Jan/Apr/Jul/Oct at 2:00 AM UTC).

This addresses the "bootstrap gap" identified in opus review:
Graph expansion only discovers dependencies of existing packages.
New popular packages with no dependents won't be discovered.

npms.io provides quality-scored package rankings that help find these gaps.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
import httpx

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
NPMSIO_API = "https://api.npms.io/v2"
QUALITY_THRESHOLD = 0.5  # Only add packages with score > 0.5
MAX_PACKAGES = 5000
BATCH_SIZE = 250  # npms.io supports up to 250 packages per request


def handler(event, context):
    """Audit coverage against npms.io top packages."""
    table = dynamodb.Table(PACKAGES_TABLE)

    # Fetch popular packages from npms.io
    top_packages = fetch_npmsio_top_packages(MAX_PACKAGES)
    logger.info(f"Fetched {len(top_packages)} packages from npms.io")

    if not top_packages:
        return {
            "statusCode": 200,
            "body": json.dumps({"audited": 0, "missing": 0, "added": 0}),
        }

    # Check which we're missing
    missing = []
    for pkg in top_packages:
        name = pkg.get("name")
        if not name:
            continue

        # Check if exists in our database
        try:
            response = table.get_item(
                Key={"pk": f"npm#{name}", "sk": "LATEST"},
                ProjectionExpression="pk",
            )
            if "Item" not in response:
                missing.append(pkg)
        except Exception as e:
            logger.warning(f"Error checking {name}: {e}")

    logger.info(f"Found {len(missing)} missing packages")

    # Add missing packages with sufficient quality
    added = 0
    queued = 0
    now = datetime.now(timezone.utc).isoformat()

    for pkg in missing:
        name = pkg.get("name")
        score = pkg.get("score", 0)

        # Skip low-quality packages
        if score < QUALITY_THRESHOLD:
            continue

        # Add to database
        try:
            table.put_item(
                Item={
                    "pk": f"npm#{name}",
                    "sk": "LATEST",
                    "name": name,
                    "ecosystem": "npm",
                    "tier": 3,
                    "source": "npmsio_audit",
                    "created_at": now,
                    "last_updated": now,
                    "data_status": "pending",
                    "next_retry_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "retry_count": 0,
                    "npmsio_score": Decimal(str(score)),
                },
                ConditionExpression="attribute_not_exists(pk)",
            )
            added += 1

            # Queue for collection
            if PACKAGE_QUEUE_URL:
                sqs.send_message(
                    QueueUrl=PACKAGE_QUEUE_URL,
                    MessageBody=json.dumps(
                        {
                            "ecosystem": "npm",
                            "name": name,
                            "tier": 3,
                            "reason": "npmsio_audit",
                        }
                    ),
                )
                queued += 1

        except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            # Already exists (race condition)
            pass
        except Exception as e:
            logger.error(f"Failed to add {name}: {e}")

    # Emit metrics
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "NpmsioAuditTotal", "value": len(top_packages)},
                {"metric_name": "NpmsioAuditMissing", "value": len(missing)},
                {"metric_name": "NpmsioAuditAdded", "value": added},
            ]
        )
    except ImportError:
        pass

    logger.info(f"Added {added} packages from npms.io audit")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "audited": len(top_packages),
                "missing": len(missing),
                "added": added,
                "queued": queued,
            }
        ),
    }


def fetch_npmsio_top_packages(limit: int) -> list[dict]:
    """
    Fetch top packages from npms.io by score.

    Uses the search endpoint with score:desc sorting.
    """
    packages = []
    offset = 0

    with httpx.Client(timeout=30.0) as client:
        while len(packages) < limit:
            try:
                # npms.io search with quality boost
                response = client.get(
                    f"{NPMSIO_API}/search",
                    params={
                        "q": "boost-exact:false",  # Include all packages
                        "size": min(250, limit - len(packages)),
                        "from": offset,
                    },
                )
                response.raise_for_status()
                data = response.json()

                results = data.get("results", [])
                if not results:
                    break

                for result in results:
                    pkg = result.get("package", {})
                    score = result.get("score", {})
                    packages.append(
                        {
                            "name": pkg.get("name"),
                            "score": score.get("final", 0),
                            "quality": score.get("detail", {}).get("quality", 0),
                            "popularity": score.get("detail", {}).get("popularity", 0),
                            "maintenance": score.get("detail", {}).get("maintenance", 0),
                        }
                    )

                offset += len(results)

                # npms.io limits to 10000 results
                if offset >= 10000:
                    break

            except httpx.HTTPStatusError as e:
                logger.error(f"npms.io API error: {e}")
                break
            except Exception as e:
                logger.error(f"Error fetching from npms.io: {e}")
                break

    return packages
