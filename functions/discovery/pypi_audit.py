"""
PyPI Quarterly Audit - Finds popular PyPI packages we're missing.

Triggered by EventBridge quarterly (1st of Jan/Apr/Jul/Oct at 3:00 AM UTC).

This is the PyPI counterpart of npmsio_audit.py, addressing the same
"bootstrap gap" for the Python ecosystem. Uses hugovk's top-pypi-packages
dataset (monthly dump of 15,000 most-downloaded PyPI packages sourced from
ClickHouse/BigQuery), which is free, reliable, and requires no auth.

Source: https://hugovk.github.io/top-pypi-packages/
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import boto3
import httpx

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
MIN_DOWNLOADS = 10000  # Only add packages with 10K+ monthly (30-day) downloads
MAX_PACKAGES = 8000


def normalize_pypi_name(name: str) -> str:
    """Normalize PyPI package name per PEP 503."""
    name = name.lower()
    name = re.sub(r"[-_.]+", "-", name)
    return name


def handler(event, context):
    """Audit coverage against top PyPI packages."""
    table = dynamodb.Table(PACKAGES_TABLE)

    top_packages = fetch_top_pypi_packages()
    logger.info(f"Fetched {len(top_packages)} packages from top-pypi-packages")

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

        try:
            response = table.get_item(
                Key={"pk": f"pypi#{name}", "sk": "LATEST"},
                ProjectionExpression="pk",
            )
            if "Item" not in response:
                missing.append(pkg)
        except Exception as e:
            logger.warning(f"Error checking {name}: {e}")

    logger.info(f"Found {len(missing)} missing packages")

    # Add missing packages above download threshold
    added = 0
    queued = 0
    now = datetime.now(timezone.utc).isoformat()

    for pkg in missing:
        name = pkg.get("name")
        downloads = pkg.get("download_count", 0)

        if downloads < MIN_DOWNLOADS:
            continue

        try:
            table.put_item(
                Item={
                    "pk": f"pypi#{name}",
                    "sk": "LATEST",
                    "name": name,
                    "ecosystem": "pypi",
                    "tier": 3,
                    "source": "pypi_audit",
                    "created_at": now,
                    "last_updated": now,
                    "data_status": "pending",
                    "next_retry_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "retry_count": 0,
                    "weekly_downloads": int(downloads // 4),
                },
                ConditionExpression="attribute_not_exists(pk)",
            )
            added += 1

            if PACKAGE_QUEUE_URL:
                sqs.send_message(
                    QueueUrl=PACKAGE_QUEUE_URL,
                    MessageBody=json.dumps(
                        {
                            "ecosystem": "pypi",
                            "name": name,
                            "tier": 3,
                            "reason": "pypi_audit",
                        }
                    ),
                )
                queued += 1

        except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            pass
        except Exception as e:
            logger.error(f"Failed to add {name}: {e}")

    # Emit metrics
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "PypiAuditTotal", "value": len(top_packages)},
                {"metric_name": "PypiAuditMissing", "value": len(missing)},
                {"metric_name": "PypiAuditAdded", "value": added},
            ]
        )
    except ImportError:
        pass

    logger.info(f"Added {added} packages from PyPI audit")

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


def fetch_top_pypi_packages() -> list[dict]:
    """
    Fetch top PyPI packages from hugovk's top-pypi-packages dataset.

    Returns list of dicts with 'name' (normalized) and 'download_count' (30-day).
    """
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.get(TOP_PYPI_URL)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"top-pypi-packages HTTP error: {e}")
        return []
    except Exception as e:
        logger.error(f"Error fetching top-pypi-packages: {e}")
        return []

    rows = data.get("rows", [])
    packages = []

    for row in rows[:MAX_PACKAGES]:
        project = row.get("project")
        if not project:
            continue

        name = normalize_pypi_name(project)
        download_count = row.get("download_count", 0)

        packages.append(
            {
                "name": name,
                "download_count": download_count,
            }
        )

    return packages
