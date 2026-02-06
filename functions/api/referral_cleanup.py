"""
Referral Cleanup - Scheduled Lambda (daily at 2:00 AM UTC)

Cleans up stale pending referrals that never reached the activity threshold
(100 packages scanned) within the 90-day timeout window.
"""

import logging
import os
from datetime import datetime, timezone

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from shared.aws_clients import get_dynamodb
from shared.referral_utils import update_referrer_stats

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for daily cleanup of stale pending referrals.

    Scans for USER_META records where:
    - referral_pending = True
    - referral_pending_expires < now

    For each matching record:
    1. Clear the referral_pending flag
    2. Decrement referrer's pending_count
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    processed = 0
    cleaned = 0
    errors = 0

    try:
        # Scan for expired pending referrals
        # Note: This is a scan which is not ideal, but:
        # - It runs once daily during low-traffic hours
        # - The filter reduces returned items significantly
        # - We paginate to avoid Lambda timeouts
        scan_kwargs = {
            "FilterExpression": (
                Attr("sk").eq("USER_META")
                & Attr("referral_pending").eq(True)
                & Attr("referral_pending_expires").lt(now_iso)
            ),
            "ProjectionExpression": "pk, referred_by, referral_pending_expires",
        }

        while True:
            response = table.scan(**scan_kwargs)
            items = response.get("Items", [])

            logger.info(f"Found {len(items)} expired pending referrals in this batch")

            for item in items:
                processed += 1
                user_id = item.get("pk")
                referrer_id = item.get("referred_by")
                expires = item.get("referral_pending_expires")

                try:
                    # Clear pending flag on the referred user
                    table.update_item(
                        Key={"pk": user_id, "sk": "USER_META"},
                        UpdateExpression="REMOVE referral_pending, referral_pending_expires",
                        ConditionExpression=Attr("referral_pending").eq(True),
                    )

                    # Decrement referrer's pending count
                    if referrer_id:
                        update_referrer_stats(referrer_id, pending_delta=-1)

                    logger.info(
                        f"Cleaned up stale pending referral: {user_id} (referrer: {referrer_id}, expired: {expires})"
                    )
                    cleaned += 1

                except ClientError as e:
                    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                        # Already cleaned up (race condition) - that's OK
                        logger.debug(f"Pending flag already cleared for {user_id}")
                    else:
                        logger.error(f"Error cleaning up {user_id}: {e}")
                        errors += 1

                except Exception as e:
                    logger.error(f"Error cleaning up {user_id}: {e}")
                    errors += 1

            # Check for more pages
            if "LastEvaluatedKey" not in response:
                break

            scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    except Exception as e:
        logger.error(f"Error in referral cleanup scan: {e}")
        return {"processed": 0, "cleaned": 0, "error": str(e)}

    logger.info(f"Referral cleanup complete: processed={processed}, cleaned={cleaned}, errors={errors}")

    return {
        "processed": processed,
        "cleaned": cleaned,
        "errors": errors,
    }
