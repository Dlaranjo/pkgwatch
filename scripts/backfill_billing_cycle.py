#!/usr/bin/env python3
"""
Backfill billing cycle data for legacy users.

Scans all users with stripe_subscription_id, fetches their subscription from Stripe,
and updates current_period_end in both API key records and USER_META.

This is a one-time migration script for users who subscribed before billing cycle
tracking was fully implemented.

Usage:
    # Dry run (shows what would be updated)
    python scripts/backfill_billing_cycle.py --dry-run

    # Actually perform updates
    python scripts/backfill_billing_cycle.py
"""

import argparse
import json
import os
import sys
import time

import boto3
import stripe

# Add functions directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions"))

dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")
table = dynamodb.Table(os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys"))

# Rate limiting for Stripe API (25 req/sec is safe)
STRIPE_REQUESTS_PER_SECOND = 10
STRIPE_REQUEST_INTERVAL = 1.0 / STRIPE_REQUESTS_PER_SECOND


def get_stripe_api_key() -> str:
    """Retrieve Stripe API key from Secrets Manager or environment."""
    # First try environment variable (for local testing)
    api_key = os.environ.get("STRIPE_API_KEY")
    if api_key:
        return api_key

    # Try Secrets Manager
    secret_name = os.environ.get("STRIPE_SECRET_ARN", "pkgwatch/stripe-secret")
    try:
        response = secretsmanager.get_secret_value(SecretId=secret_name)
        secret_value = response.get("SecretString", "")
        try:
            secret_json = json.loads(secret_value)
            return secret_json.get("key") or secret_value
        except json.JSONDecodeError:
            return secret_value
    except Exception as e:
        print(f"Error retrieving Stripe API key: {e}")
        print("Set STRIPE_API_KEY environment variable or ensure AWS credentials are configured.")
        sys.exit(1)


def scan_users_with_subscription():
    """Scan for users who have a Stripe subscription but may be missing billing cycle data."""
    print("Scanning for users with stripe_subscription_id...")

    users = []
    scan_kwargs = {
        "FilterExpression": (
            "attribute_exists(stripe_subscription_id) AND "
            "sk <> :pending AND "
            "sk <> :meta AND "
            "NOT begins_with(pk, :system)"
        ),
        "ExpressionAttributeValues": {
            ":pending": "PENDING",
            ":meta": "USER_META",
            ":system": "SYSTEM#",
        },
        "ProjectionExpression": (
            "pk, sk, stripe_subscription_id, stripe_customer_id, "
            "tier, current_period_end, current_period_start, email"
        ),
    }

    while True:
        response = table.scan(**scan_kwargs)
        users.extend(response.get("Items", []))

        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        print(f"  Scanned {len(users)} records so far...")

    return users


def group_by_subscription(users):
    """Group API key records by subscription ID to deduplicate Stripe calls."""
    subscriptions = {}
    for user in users:
        sub_id = user.get("stripe_subscription_id")
        if sub_id:
            if sub_id not in subscriptions:
                subscriptions[sub_id] = {
                    "subscription_id": sub_id,
                    "customer_id": user.get("stripe_customer_id"),
                    "records": [],
                    "has_period_end": False,
                }
            subscriptions[sub_id]["records"].append(user)
            # Check if any record already has current_period_end
            if user.get("current_period_end"):
                subscriptions[sub_id]["has_period_end"] = True

    return subscriptions


def fetch_subscription_from_stripe(subscription_id):
    """Fetch subscription details from Stripe API."""
    try:
        return stripe.Subscription.retrieve(subscription_id)
    except stripe.error.InvalidRequestError:
        # Subscription doesn't exist (cancelled and deleted)
        return None
    except stripe.error.StripeError as e:
        print(f"  Stripe error fetching subscription {subscription_id}: {e}")
        return None


def update_records(records, period_start, period_end, dry_run=False):
    """Update API key records with billing cycle data."""
    updated = 0
    user_id = records[0]["pk"] if records else None

    for record in records:
        if dry_run:
            print(f"    Would update {record['pk']}/{record['sk']}")
            updated += 1
            continue

        try:
            table.update_item(
                Key={"pk": record["pk"], "sk": record["sk"]},
                UpdateExpression=(
                    "SET current_period_start = :start, "
                    "current_period_end = :end"
                ),
                ExpressionAttributeValues={
                    ":start": period_start,
                    ":end": period_end,
                },
            )
            updated += 1
        except Exception as e:
            print(f"    Error updating {record['pk']}/{record['sk']}: {e}")

    # Also update USER_META if exists
    if user_id and not dry_run:
        try:
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression=(
                    "SET current_period_end = :end"
                ),
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues={
                    ":end": period_end,
                },
            )
        except Exception as e:
            if "ConditionalCheckFailedException" not in str(e):
                print(f"    Error updating USER_META for {user_id}: {e}")

    return updated


def main():
    parser = argparse.ArgumentParser(description="Backfill billing cycle data for legacy users")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be updated without making changes")
    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN MODE - No changes will be made ===\n")

    # Initialize Stripe
    stripe.api_key = get_stripe_api_key()
    print(f"Stripe API initialized (key ending in ...{stripe.api_key[-4:]})\n")

    # Scan for users
    users = scan_users_with_subscription()
    print(f"\nFound {len(users)} API key records with subscription IDs")

    # Group by subscription
    subscriptions = group_by_subscription(users)
    print(f"Found {len(subscriptions)} unique subscriptions")

    # Identify subscriptions missing billing data
    needs_backfill = {
        sub_id: data for sub_id, data in subscriptions.items()
        if not data["has_period_end"]
    }
    already_complete = len(subscriptions) - len(needs_backfill)

    print(f"\n  Already have billing data: {already_complete}")
    print(f"  Need backfill: {len(needs_backfill)}")

    if not needs_backfill:
        print("\nNo backfill needed! All users have billing cycle data.")
        return

    # Show sample
    print("\nSample subscriptions needing backfill:")
    for i, (sub_id, data) in enumerate(list(needs_backfill.items())[:5]):
        email = data["records"][0].get("email", "unknown")
        tier = data["records"][0].get("tier", "unknown")
        print(f"  {sub_id[:20]}... - {email} ({tier})")

    # Confirm
    if not args.dry_run:
        confirm = input(f"\nBackfill {len(needs_backfill)} subscriptions? [y/N]: ")
        if confirm.lower() != "y":
            print("Aborted.")
            return

    # Process subscriptions
    print(f"\nProcessing {len(needs_backfill)} subscriptions...")

    updated_count = 0
    skipped_count = 0
    error_count = 0
    last_request_time = 0

    for i, (sub_id, data) in enumerate(needs_backfill.items()):
        # Rate limiting
        elapsed = time.time() - last_request_time
        if elapsed < STRIPE_REQUEST_INTERVAL:
            time.sleep(STRIPE_REQUEST_INTERVAL - elapsed)

        # Fetch from Stripe
        last_request_time = time.time()
        try:
            subscription = fetch_subscription_from_stripe(sub_id)
        except Exception as e:
            print(f"  [{i+1}/{len(needs_backfill)}] {sub_id[:20]}... - unexpected error: {e}")
            error_count += 1
            continue

        if not subscription:
            print(f"  [{i+1}/{len(needs_backfill)}] {sub_id[:20]}... - subscription not found, skipping")
            skipped_count += 1
            continue

        period_start = subscription.get("current_period_start")
        period_end = subscription.get("current_period_end")
        status = subscription.get("status")

        if status not in ["active", "trialing"]:
            print(f"  [{i+1}/{len(needs_backfill)}] {sub_id[:20]}... - status={status}, skipping")
            skipped_count += 1
            continue

        # Update records
        try:
            num_updated = update_records(data["records"], period_start, period_end, args.dry_run)
            updated_count += num_updated

            email = data["records"][0].get("email", "unknown")[:30]
            print(f"  [{i+1}/{len(needs_backfill)}] {sub_id[:20]}... - updated {num_updated} records ({email})")
        except Exception as e:
            print(f"  [{i+1}/{len(needs_backfill)}] {sub_id[:20]}... - error updating records: {e}")
            error_count += 1

    # Summary
    print(f"\n{'=== DRY RUN SUMMARY ===' if args.dry_run else '=== SUMMARY ==='}")
    print(f"  Total subscriptions processed: {len(needs_backfill)}")
    print(f"  Records {'would be ' if args.dry_run else ''}updated: {updated_count}")
    print(f"  Subscriptions skipped: {skipped_count}")
    if error_count:
        print(f"  Errors: {error_count}")


if __name__ == "__main__":
    main()
