#!/usr/bin/env python3
"""Migrate data from dephealth-* tables to pkgwatch-* tables."""

import boto3
from decimal import Decimal
import json
import sys

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

def migrate_table(source_table_name: str, dest_table_name: str):
    """Migrate all items from source to destination table."""
    source = dynamodb.Table(source_table_name)
    dest = dynamodb.Table(dest_table_name)

    print(f"Migrating {source_table_name} -> {dest_table_name}")

    # Scan source table
    items = []
    response = source.scan()
    items.extend(response.get('Items', []))

    while 'LastEvaluatedKey' in response:
        response = source.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        items.extend(response.get('Items', []))

    print(f"  Found {len(items)} items to migrate")

    if not items:
        print("  No items to migrate")
        return

    # Batch write to destination
    with dest.batch_writer() as batch:
        for i, item in enumerate(items):
            batch.put_item(Item=item)
            if (i + 1) % 100 == 0:
                print(f"  Migrated {i + 1}/{len(items)} items...")

    print(f"  Completed: {len(items)} items migrated")

def main():
    # Migrate packages table
    migrate_table('dephealth-packages', 'pkgwatch-packages')

    # Migrate api-keys table
    migrate_table('dephealth-api-keys', 'pkgwatch-api-keys')

    print("\nMigration complete!")

if __name__ == '__main__':
    main()
