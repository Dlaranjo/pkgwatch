"""
Seed Packages - Admin Lambda to populate the database with top packages.

Fetches top packages from npm and PyPI, inserts them into DynamoDB,
and optionally triggers the collection pipeline.

Event format:
{
    "npm_count": 5000,      # Number of npm packages to seed (default: 5000)
    "pypi_count": 5000,     # Number of PyPI packages to seed (default: 5000)
    "trigger_collection": true,  # Whether to trigger refresh after seeding
    "dry_run": false        # If true, just report what would be done
}
"""

import json
import logging
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
REFRESH_DISPATCHER_ARN = os.environ.get("REFRESH_DISPATCHER_ARN", "")

# Tier thresholds (by rank within ecosystem)
TIER_1_MAX = 100  # Top 100 = daily refresh
TIER_2_MAX = 500  # 101-500 = every 3 days
# 501+ = tier 3 = weekly

# Data sources
NPM_TOP_PACKAGES_URL = "https://raw.githubusercontent.com/pnpm/awesome-pnpm/main/badge/top-packages.json"
PYPI_TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

# Fallback: npm popular packages (curated list of most depended-on packages)
NPM_REGISTRY_SEARCH_URL = "https://registry.npmjs.org/-/v1/search?text=boost-exact:true&popularity=1.0&size=250"


def get_tier(rank: int) -> int:
    """Assign tier based on package rank within its ecosystem."""
    if rank <= TIER_1_MAX:
        return 1
    elif rank <= TIER_2_MAX:
        return 2
    return 3


def fetch_json(url: str, timeout: int = 30) -> Any:
    """Fetch JSON from URL with timeout."""
    req = urllib.request.Request(url, headers={"User-Agent": "PkgWatch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error fetching {url}: {e.code} {e.reason}")
        raise
    except urllib.error.URLError as e:
        logger.error(f"URL error fetching {url}: {e.reason}")
        raise


def fetch_top_npm_packages(count: int) -> list[dict]:
    """
    Fetch top npm packages.

    Uses npm registry search API with common keywords to find popular packages.
    Returns list of {name, rank} dicts.
    """
    packages = []
    seen = set()

    # Use common framework/library keywords to find popular packages
    # These cover most of the npm ecosystem
    search_terms = [
        "react",
        "vue",
        "angular",
        "express",
        "webpack",
        "babel",
        "typescript",
        "eslint",
        "jest",
        "lodash",
        "axios",
        "moment",
        "redux",
        "graphql",
        "apollo",
        "next",
        "gatsby",
        "nuxt",
        "node",
        "npm",
        "yarn",
        "gulp",
        "grunt",
        "rollup",
        "vite",
        "socket",
        "mongoose",
        "sequelize",
        "prisma",
        "knex",
        "aws",
        "google",
        "azure",
        "firebase",
        "supabase",
        "test",
        "mock",
        "faker",
        "chai",
        "mocha",
        "jasmine",
        "crypto",
        "bcrypt",
        "jwt",
        "passport",
        "auth",
        "http",
        "https",
        "fetch",
        "request",
        "got",
        "fs",
        "path",
        "stream",
        "buffer",
        "util",
        "cli",
        "commander",
        "yargs",
        "inquirer",
        "chalk",
        "date",
        "time",
        "uuid",
        "nanoid",
        "shortid",
        "json",
        "yaml",
        "xml",
        "csv",
        "markdown",
        "image",
        "sharp",
        "canvas",
        "pdf",
        "excel",
        "email",
        "nodemailer",
        "sendgrid",
        "mailgun",
        "cache",
        "redis",
        "memcached",
        "lru",
        "queue",
        "bull",
        "bee",
        "agenda",
        "log",
        "winston",
        "bunyan",
        "pino",
        "debug",
        "config",
        "dotenv",
        "convict",
        "nconf",
        "validation",
        "joi",
        "yup",
        "zod",
        "ajv",
        "orm",
        "database",
        "sql",
        "postgres",
        "mysql",
        "sqlite",
        "mongo",
        "api",
        "rest",
        "swagger",
        "openapi",
        "ui",
        "component",
        "button",
        "form",
        "table",
        "modal",
        "style",
        "css",
        "sass",
        "less",
        "styled",
        "tailwind",
        "bootstrap",
        "animation",
        "transition",
        "motion",
        "framer",
        "chart",
        "graph",
        "d3",
        "echarts",
        "highcharts",
        "map",
        "leaflet",
        "mapbox",
        "google-maps",
        "video",
        "audio",
        "media",
        "player",
        "build",
        "bundle",
        "compile",
        "transpile",
        "minify",
        "lint",
        "format",
        "prettier",
        "standard",
        "type",
        "types",
        "typing",
        "interface",
        "async",
        "promise",
        "observable",
        "rxjs",
        "state",
        "store",
        "flux",
        "mobx",
        "recoil",
        "router",
        "route",
        "navigation",
        "history",
        "server",
        "client",
        "ssr",
        "ssg",
        "spa",
        "plugin",
        "extension",
        "addon",
        "middleware",
        "util",
        "helper",
        "tool",
        "kit",
        "core",
        "common",
        "shared",
    ]

    page_size = 250

    for term in search_terms:
        if len(packages) >= count:
            break

        offset = 0
        # Limit pages per term to avoid getting stuck
        max_pages_per_term = 4

        while len(packages) < count and offset < max_pages_per_term * page_size:
            url = f"https://registry.npmjs.org/-/v1/search?text={term}&size={page_size}&from={offset}&popularity=1.0"

            try:
                data = fetch_json(url)
                objects = data.get("objects", [])

                if not objects:
                    break

                added_this_page = 0
                for obj in objects:
                    pkg_name = obj.get("package", {}).get("name")
                    if pkg_name and pkg_name not in seen and len(packages) < count:
                        score = obj.get("score", {}).get("final", 0)
                        packages.append(
                            {
                                "name": pkg_name,
                                "rank": len(packages) + 1,
                                "score": score,
                            }
                        )
                        seen.add(pkg_name)
                        added_this_page += 1

                # If no new packages were added, move to next term
                if added_this_page == 0:
                    break

                offset += page_size

            except Exception as e:
                logger.warning(f"Error fetching npm packages for term '{term}' at offset {offset}: {e}")
                break

        if len(packages) % 500 == 0 or len(packages) >= count:
            logger.info(f"Fetched {len(packages)} npm packages so far...")

    # Sort by score and re-assign ranks for better tier distribution
    packages.sort(key=lambda x: x.get("score", 0), reverse=True)
    for i, pkg in enumerate(packages):
        pkg["rank"] = i + 1

    logger.info(f"Total npm packages fetched: {len(packages)}")
    return packages[:count]


def fetch_top_pypi_packages(count: int) -> list[dict]:
    """
    Fetch top PyPI packages from hugovk's maintained list.

    Source: https://hugovk.github.io/top-pypi-packages/
    Updated monthly, contains top 8000 packages by downloads.
    """
    packages = []

    try:
        data = fetch_json(PYPI_TOP_PACKAGES_URL)
        rows = data.get("rows", [])

        for i, row in enumerate(rows[:count]):
            pkg_name = row.get("project")
            if pkg_name:
                packages.append(
                    {
                        "name": pkg_name,
                        "rank": i + 1,
                    }
                )

        logger.info(f"Total PyPI packages fetched: {len(packages)}")

    except Exception as e:
        logger.error(f"Error fetching PyPI packages: {e}")

    return packages


def batch_write_packages(
    table_name: str,
    packages: list[dict],
    ecosystem: str,
) -> tuple[int, int]:
    """
    Batch write packages to DynamoDB.

    Uses batch_write_item with 25 items per batch (DynamoDB limit).
    Returns (success_count, error_count).
    """
    table = dynamodb.Table(table_name)
    success_count = 0
    error_count = 0

    now = datetime.now(timezone.utc).isoformat()

    # Process in batches of 25 (DynamoDB limit)
    batch_size = 25

    for i in range(0, len(packages), batch_size):
        batch = packages[i : i + batch_size]

        try:
            with table.batch_writer() as writer:
                for pkg in batch:
                    tier = get_tier(pkg["rank"])

                    item = {
                        "pk": f"{ecosystem}#{pkg['name']}",
                        "sk": "LATEST",
                        "ecosystem": ecosystem,
                        "name": pkg["name"],
                        "tier": tier,
                        "seeded_at": now,
                        "seeded_rank": pkg["rank"],
                        # Mark as needing collection
                        "needs_collection": True,
                        # Initial data quality state - ensures retry system can find this package
                        "data_status": "pending",
                        # Not queryable until data is collected and scored
                        "queryable": False,
                    }

                    writer.put_item(Item=item)

            success_count += len(batch)

        except Exception as e:
            logger.error(f"Error writing batch at index {i}: {e}")
            error_count += len(batch)

    return success_count, error_count


def trigger_refresh_dispatcher(tier: int) -> dict:
    """Invoke the refresh dispatcher Lambda to start collection."""
    if not REFRESH_DISPATCHER_ARN:
        logger.warning("REFRESH_DISPATCHER_ARN not configured, skipping trigger")
        return {"skipped": True, "reason": "ARN not configured"}

    try:
        response = lambda_client.invoke(
            FunctionName=REFRESH_DISPATCHER_ARN,
            InvocationType="Event",  # Async invocation
            Payload=json.dumps(
                {
                    "tier": tier,
                    "reason": "seed_packages",
                }
            ),
        )

        return {
            "status_code": response.get("StatusCode"),
            "tier": tier,
        }

    except Exception as e:
        logger.error(f"Error triggering refresh dispatcher for tier {tier}: {e}")
        return {"error": str(e), "tier": tier}


def handler(event, context):
    """
    Lambda handler for seeding packages.
    """
    npm_count = event.get("npm_count", 5000)
    pypi_count = event.get("pypi_count", 5000)
    trigger_collection = event.get("trigger_collection", True)
    dry_run = event.get("dry_run", False)

    logger.info(f"Starting package seeding: npm={npm_count}, pypi={pypi_count}, dry_run={dry_run}")

    results = {
        "npm": {"requested": npm_count, "fetched": 0, "inserted": 0, "errors": 0},
        "pypi": {"requested": pypi_count, "fetched": 0, "inserted": 0, "errors": 0},
        "dry_run": dry_run,
        "trigger_results": [],
    }

    # Fetch packages in parallel
    npm_packages = []
    pypi_packages = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}

        if npm_count > 0:
            futures[executor.submit(fetch_top_npm_packages, npm_count)] = "npm"

        if pypi_count > 0:
            futures[executor.submit(fetch_top_pypi_packages, pypi_count)] = "pypi"

        for future in as_completed(futures):
            ecosystem = futures[future]
            try:
                packages = future.result()
                if ecosystem == "npm":
                    npm_packages = packages
                    results["npm"]["fetched"] = len(packages)
                else:
                    pypi_packages = packages
                    results["pypi"]["fetched"] = len(packages)
            except Exception as e:
                logger.error(f"Error fetching {ecosystem} packages: {e}")

    if dry_run:
        # Report what would be done without actually doing it
        results["message"] = "Dry run - no packages inserted"

        # Sample packages for each tier
        for ecosystem, packages in [("npm", npm_packages), ("pypi", pypi_packages)]:
            tier_counts = {1: 0, 2: 0, 3: 0}
            for pkg in packages:
                tier = get_tier(pkg["rank"])
                tier_counts[tier] += 1
            results[ecosystem]["tier_distribution"] = tier_counts
            results[ecosystem]["sample_tier1"] = [p["name"] for p in packages[:5]]
            results[ecosystem]["sample_tier3"] = [p["name"] for p in packages[-5:]]

        return {
            "statusCode": 200,
            "body": json.dumps(results, indent=2),
        }

    # Insert packages into DynamoDB
    if npm_packages:
        success, errors = batch_write_packages(PACKAGES_TABLE, npm_packages, "npm")
        results["npm"]["inserted"] = success
        results["npm"]["errors"] = errors
        logger.info(f"Inserted {success} npm packages, {errors} errors")

    if pypi_packages:
        success, errors = batch_write_packages(PACKAGES_TABLE, pypi_packages, "pypi")
        results["pypi"]["inserted"] = success
        results["pypi"]["errors"] = errors
        logger.info(f"Inserted {success} pypi packages, {errors} errors")

    # Trigger collection pipeline
    if trigger_collection:
        logger.info("Triggering refresh dispatcher for all tiers...")

        # Trigger each tier (they run async)
        for tier in [3, 2, 1]:  # Start with tier 3 (largest), end with tier 1
            result = trigger_refresh_dispatcher(tier)
            results["trigger_results"].append(result)

    # Summary
    total_inserted = results["npm"]["inserted"] + results["pypi"]["inserted"]
    total_errors = results["npm"]["errors"] + results["pypi"]["errors"]

    results["summary"] = {
        "total_inserted": total_inserted,
        "total_errors": total_errors,
        "collection_triggered": trigger_collection,
    }

    logger.info(f"Seeding complete: {total_inserted} packages inserted, {total_errors} errors")

    return {
        "statusCode": 200,
        "body": json.dumps(results, indent=2),
    }
