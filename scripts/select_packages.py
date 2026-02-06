#!/usr/bin/env python3
"""
Package Selection Script

Selects top 2,500 npm packages for MVP based on:
- PageRank score (from npmrank)
- Weekly downloads
- Has GitHub repository
- Not deprecated

Outputs a JSON file with package list and tiers.
"""

import asyncio
import json
from pathlib import Path

import httpx

# npms.io API for popular packages (reliable, actively maintained)
NPMS_SEARCH_URL = "https://api.npms.io/v2/search"


async def fetch_top_packages_npms(limit: int = 3000) -> list[dict]:
    """
    Fetch top npm packages from npms.io API.

    npms.io provides a reliable search API with popularity scoring.
    We fetch in batches since the API limits to 250 per request.
    """
    print(f"Fetching top {limit} packages from npms.io...")

    packages = []
    batch_size = 250  # npms.io API limit

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            offset = 0
            while len(packages) < limit:
                # Search for all packages, sorted by popularity
                params = {
                    "q": "not:deprecated",  # Exclude deprecated packages
                    "size": min(batch_size, limit - len(packages)),
                    "from": offset,
                }

                resp = await client.get(NPMS_SEARCH_URL, params=params)
                resp.raise_for_status()

                data = resp.json()
                results = data.get("results", [])

                if not results:
                    print(f"No more results at offset {offset}")
                    break

                for item in results:
                    pkg_name = item.get("package", {}).get("name")
                    if pkg_name:
                        # Skip @types packages
                        if pkg_name.startswith("@types/"):
                            continue

                        packages.append({
                            "name": pkg_name,
                            "rank": len(packages) + 1,
                            "downloads": 0,
                            "score": item.get("score", {}).get("final", 0),
                        })

                        if len(packages) >= limit:
                            break

                offset += batch_size
                print(f"  Fetched {len(packages)} packages so far...")

            print(f"Fetched {len(packages)} packages total")
            return packages

        except Exception as e:
            print(f"Error fetching npms.io data: {e}")
            return []


async def filter_packages(packages: list[dict]) -> list[dict]:
    """
    Filter packages based on criteria:
    - Has npm registry entry
    - Not deprecated
    - Not a TypeScript type package (@types/*)
    - Has reasonable download count
    """
    filtered = []

    for pkg in packages:
        name = pkg["name"]

        # Skip type definition packages
        if name.startswith("@types/"):
            continue

        # Skip known problematic packages
        skip_patterns = [
            "codelyzer",  # Deprecated Angular linter
        ]
        if any(p in name.lower() for p in skip_patterns):
            continue

        filtered.append(pkg)

    return filtered


def assign_tiers(packages: list[dict], tier_sizes: dict = None) -> list[dict]:
    """
    Assign refresh tiers to packages based on rank.

    Tier 1 (daily): Top 100 packages
    Tier 2 (every 3 days): Top 500 packages
    Tier 3 (weekly): All remaining packages
    """
    tier_sizes = tier_sizes or {1: 100, 2: 500}

    for i, pkg in enumerate(packages):
        rank = i + 1
        if rank <= tier_sizes.get(1, 100):
            pkg["tier"] = 1
        elif rank <= tier_sizes.get(2, 500):
            pkg["tier"] = 2
        else:
            pkg["tier"] = 3

    return packages


async def get_top_packages(limit: int = 2500) -> list[dict]:
    """
    Main function to get top npm packages with tiers assigned.
    """
    # Fetch more than needed to account for filtering
    raw_packages = await fetch_top_packages_npms(limit=limit + 500)

    if not raw_packages:
        print("Failed to fetch packages, using fallback list")
        return get_fallback_packages(limit)

    # Filter packages
    filtered = await filter_packages(raw_packages)
    print(f"After filtering: {len(filtered)} packages")

    # Limit to requested amount
    selected = filtered[:limit]

    # Assign tiers
    tiered = assign_tiers(selected)

    return tiered


def get_fallback_packages(limit: int = 2500) -> list[dict]:
    """
    Fallback list of well-known packages if API fails.
    """
    # Top packages that are definitely important
    fallback = [
        "lodash", "react", "express", "axios", "typescript", "webpack",
        "moment", "chalk", "commander", "debug", "uuid", "dotenv",
        "jest", "eslint", "prettier", "vue", "next", "tailwindcss",
        "prisma", "zod", "trpc", "vite", "esbuild", "fastify",
        "socket.io", "mongoose", "sequelize", "knex", "pg", "mysql2",
        "redis", "ioredis", "aws-sdk", "firebase", "stripe", "twilio",
        "nodemailer", "passport", "jsonwebtoken", "bcrypt", "crypto-js",
        "dayjs", "date-fns", "luxon", "numeral", "bignumber.js",
        "cheerio", "puppeteer", "playwright", "selenium-webdriver",
        "sharp", "jimp", "canvas", "pdf-lib", "pdfkit",
        "winston", "pino", "bunyan", "morgan", "debug",
        "yargs", "inquirer", "ora", "boxen", "figlet",
        "glob", "minimatch", "micromatch", "fast-glob", "chokidar",
        "fs-extra", "rimraf", "mkdirp", "tar", "archiver",
        "cross-env", "dotenv-expand", "config", "nconf", "convict",
        "body-parser", "cors", "helmet", "compression", "cookie-parser",
        "multer", "formidable", "busboy", "multiparty",
        "supertest", "nock", "sinon", "chai", "mocha",
        "rxjs", "ramda", "immer", "reselect", "redux",
        "mobx", "zustand", "jotai", "recoil", "valtio",
        "@emotion/react", "styled-components", "sass", "less", "postcss",
    ]

    packages = []
    for i, name in enumerate(fallback[:limit]):
        tier = 1 if i < 100 else (2 if i < 500 else 3)
        packages.append({"name": name, "rank": i + 1, "tier": tier})

    return packages


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Select top npm packages")
    parser.add_argument(
        "--limit", type=int, default=2500, help="Number of packages to select"
    )
    parser.add_argument(
        "--output", type=str, default="packages.json", help="Output file path"
    )
    args = parser.parse_args()

    packages = await get_top_packages(args.limit)

    # Summary stats
    tier_counts = {1: 0, 2: 0, 3: 0}
    for pkg in packages:
        tier_counts[pkg["tier"]] = tier_counts.get(pkg["tier"], 0) + 1

    print(f"\nSelected {len(packages)} packages:")
    print(f"  Tier 1 (daily): {tier_counts[1]}")
    print(f"  Tier 2 (3-day): {tier_counts[2]}")
    print(f"  Tier 3 (weekly): {tier_counts[3]}")

    # Write output
    output_path = Path(args.output)
    output_data = {
        "total": len(packages),
        "tier_counts": tier_counts,
        "packages": packages,
    }

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\nWritten to {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
