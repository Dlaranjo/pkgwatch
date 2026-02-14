import * as core from "@actions/core";
import { ScanResult, PackageHealth, RepoScanResult, ManifestScanResult } from "./api";

// Version is injected at build time via esbuild --define
declare const __VERSION__: string;
const VERSION = typeof __VERSION__ !== "undefined" ? __VERSION__ : "1.0.0";

const GITHUB_REPO = "https://github.com/Dlaranjo/pkgwatch";

export async function generateSummary(
  result: ScanResult,
  failed: boolean,
  threshold: string
): Promise<void> {
  const summary = core.summary;

  const hasIssues = result.critical > 0 || result.high > 0;

  // Pass/fail banner
  if (failed) {
    summary.addRaw(
      `> [!CAUTION]\n> **Policy Violation**: Packages exceed ${threshold} threshold\n\n`
    );
  } else if (threshold) {
    summary.addRaw(
      `> [!TIP]\n> **Scan Passed**: No packages exceed ${threshold} threshold\n\n`
    );
  } else if (hasIssues) {
    // No threshold set, but there are issues to flag
    summary.addRaw(
      `> [!WARNING]\n> **Attention**: Found ${result.critical + result.high} packages with CRITICAL or HIGH risk\n\n`
    );
  } else {
    // No threshold, no issues - healthy dependencies
    summary.addRaw(
      `> [!TIP]\n> **Healthy**: All dependencies have acceptable health scores\n\n`
    );
  }

  summary.addHeading("PkgWatch Scan Results", 2);
  summary.addRaw(`\nScanned **${result.total}** packages\n\n`);

  // Summary counts
  const counts = [
    result.critical > 0 ? `**${result.critical} Critical**` : null,
    result.high > 0 ? `**${result.high} High**` : null,
    result.medium > 0 ? `${result.medium} Medium` : null,
    result.low > 0 ? `${result.low} Low` : null,
  ]
    .filter(Boolean)
    .join(" | ");

  if (counts) {
    summary.addRaw(counts + "\n\n");
  }

  // Table for HIGH and CRITICAL packages
  const riskPackages = result.packages.filter(
    (p) => p.risk_level === "CRITICAL" || p.risk_level === "HIGH"
  );

  if (riskPackages.length > 0) {
    summary.addHeading("Packages Requiring Attention", 3);
    summary.addTable([
      [
        { data: "Package", header: true },
        { data: "Risk", header: true },
        { data: "Score", header: true },
        { data: "Data", header: true },
        { data: "Key Issue", header: true },
      ],
      ...riskPackages.map((pkg) => {
        const isUnverified = !pkg.data_quality || pkg.data_quality.assessment !== "VERIFIED";
        const dataStatus = isUnverified ? "⚠️" : "✓";
        return [
          `<code>${escapeHtml(pkg.package)}</code>`,
          pkg.risk_level,
          `${pkg.health_score}/100`,
          dataStatus,
          escapeHtml(pkg.abandonment_risk?.risk_factors?.[0] || "-"),
        ];
      }),
    ]);
  }

  // Data quality note
  const unverifiedRisk = result.unverified_risk_count || 0;
  if (unverifiedRisk > 0) {
    summary.addRaw("\n> [!NOTE]\n");
    summary.addRaw(`> **${unverifiedRisk} package(s) have incomplete data** (marked ⚠️). `);
    summary.addRaw("Risk levels may be inaccurate due to missing repository information.\n\n");
  }

  // All packages in collapsible
  if (result.packages.length > 0) {
    const allTable = result.packages
      .sort((a, b) => (a.health_score ?? -1) - (b.health_score ?? -1))
      .map(
        (p) =>
          `| \`${escapeMarkdown(p.package)}\` | ${p.risk_level} | ${p.health_score}/100 |`
      )
      .join("\n");

    summary.addRaw("\n<details>\n<summary>View all packages</summary>\n\n");
    summary.addRaw("| Package | Risk | Score |\n|---------|------|-------|\n");
    summary.addRaw(allTable);
    summary.addRaw("\n\n</details>\n");
  }

  // Not found packages warning
  if (result.not_found && result.not_found.length > 0) {
    summary.addRaw("\n> [!NOTE]\n");
    summary.addRaw(`> **${result.not_found.length} package(s) not found**: `);
    summary.addRaw(result.not_found.map((p) => `\`${escapeMarkdown(p)}\``).join(", "));
    summary.addRaw("\n\n");
  }

  // Footer with contextual feedback links
  summary.addRaw("\n---\n");
  if (hasIssues) {
    summary.addRaw(
      `*[PkgWatch](https://pkgwatch.dev?utm_source=action&utm_medium=summary) v${VERSION}* | ` +
      `[Wrong score?](${GITHUB_REPO}/issues/new?template=bug_report.yml&labels=bug,action,false-positive) | ` +
      `[Feedback](${GITHUB_REPO}/discussions/new?category=feedback)\n`
    );
  } else {
    summary.addRaw(
      `*[PkgWatch](https://pkgwatch.dev?utm_source=action&utm_medium=summary) v${VERSION}*\n`
    );
  }

  await summary.write();
}

/**
 * Generate job summary for multi-manifest (recursive) scan
 */
export async function generateRepoSummary(
  result: RepoScanResult,
  failed: boolean,
  threshold: string
): Promise<void> {
  const summary = core.summary;
  const { manifests, summary: repoSummary } = result;

  const hasIssues = repoSummary.critical > 0 || repoSummary.high > 0;

  // Pass/fail banner
  if (failed) {
    summary.addRaw(
      `> [!CAUTION]\n> **Policy Violation**: Packages exceed ${threshold} threshold\n\n`
    );
  } else if (threshold) {
    summary.addRaw(
      `> [!TIP]\n> **Scan Passed**: No packages exceed ${threshold} threshold\n\n`
    );
  } else if (hasIssues) {
    summary.addRaw(
      `> [!WARNING]\n> **Attention**: Found ${repoSummary.critical + repoSummary.high} packages with CRITICAL or HIGH risk\n\n`
    );
  } else {
    summary.addRaw(
      `> [!TIP]\n> **Healthy**: All dependencies have acceptable health scores\n\n`
    );
  }

  // Warnings for truncation and rate limiting
  if (result.truncated) {
    summary.addRaw(
      `> [!WARNING]\n> **Truncated**: Maximum manifest limit reached. Some manifests were not scanned.\n\n`
    );
  }

  if (result.rateLimited) {
    summary.addRaw(
      `> [!WARNING]\n> **Rate Limited**: API quota reached during scan. Some results may be incomplete.\n\n`
    );
  }

  summary.addHeading("PkgWatch Repository Scan Results", 2);
  summary.addRaw(
    `\nScanned **${repoSummary.totalManifests}** manifest files with **${repoSummary.uniquePackages}** unique packages\n\n`
  );

  // Summary counts
  const counts = [
    repoSummary.critical > 0 ? `**${repoSummary.critical} Critical**` : null,
    repoSummary.high > 0 ? `**${repoSummary.high} High**` : null,
    repoSummary.medium > 0 ? `${repoSummary.medium} Medium` : null,
    repoSummary.low > 0 ? `${repoSummary.low} Low` : null,
  ]
    .filter(Boolean)
    .join(" | ");

  if (counts) {
    summary.addRaw(counts + "\n\n");
  }

  // Manifests overview table
  summary.addHeading("Manifests", 3);

  const manifestRows = manifests.map((m) => {
    const statusEmoji = getStatusEmoji(m.status);
    const ecosystem = m.manifest.ecosystem.toUpperCase();
    const countsStr = m.counts
      ? `${m.counts.critical}C / ${m.counts.high}H / ${m.counts.medium}M / ${m.counts.low}L`
      : m.error
        ? escapeHtml(m.error.slice(0, 50))
        : "-";

    return [
      `${statusEmoji} <code>${escapeHtml(m.manifest.relativePath)}</code>`,
      ecosystem,
      countsStr,
    ];
  });

  summary.addTable([
    [
      { data: "Manifest", header: true },
      { data: "Ecosystem", header: true },
      { data: "Results (C/H/M/L)", header: true },
    ],
    ...manifestRows,
  ]);

  // Collect all high-risk packages across manifests
  const allRiskPackages: Array<{ pkg: PackageHealth; manifest: string }> = [];
  for (const m of manifests) {
    if (m.status === "success" && m.packages) {
      for (const pkg of m.packages) {
        if (pkg.risk_level === "CRITICAL" || pkg.risk_level === "HIGH") {
          allRiskPackages.push({ pkg, manifest: m.manifest.relativePath });
        }
      }
    }
  }

  // Deduplicate (same package might appear in multiple manifests)
  const seenPackages = new Set<string>();
  const uniqueRiskPackages = allRiskPackages.filter(({ pkg }) => {
    if (seenPackages.has(pkg.package)) return false;
    seenPackages.add(pkg.package);
    return true;
  });

  if (uniqueRiskPackages.length > 0) {
    summary.addHeading("Packages Requiring Attention", 3);
    summary.addTable([
      [
        { data: "Package", header: true },
        { data: "Risk", header: true },
        { data: "Score", header: true },
        { data: "Data", header: true },
        { data: "Location", header: true },
        { data: "Key Issue", header: true },
      ],
      ...uniqueRiskPackages.map(({ pkg, manifest }) => {
        const isUnverified = !pkg.data_quality || pkg.data_quality.assessment !== "VERIFIED";
        const dataStatus = isUnverified ? "⚠️" : "✓";
        return [
          `<code>${escapeHtml(pkg.package)}</code>`,
          pkg.risk_level,
          `${pkg.health_score}/100`,
          dataStatus,
          `<code>${escapeHtml(manifest)}</code>`,
          escapeHtml(pkg.abandonment_risk?.risk_factors?.[0] || "-"),
        ];
      }),
    ]);

    // Count unverified high-risk packages
    const unverifiedRiskCount = uniqueRiskPackages.filter(
      ({ pkg }) => !pkg.data_quality || pkg.data_quality.assessment !== "VERIFIED"
    ).length;

    if (unverifiedRiskCount > 0) {
      summary.addRaw("\n> [!NOTE]\n");
      summary.addRaw(`> **${unverifiedRiskCount} package(s) have incomplete data** (marked ⚠️). `);
      summary.addRaw("Risk levels may be inaccurate due to missing repository information.\n\n");
    }
  }

  // Per-manifest details in collapsible sections
  const successfulManifests = manifests.filter((m) => m.status === "success" && m.packages && m.packages.length > 0);

  if (successfulManifests.length > 0) {
    summary.addRaw("\n<details>\n<summary>View all packages by manifest</summary>\n\n");

    for (const m of successfulManifests) {
      if (!m.packages || m.packages.length === 0) continue;

      summary.addRaw(`\n#### \`${escapeMarkdown(m.manifest.relativePath)}\` (${m.manifest.ecosystem})\n\n`);

      const packageTable = m.packages
        .sort((a, b) => (a.health_score ?? -1) - (b.health_score ?? -1))
        .map(
          (p) =>
            `| \`${escapeMarkdown(p.package)}\` | ${p.risk_level} | ${p.health_score}/100 |`
        )
        .join("\n");

      summary.addRaw("| Package | Risk | Score |\n|---------|------|-------|\n");
      summary.addRaw(packageTable + "\n");
    }

    summary.addRaw("\n</details>\n");
  }

  // Failed manifests details
  const failedManifests = manifests.filter((m) => m.status !== "success");
  if (failedManifests.length > 0) {
    summary.addRaw("\n<details>\n<summary>Failed manifests</summary>\n\n");

    for (const m of failedManifests) {
      const statusLabel = getStatusLabel(m.status);
      summary.addRaw(
        `- \`${escapeMarkdown(m.manifest.relativePath)}\`: ${statusLabel}${m.error ? ` - ${escapeMarkdown(m.error)}` : ""}\n`
      );
    }

    summary.addRaw("\n</details>\n");
  }

  // Not found packages (deduplicated across manifests)
  const allNotFound = new Set<string>();
  for (const m of manifests) {
    if (m.notFound) {
      for (const pkg of m.notFound) {
        allNotFound.add(pkg);
      }
    }
  }

  if (allNotFound.size > 0) {
    summary.addRaw("\n> [!NOTE]\n");
    summary.addRaw(`> **${allNotFound.size} package(s) not found**: `);
    summary.addRaw([...allNotFound].slice(0, 15).map((p) => `\`${escapeMarkdown(p)}\``).join(", "));
    if (allNotFound.size > 15) {
      summary.addRaw(` *(and ${allNotFound.size - 15} more)*`);
    }
    summary.addRaw("\n\n");
  }

  // Footer with contextual feedback links
  summary.addRaw("\n---\n");
  if (hasIssues) {
    summary.addRaw(
      `*[PkgWatch](https://pkgwatch.dev?utm_source=action&utm_medium=summary) v${VERSION}* | ` +
      `[Wrong score?](${GITHUB_REPO}/issues/new?template=bug_report.yml&labels=bug,action,false-positive) | ` +
      `[Feedback](${GITHUB_REPO}/discussions/new?category=feedback)\n`
    );
  } else {
    summary.addRaw(
      `*[PkgWatch](https://pkgwatch.dev?utm_source=action&utm_medium=summary) v${VERSION}*\n`
    );
  }

  await summary.write();
}

function getStatusEmoji(status: string): string {
  switch (status) {
    case "success":
      return "✅";
    case "parse_error":
      return "❌";
    case "api_error":
      return "⚠️";
    case "rate_limited":
      return "🚫";
    default:
      return "❓";
  }
}

function getStatusLabel(status: string): string {
  switch (status) {
    case "success":
      return "Success";
    case "parse_error":
      return "Parse Error";
    case "api_error":
      return "API Error";
    case "rate_limited":
      return "Rate Limited";
    default:
      return "Unknown";
  }
}

/**
 * Escape text for use in raw markdown contexts (pipe tables inside <details>, inline text).
 * Escapes markdown-special characters so they render literally.
 */
function escapeMarkdown(text: string): string {
  return text
    .replace(/[\\`*_[\]|<>]/g, "\\$&")
    .slice(0, 100); // Truncate long values
}

/**
 * Escape text for use inside HTML elements (e.g. <td> cells from addTable()).
 * GitHub does NOT render markdown inside HTML blocks, so we need HTML entities instead.
 */
function escapeHtml(text: string): string {
  return text
    .slice(0, 100) // Truncate before escaping to avoid cutting mid-entity
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
