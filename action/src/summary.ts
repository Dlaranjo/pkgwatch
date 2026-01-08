import * as core from "@actions/core";
import { ScanResult, PackageHealth } from "./api.js";

// Version is injected at build time via esbuild --define
declare const __VERSION__: string;
const VERSION = typeof __VERSION__ !== "undefined" ? __VERSION__ : "1.0.0";

export async function generateSummary(
  result: ScanResult,
  failed: boolean,
  threshold: string
): Promise<void> {
  const summary = core.summary;

  // Pass/fail banner
  if (failed) {
    summary.addRaw(
      `> [!CAUTION]\n> **Policy Violation**: Packages exceed ${threshold} threshold\n\n`
    );
  } else if (threshold) {
    summary.addRaw(
      `> [!TIP]\n> **Scan Passed**: No packages exceed ${threshold} threshold\n\n`
    );
  }

  summary.addHeading("DepHealth Scan Results", 2);
  summary.addRaw(`Scanned **${result.total}** packages\n\n`);

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
        { data: "Key Issue", header: true },
      ],
      ...riskPackages.map((pkg) => [
        `\`${escapeMarkdown(pkg.package)}\``,
        pkg.risk_level,
        `${pkg.health_score}/100`,
        escapeMarkdown(pkg.abandonment_risk?.risk_factors?.[0] || "-"),
      ]),
    ]);
  }

  // All packages in collapsible
  if (result.packages.length > 0) {
    const allTable = result.packages
      .sort((a, b) => a.health_score - b.health_score)
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

  // Footer
  summary.addRaw("\n---\n");
  summary.addRaw(`*[DepHealth](https://dephealth.laranjo.dev) v${VERSION}*\n`);

  await summary.write();
}

function escapeMarkdown(text: string): string {
  return text
    .replace(/[\\`*_{}[\]()#+\-.!|<>]/g, "\\$&")
    .slice(0, 100); // Truncate long values
}
