import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { DepHealthClient, ScanResult } from "./api";

export async function scanDependencies(
  apiKey: string,
  basePath: string,
  includeDev: boolean
): Promise<ScanResult> {
  const packagePath = basePath.endsWith(".json")
    ? resolve(basePath)
    : resolve(basePath, "package.json");

  if (!existsSync(packagePath)) {
    throw new Error(
      `Cannot find package.json at ${packagePath}\n\nEnsure the 'working-directory' input is correct.`
    );
  }

  const content = readFileSync(packagePath, "utf-8");

  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(content);
  } catch {
    throw new Error(
      `Invalid JSON in package.json at ${packagePath}\n\nEnsure the file contains valid JSON.`
    );
  }

  const dependencies: Record<string, string> = {
    ...(pkg.dependencies || {}),
    ...(includeDev ? pkg.devDependencies || {} : {}),
  };

  const depCount = Object.keys(dependencies).length;

  if (depCount === 0) {
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, packages: [] };
  }

  const client = new DepHealthClient(apiKey);
  return client.scan(dependencies);
}
