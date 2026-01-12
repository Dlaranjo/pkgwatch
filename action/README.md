# PkgWatch GitHub Action

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue.svg)](https://github.com/features/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Scan your npm and Python dependencies for health risks and security issues in CI/CD.

## Quick Start

```yaml
- name: Scan dependencies
  uses: pkgwatch/action@v1
  with:
    api-key: ${{ secrets.PKGWATCH_API_KEY }}
```

Get your API key at [pkgwatch.laranjo.dev](https://pkgwatch.laranjo.dev).

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | - | PkgWatch API key |
| `working-directory` | No | `.` | Directory containing package.json |
| `fail-on` | No | - | Fail if risk level reached: `HIGH` or `CRITICAL` |
| `include-dev` | No | `true` | Include devDependencies in scan |
| `soft-fail` | No | `false` | Set outputs but don't fail workflow even if threshold exceeded |

## Outputs

| Output | Description |
|--------|-------------|
| `total` | Total packages scanned |
| `critical` | Count of CRITICAL risk packages |
| `high` | Count of HIGH risk packages |
| `medium` | Count of MEDIUM risk packages |
| `low` | Count of LOW risk packages |
| `has-issues` | `true` if any CRITICAL or HIGH risk packages found |
| `highest-risk` | Highest risk level found (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`) |
| `failed` | `true` if fail-on threshold was exceeded |
| `results` | Full scan results as JSON string |

## Examples

### Basic Scan

```yaml
name: PkgWatch Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  pkgwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan dependencies
        uses: pkgwatch/action@v1
        with:
          api-key: ${{ secrets.PKGWATCH_API_KEY }}
```

### Fail on HIGH Risk

```yaml
- name: Scan dependencies
  id: pkgwatch
  uses: pkgwatch/action@v1
  with:
    api-key: ${{ secrets.PKGWATCH_API_KEY }}
    fail-on: HIGH

- name: Notify on issues
  if: steps.pkgwatch.outputs.has-issues == 'true'
  run: echo "Found risky dependencies!"
```

### Monorepo (Multiple package.json)

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        package: [frontend, backend, shared]
    steps:
      - uses: actions/checkout@v4

      - name: Scan ${{ matrix.package }}
        uses: pkgwatch/action@v1
        with:
          api-key: ${{ secrets.PKGWATCH_API_KEY }}
          working-directory: packages/${{ matrix.package }}
          fail-on: CRITICAL
```

### Weekly Scheduled Scan

```yaml
name: Weekly PkgWatch Scan

on:
  schedule:
    - cron: '0 0 * * 1'  # Every Monday at midnight

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan dependencies
        uses: pkgwatch/action@v1
        with:
          api-key: ${{ secrets.PKGWATCH_API_KEY }}
          fail-on: HIGH
```

### Use Output in Conditional Steps

```yaml
- name: Scan dependencies
  id: pkgwatch
  uses: pkgwatch/action@v1
  with:
    api-key: ${{ secrets.PKGWATCH_API_KEY }}

- name: Block deploy on critical issues
  if: steps.pkgwatch.outputs.highest-risk == 'CRITICAL'
  run: |
    echo "Cannot deploy with CRITICAL risk dependencies"
    exit 1

- name: Warn on high issues
  if: steps.pkgwatch.outputs.highest-risk == 'HIGH'
  run: echo "::warning::HIGH risk dependencies detected"
```

### Soft-Fail Mode

Use `soft-fail: true` to set outputs and warnings without failing the workflow:

```yaml
- name: Scan dependencies (informational)
  uses: pkgwatch/action@v1
  with:
    api-key: ${{ secrets.PKGWATCH_API_KEY }}
    fail-on: HIGH
    soft-fail: true

# Workflow continues even if HIGH risk packages are found
# Outputs are still set and can be used in conditional steps
```

This is useful for:
- Gradual rollout of package health checks
- Informational scans that shouldn't block CI
- Tracking health trends without enforcement

## Job Summary

The action automatically generates a job summary with:
- Pass/fail status banner
- Summary counts by risk level
- Table of packages requiring attention
- Collapsible list of all packages

## GitHub Annotations

The action automatically creates GitHub annotations for all CRITICAL and HIGH risk packages. These annotations:
- Appear in the Files Changed tab on pull requests
- Show up in workflow run summaries
- Include package name, risk level, and health score
- Point to `package.json` for easy navigation

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (or no fail-on threshold set) |
| 1 | Threshold exceeded (via fail-on) |

## Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Authentication failed (401)` | Invalid or expired API key | Verify key at [dashboard](https://pkgwatch.laranjo.dev/dashboard) |
| `Rate limit exceeded (429)` | API quota exhausted | Upgrade plan or reduce scan frequency |
| `Request timed out` | API unresponsive | Check [status page](https://status.pkgwatch.laranjo.dev) |
| `Cannot find package.json` | Wrong path | Check `working-directory` input |

## Security

- API keys are automatically masked in logs
- Path traversal outside repository is blocked
- All output is sanitized to prevent markdown injection

## License

MIT
