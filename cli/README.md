# @pkgwatch/cli

[![npm version](https://img.shields.io/npm/v/@pkgwatch/cli.svg)](https://www.npmjs.com/package/@pkgwatch/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

Keep watch over your npm and Python dependencies. Monitor package health and detect risks before they become problems.

## Installation

```bash
npm install -g @pkgwatch/cli
# or
npx @pkgwatch/cli check lodash
```

Requires Node.js 20+.

## Setup

Get your API key at [pkgwatch.laranjo.dev](https://pkgwatch.laranjo.dev).

```bash
# Option 1: Interactive setup
pkgwatch config set

# Option 2: Environment variable (for CI)
export PKGWATCH_API_KEY=pw_your_key_here
```

## Commands

### Check a package

```bash
pkgwatch check lodash
pkgwatch c lodash               # Using alias
pkgwatch check @babel/core
pkgwatch check lodash --json    # JSON output
```

### Scan package.json

```bash
pkgwatch scan                      # Scan ./package.json
pkgwatch s                         # Using alias
pkgwatch scan ./path/to/project
pkgwatch scan --fail-on HIGH       # Exit 1 if HIGH or CRITICAL (CI mode)
pkgwatch scan --fail-on CRITICAL   # Exit 1 only on CRITICAL
pkgwatch scan -o json              # JSON output
pkgwatch scan -o sarif             # SARIF format (security tooling)
pkgwatch scan --json               # JSON output (deprecated)
```

**Output formats:**
- `table` (default): Human-readable table output
- `json`: JSON format for programmatic use
- `sarif`: SARIF 2.1.0 format for security tooling integration

**Features:**
- Progress bar displayed for scans with 20+ dependencies
- Rate limit warnings shown at 80% and 95% usage
- Batch processing for large dependency sets

### Check API usage

```bash
pkgwatch usage
pkgwatch u              # Using alias
```

Shows your current API usage with:
- Account tier
- Requests used this month
- Monthly limit and remaining requests
- Reset date
- Visual progress bar

**Rate limit warnings:**
- Yellow warning at 80% usage
- Red critical warning at 95% usage

### Doctor (diagnostics)

```bash
pkgwatch doctor         # Check configuration and API connectivity
```

Validates:
- API key configuration
- API connectivity
- Node.js version
- Account tier and usage

### Configuration

```bash
pkgwatch config set    # Set API key (validates key)
pkgwatch config show   # Show configuration
pkgwatch config clear  # Clear configuration
```

## Global Flags

These flags work with any command:

| Flag | Description |
|------|-------------|
| `-q, --quiet` | Suppress progress output (spinner, status messages) |
| `-v, --verbose` | Show detailed debug output |
| `-V, --version` | Show CLI version |
| `-h, --help` | Show help |

```bash
pkgwatch -q check lodash      # No spinner, just results
pkgwatch -v check lodash      # Show API call details
pkgwatch --version            # Show version
```

## Command Aliases

All main commands have short aliases for faster typing:

| Command | Alias |
|---------|-------|
| `check` | `c` |
| `scan` | `s` |
| `usage` | `u` |

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Check dependencies
  env:
    PKGWATCH_API_KEY: ${{ secrets.PKGWATCH_API_KEY }}
  run: npx @pkgwatch/cli scan --fail-on HIGH
```

For quieter CI output:

```yaml
- name: Check dependencies
  env:
    PKGWATCH_API_KEY: ${{ secrets.PKGWATCH_API_KEY }}
  run: npx @pkgwatch/cli -q scan --fail-on HIGH
```

SARIF output for security tooling:

```yaml
- name: Check dependencies
  env:
    PKGWATCH_API_KEY: ${{ secrets.PKGWATCH_API_KEY }}
  run: npx @pkgwatch/cli scan -o sarif > pkgwatch.sarif
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Risk threshold exceeded (with --fail-on) |
| 2 | CLI error (network, auth, invalid args) |

## Example Output

```
$ pkgwatch check express

express@5.2.1

  Health Score    83.5/100  LOW
  Abandon Risk    3.5% (12 months)

  + Active commits (0 days ago)
  + 37.9M+ weekly downloads
  + 5 maintainers
  + 11 active contributors (90d)

  Components:
    Maintainer:  100/100
    Evolution:   87/100
    Community:   74/100
    User Impact: 69/100
```

## License

MIT
