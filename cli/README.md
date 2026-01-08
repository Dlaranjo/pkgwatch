# @dephealth/cli

[![npm version](https://img.shields.io/npm/v/@dephealth/cli.svg)](https://www.npmjs.com/package/@dephealth/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

Check npm package health scores from the command line.

## Installation

```bash
npm install -g @dephealth/cli
# or
npx @dephealth/cli check lodash
```

Requires Node.js 20+.

## Setup

Get your API key at [dephealth.laranjo.dev](https://dephealth.laranjo.dev).

```bash
# Option 1: Interactive setup
dephealth config set

# Option 2: Environment variable (for CI)
export DEPHEALTH_API_KEY=dh_your_key_here
```

## Commands

### Check a package

```bash
dephealth check lodash
dephealth check @babel/core
dephealth check lodash --json    # JSON output
```

### Scan package.json

```bash
dephealth scan                      # Scan ./package.json
dephealth scan ./path/to/project
dephealth scan --fail-on HIGH       # Exit 1 if HIGH or CRITICAL (CI mode)
dephealth scan --fail-on CRITICAL   # Exit 1 only on CRITICAL
dephealth scan --json               # JSON output
```

### Check API usage

```bash
dephealth usage
```

### Configuration

```bash
dephealth config set    # Set API key
dephealth config show   # Show configuration
dephealth config clear  # Clear configuration
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
dephealth -q check lodash      # No spinner, just results
dephealth -v check lodash      # Show API call details
dephealth --version            # Show version
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Check dependencies
  env:
    DEPHEALTH_API_KEY: ${{ secrets.DEPHEALTH_API_KEY }}
  run: npx @dephealth/cli scan --fail-on HIGH
```

For quieter CI output:

```yaml
- name: Check dependencies
  env:
    DEPHEALTH_API_KEY: ${{ secrets.DEPHEALTH_API_KEY }}
  run: npx @dephealth/cli -q scan --fail-on HIGH
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Risk threshold exceeded (with --fail-on) |
| 2 | CLI error (network, auth, invalid args) |

## Example Output

```
$ dephealth check express

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
