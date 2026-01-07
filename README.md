# Qualys Code Scan

GitHub Action for scanning code repositories for vulnerabilities using Qualys Software Composition Analysis (SCA).

## Features

- Scan source code for vulnerable dependencies
- Secrets detection in source code
- SBOM generation (SPDX and CycloneDX formats)
- GitHub Security tab integration (SARIF upload)
- Automatic GitHub Issue creation for vulnerabilities
- Flexible pass/fail criteria with thresholds or Qualys cloud policies
- Organization-wide deployment support

## Quick Start

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      issues: write

    steps:
      - uses: actions/checkout@v4

      - name: Qualys Code Scan
        uses: qualys/qualys-code-scan@v1
        with:
          qualys_access_token: ${{ secrets.QUALYS_ACCESS_TOKEN }}
          qualys_pod: ${{ vars.QUALYS_POD }}
          max_critical: 0
          max_high: 5
          create_issues: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Setup

### Organization-Wide Configuration

1. Go to GitHub Organization Settings
2. Navigate to Secrets and variables then Actions
3. Create Organization secret: `QUALYS_ACCESS_TOKEN`
4. Create Organization variable: `QUALYS_POD` (e.g., US1, US2, US3, EU1)

### Repository-Level Configuration

For individual repositories, create repository secrets and variables with the same names.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `qualys_access_token` | Yes | - | Qualys API access token |
| `qualys_pod` | Yes | `US3` | Qualys platform POD |
| `scan_path` | No | Repo root | Directory to scan |
| `exclude_dirs` | No | - | Directories to exclude |
| `exclude_files` | No | - | File patterns to exclude |
| `use_policy_evaluation` | No | `false` | Use Qualys cloud policy |
| `policy_tags` | No | - | Comma-separated policy tags |
| `max_critical` | No | `0` | Max critical vulnerabilities (-1 = unlimited) |
| `max_high` | No | `0` | Max high vulnerabilities |
| `max_medium` | No | `-1` | Max medium vulnerabilities |
| `max_low` | No | `-1` | Max low vulnerabilities |
| `scan_secrets` | No | `false` | Enable secrets detection |
| `offline_scan` | No | `false` | Offline scan (no cloud upload) |
| `generate_sbom` | No | `false` | Generate SBOM |
| `sbom_format` | No | `spdx` | SBOM format (spdx, cyclonedx, both) |
| `scan_timeout` | No | `300` | Scan timeout in seconds |
| `upload_sarif` | No | `true` | Upload to GitHub Security tab |
| `continue_on_error` | No | `false` | Continue on threshold violation |
| `create_issues` | No | `false` | Create GitHub Issues |
| `issue_min_severity` | No | `4` | Min severity for issues (5=critical, 4=high) |
| `issue_labels` | No | - | Additional labels for issues |
| `issue_assignees` | No | - | GitHub usernames to assign |

## Outputs

| Output | Description |
|--------|-------------|
| `vulnerability_count` | Total vulnerabilities found |
| `critical_count` | Critical vulnerabilities |
| `high_count` | High vulnerabilities |
| `medium_count` | Medium vulnerabilities |
| `low_count` | Low vulnerabilities |
| `policy_result` | Policy result: ALLOW, DENY, AUDIT, NONE |
| `scan_passed` | Whether scan passed (true/false) |
| `sarif_path` | Path to SARIF report |
| `json_path` | Path to JSON report |
| `sbom_path` | Path to SBOM (if enabled) |
| `issues_created` | Number of issues created |

## Threshold vs Policy Evaluation

### Manual Thresholds

Set maximum allowed vulnerabilities per severity:

```yaml
- uses: qualys/qualys-code-scan@v1
  with:
    qualys_access_token: ${{ secrets.QUALYS_ACCESS_TOKEN }}
    qualys_pod: ${{ vars.QUALYS_POD }}
    max_critical: 0
    max_high: 3
    max_medium: -1
    max_low: -1
```

### Qualys Cloud Policies

Use centralized policies defined in Qualys:

```yaml
- uses: qualys/qualys-code-scan@v1
  with:
    qualys_access_token: ${{ secrets.QUALYS_ACCESS_TOKEN }}
    qualys_pod: ${{ vars.QUALYS_POD }}
    use_policy_evaluation: true
    policy_tags: production,pci-dss
```

## SBOM Generation

Generate Software Bill of Materials for compliance:

```yaml
- uses: qualys/qualys-code-scan@v1
  with:
    qualys_access_token: ${{ secrets.QUALYS_ACCESS_TOKEN }}
    qualys_pod: ${{ vars.QUALYS_POD }}
    generate_sbom: true
    sbom_format: both  # spdx, cyclonedx, or both
```

## GitHub Integration

### Security Tab

Results automatically appear in Security then Code scanning alerts when `upload_sarif: true`.

### Issue Creation

Enable `create_issues: true` to automatically create GitHub Issues for vulnerabilities. Issues include:
- Severity label
- CVE links
- Package and version info
- Remediation guidance
- Automatic deduplication

## Qualys POD Regions

| POD | Region |
|-----|--------|
| US1 | United States 1 |
| US2 | United States 2 |
| US3 | United States 3 |
| US4 | United States 4 |
| EU1 | Europe 1 |
| EU2 | Europe 2 |
| CA1 | Canada |
| IN1 | India |
| AU1 | Australia |
| UK1 | United Kingdom |
| AE1 | UAE |
| KSA1 | Saudi Arabia |

## Requirements

- Runner: Linux x86_64 (ubuntu-latest)
- Qualys Account: Container Security module with API access
- GitHub: Repository with Actions enabled

## License

MIT
