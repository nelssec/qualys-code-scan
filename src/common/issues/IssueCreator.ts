import * as core from '@actions/core';
import * as github from '@actions/github';
import { SarifResult, SarifReport } from '../types';

export interface IssueConfig {
  enabled: boolean;
  minSeverity: number;
  labels: string[];
  assignees: string[];
}

export interface CreatedIssue {
  number: number;
  url: string;
  title: string;
}

export class IssueCreator {
  private octokit: ReturnType<typeof github.getOctokit>;
  private config: IssueConfig;
  private owner: string;
  private repo: string;

  constructor(token: string, config: IssueConfig) {
    this.octokit = github.getOctokit(token);
    this.config = config;
    this.owner = github.context.repo.owner;
    this.repo = github.context.repo.repo;
  }

  async createIssuesFromSarif(report: SarifReport, scanType: 'container' | 'code'): Promise<CreatedIssue[]> {
    if (!this.config.enabled) {
      return [];
    }

    const createdIssues: CreatedIssue[] = [];
    const existingIssues = await this.getExistingQualysIssues();

    for (const run of report.runs || []) {
      const ruleSeverityMap = new Map<string, number>();
      if (run.tool?.driver?.rules) {
        for (const rule of run.tool.driver.rules) {
          const severity = rule.properties?.severity as number | undefined;
          if (rule.id && severity !== undefined) {
            ruleSeverityMap.set(rule.id, severity);
          }
        }
      }

      for (const result of run.results || []) {
        let severity: number = result.properties?.severity as number ?? 1;
        if (severity === undefined && result.ruleId) {
          severity = ruleSeverityMap.get(result.ruleId) ?? 1;
        }

        if (severity < this.config.minSeverity) {
          continue;
        }

        const vulnId = this.getVulnId(result);
        const qualysTag = `qualys-vuln:${vulnId}`;

        if (existingIssues.has(qualysTag)) {
          core.debug(`Issue already exists for ${vulnId}, skipping`);
          continue;
        }

        try {
          const issue = await this.createIssue(result, severity, scanType, qualysTag);
          createdIssues.push(issue);
          existingIssues.add(qualysTag);
        } catch (error) {
          core.warning(`Failed to create issue for ${vulnId}: ${error instanceof Error ? error.message : error}`);
        }
      }
    }

    return createdIssues;
  }

  private async getExistingQualysIssues(): Promise<Set<string>> {
    const existingTags = new Set<string>();

    try {
      const issues = await this.octokit.rest.issues.listForRepo({
        owner: this.owner,
        repo: this.repo,
        labels: 'qualys-vulnerability',
        state: 'all',
        per_page: 100,
      });

      for (const issue of issues.data) {
        const match = issue.body?.match(/<!-- qualys-vuln:([^\s]+) -->/);
        if (match) {
          existingTags.add(`qualys-vuln:${match[1]}`);
        }
      }
    } catch (error) {
      core.warning(`Failed to fetch existing issues: ${error instanceof Error ? error.message : error}`);
    }

    return existingTags;
  }

  private async createIssue(
    result: SarifResult,
    severity: number,
    scanType: 'container' | 'code',
    qualysTag: string
  ): Promise<CreatedIssue> {
    const severityLabel = this.getSeverityLabel(severity);
    const vulnId = this.getVulnId(result);
    const title = `[${severityLabel}] ${vulnId}: ${this.truncate(result.message.text, 80)}`;

    const body = this.buildIssueBody(result, severity, scanType, qualysTag);

    await this.ensureLabelsExist(severityLabel);

    const labels = [
      'qualys-vulnerability',
      `severity:${severityLabel.toLowerCase()}`,
      `scan:${scanType}`,
      ...this.config.labels,
    ];

    const response = await this.octokit.rest.issues.create({
      owner: this.owner,
      repo: this.repo,
      title,
      body,
      labels,
      assignees: this.config.assignees.length > 0 ? this.config.assignees : undefined,
    });

    core.info(`Created issue #${response.data.number}: ${title}`);

    return {
      number: response.data.number,
      url: response.data.html_url,
      title,
    };
  }

  private buildIssueBody(
    result: SarifResult,
    severity: number,
    scanType: 'container' | 'code',
    qualysTag: string
  ): string {
    const props = result.properties || {};
    const severityLabel = this.getSeverityLabel(severity);

    let body = `<!-- ${qualysTag} -->\n\n`;
    body += `## Vulnerability Details\n\n`;
    body += `| Property | Value |\n`;
    body += `|----------|-------|\n`;
    body += `| **Severity** | ${severityLabel} |\n`;
    body += `| **Scan Type** | ${scanType === 'container' ? 'Container Image' : 'Code/SCA'} |\n`;

    if (props.qid) {
      body += `| **QID** | ${props.qid} |\n`;
    }

    if (props.cves && Array.isArray(props.cves) && props.cves.length > 0) {
      const cveLinks = props.cves.map((cve: string) => `[${cve}](https://nvd.nist.gov/vuln/detail/${cve})`).join(', ');
      body += `| **CVE(s)** | ${cveLinks} |\n`;
    }

    if (props.cvssScore) {
      body += `| **CVSS Score** | ${props.cvssScore} |\n`;
    }

    if (props.packageName) {
      body += `| **Package** | ${props.packageName} |\n`;
    }

    if (props.installedVersion) {
      body += `| **Installed Version** | ${props.installedVersion} |\n`;
    }

    if (props.fixedVersion) {
      body += `| **Fixed Version** | ${props.fixedVersion} |\n`;
    }

    body += `\n## Description\n\n${result.message.text}\n`;

    if (result.locations && result.locations.length > 0) {
      body += `\n## Location\n\n`;
      for (const loc of result.locations) {
        if (loc.physicalLocation?.artifactLocation?.uri) {
          body += `- \`${loc.physicalLocation.artifactLocation.uri}\`\n`;
        }
        if (loc.logicalLocations) {
          for (const logical of loc.logicalLocations) {
            body += `- ${logical.kind}: \`${logical.name}\`\n`;
          }
        }
      }
    }

    body += `\n---\n`;
    body += `*Created by Qualys ${scanType === 'container' ? 'Container' : 'Code'} Scan GitHub Action*\n`;
    body += `*Scan run: ${github.context.runId} | Workflow: ${github.context.workflow}*\n`;

    return body;
  }

  private async ensureLabelsExist(severityLabel: string): Promise<void> {
    const labelsToCreate = [
      { name: 'qualys-vulnerability', color: 'b60205', description: 'Vulnerability detected by Qualys scan' },
      { name: `severity:${severityLabel.toLowerCase()}`, color: this.getSeverityColor(severityLabel), description: `${severityLabel} severity vulnerability` },
      { name: 'scan:container', color: '1d76db', description: 'Container image scan finding' },
      { name: 'scan:code', color: '5319e7', description: 'Code/SCA scan finding' },
    ];

    for (const label of labelsToCreate) {
      try {
        await this.octokit.rest.issues.getLabel({
          owner: this.owner,
          repo: this.repo,
          name: label.name,
        });
      } catch {
        try {
          await this.octokit.rest.issues.createLabel({
            owner: this.owner,
            repo: this.repo,
            name: label.name,
            color: label.color,
            description: label.description,
          });
        } catch {
          // Ignore race conditions
        }
      }
    }
  }

  private getVulnId(result: SarifResult): string {
    const props = result.properties || {};
    if (props.qid) {
      return `QID-${props.qid}`;
    }
    if (props.cves && Array.isArray(props.cves) && props.cves.length > 0) {
      return props.cves[0];
    }
    return result.ruleId || 'UNKNOWN';
  }

  private getSeverityLabel(severity: number): string {
    switch (severity) {
      case 5: return 'Critical';
      case 4: return 'High';
      case 3: return 'Medium';
      case 2: return 'Low';
      default: return 'Info';
    }
  }

  private getSeverityColor(label: string): string {
    switch (label.toLowerCase()) {
      case 'critical': return 'b60205';
      case 'high': return 'd93f0b';
      case 'medium': return 'fbca04';
      case 'low': return '0e8a16';
      default: return 'c5def5';
    }
  }

  private truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
  }
}

export function createIssueConfig(inputs: {
  createIssues: boolean;
  minSeverity: string;
  labels: string;
  assignees: string;
}): IssueConfig {
  return {
    enabled: inputs.createIssues,
    minSeverity: parseInt(inputs.minSeverity, 10) || 4,
    labels: inputs.labels ? inputs.labels.split(',').map(l => l.trim()).filter(Boolean) : [],
    assignees: inputs.assignees ? inputs.assignees.split(',').map(a => a.trim()).filter(Boolean) : [],
  };
}
