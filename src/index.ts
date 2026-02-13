import * as core from '@actions/core';
import * as path from 'path';
import * as fs from 'fs';
import { QScannerRunner } from './common/qscanner/QScannerRunner';
import { ThresholdEvaluator, createThresholdConfig } from './common/thresholds/ThresholdEvaluator';
import { uploadSarifToGitHub } from './common/sarif/uploader';
import { IssueCreator, createIssueConfig } from './common/issues/IssueCreator';
import {
  RepoScanOptions,
  QScannerConfig,
  QScannerExitCode,
  QScannerResult,
  VulnerabilitySummary,
  SarifReport,
} from './common/types';

function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

async function runScanWithRetry(
  runner: QScannerRunner,
  scanOptions: RepoScanOptions,
  maxAttempts: number,
  delaySeconds: number,
): Promise<QScannerResult> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (attempt > 1) {
      core.info('');
      core.info(`Waiting ${delaySeconds}s before retry...`);
      await sleep(delaySeconds);
    }

    core.info(`Starting code scan (attempt ${attempt}/${maxAttempts})...`);
    const result = await runner.scanRepo(scanOptions);

    if (result.exitCode !== QScannerExitCode.FAILED_TO_GET_VULN_REPORT
        && result.exitCode !== QScannerExitCode.FAILED_TO_GET_POLICY_EVALUATION_RESULT) {
      return result;
    }

    if (attempt < maxAttempts) {
      core.warning(
        `Vulnerability report not available (exit code ${result.exitCode}). `
        + `Retrying full scan (${attempt}/${maxAttempts})...`
      );
    } else {
      core.error(
        `Vulnerability report not available after ${maxAttempts} attempts. `
        + `Qualys cloud may still be processing the scan results.`
      );
      return result;
    }
  }

  // Unreachable, but TypeScript needs it
  throw new Error('Unexpected: retry loop exited without returning');
}

async function run(): Promise<void> {
  try {
    const accessToken = core.getInput('qualys_access_token', { required: true });
    const pod = core.getInput('qualys_pod', { required: true });
    const scanPath = core.getInput('scan_path') || process.env.GITHUB_WORKSPACE || '.';
    const excludeDirs = core.getInput('exclude_dirs');
    const excludeFiles = core.getInput('exclude_files');
    const usePolicyEvaluation = core.getBooleanInput('use_policy_evaluation');
    const policyTags = core.getInput('policy_tags');
    const maxCritical = core.getInput('max_critical') || '0';
    const maxHigh = core.getInput('max_high') || '0';
    const maxMedium = core.getInput('max_medium') || '-1';
    const maxLow = core.getInput('max_low') || '-1';
    const scanSecrets = core.getBooleanInput('scan_secrets');
    const offlineScan = core.getBooleanInput('offline_scan');
    const generateSbom = core.getBooleanInput('generate_sbom');
    const sbomFormat = core.getInput('sbom_format') || 'spdx';
    const scanTimeout = parseInt(core.getInput('scan_timeout') || '300', 10);
    const uploadSarif = core.getBooleanInput('upload_sarif');
    const continueOnError = core.getBooleanInput('continue_on_error');
    const createIssues = core.getBooleanInput('create_issues');
    const issueMinSeverity = core.getInput('issue_min_severity') || '4';
    const issueLabels = core.getInput('issue_labels') || '';
    const issueAssignees = core.getInput('issue_assignees') || '';
    const maxNetworkRetries = parseInt(core.getInput('max_network_retries') || '5', 10);
    const networkRetryWaitMin = parseInt(core.getInput('network_retry_wait_min') || '10', 10);
    const networkRetryWaitMax = parseInt(core.getInput('network_retry_wait_max') || '15', 10);
    const reportFetchRetries = parseInt(core.getInput('report_fetch_retries') || '3', 10);
    const reportFetchDelay = parseInt(core.getInput('report_fetch_delay') || '60', 10);
    const debug = core.getBooleanInput('debug');

    core.setSecret(accessToken);

    core.info('='.repeat(60));
    core.info('Qualys Code Scan (SCA)');
    core.info('='.repeat(60));
    core.info(`Scan Path: ${scanPath}`);
    core.info(`POD: ${pod}`);
    if (excludeDirs) core.info(`Exclude Dirs: ${excludeDirs}`);
    if (excludeFiles) core.info(`Exclude Files: ${excludeFiles}`);
    core.info(`Policy Evaluation: ${usePolicyEvaluation}`);
    if (!usePolicyEvaluation) {
      core.info(`Thresholds - Critical: ${maxCritical}, High: ${maxHigh}, Medium: ${maxMedium}, Low: ${maxLow}`);
    }
    core.info(`Offline Scan: ${offlineScan}`);
    core.info(`Generate SBOM: ${generateSbom}`);
    core.info('='.repeat(60));

    const config: QScannerConfig = {
      authMethod: 'access-token',
      accessToken,
      pod: pod.toUpperCase(),
    };

    const runner = new QScannerRunner(config);
    await runner.setup();

    const scanTypes: ('pkg' | 'secret')[] = ['pkg'];
    if (scanSecrets) {
      scanTypes.push('secret');
    }

    const formats: ('json' | 'spdx' | 'cyclonedx')[] = ['json'];
    if (generateSbom) {
      if (sbomFormat === 'both') {
        formats.push('spdx', 'cyclonedx');
      } else if (sbomFormat === 'cyclonedx') {
        formats.push('cyclonedx');
      } else {
        formats.push('spdx');
      }
    }

    const scanOptions: RepoScanOptions = {
      scanPath: path.resolve(scanPath),
      excludeDirs: excludeDirs ? excludeDirs.split(',').map((d) => d.trim()).filter(Boolean) : undefined,
      excludeFiles: excludeFiles ? excludeFiles.split(',').map((f) => f.trim()).filter(Boolean) : undefined,
      mode: usePolicyEvaluation ? 'evaluate-policy' : 'get-report',
      scanTypes,
      format: formats,
      reportFormat: ['sarif', 'json'],
      policyTags: policyTags ? policyTags.split(',').map((t) => t.trim()).filter(Boolean) : undefined,
      timeout: scanTimeout,
      offlineScan,
      logLevel: (debug || core.isDebug()) ? 'debug' : 'info',
      showPerfStat: debug || core.isDebug(),
      maxNetworkRetries,
      networkRetryWaitMin,
      networkRetryWaitMax,
    };

    const maxAttempts = reportFetchRetries + 1;
    const result = await runScanWithRetry(runner, scanOptions, maxAttempts, reportFetchDelay);

    let summary: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    let sarifPath: string | undefined;
    let sbomPath: string | undefined;
    let sarifReport: SarifReport | undefined;
    const reportFetchFailed = result.exitCode === QScannerExitCode.FAILED_TO_GET_VULN_REPORT
      || result.exitCode === QScannerExitCode.FAILED_TO_GET_POLICY_EVALUATION_RESULT;

    if (result.reportFile && fs.existsSync(result.reportFile)) {
      sarifPath = result.reportFile;
      const parsed = runner.parseSarifReport(result.reportFile);
      summary = parsed.summary;
      sarifReport = parsed.report;
    }

    if (generateSbom && fs.existsSync(result.outputDir)) {
      const files = fs.readdirSync(result.outputDir);
      const sbomFiles = files.filter((f) => f.includes('spdx') || f.includes('cyclonedx'));
      if (sbomFiles.length > 0) {
        sbomPath = path.join(result.outputDir, sbomFiles[0]);
      }
    }

    core.info('');
    core.info('='.repeat(60));
    core.info('Scan Results Summary');
    core.info('='.repeat(60));
    if (reportFetchFailed) {
      core.warning('Vulnerability report could not be retrieved from Qualys cloud');
    }
    core.info(`Total Vulnerabilities: ${summary.total}`);
    core.info(`  Critical: ${summary.critical}`);
    core.info(`  High:     ${summary.high}`);
    core.info(`  Medium:   ${summary.medium}`);
    core.info(`  Low:      ${summary.low}`);
    core.info(`  Info:     ${summary.informational}`);
    core.info('='.repeat(60));

    core.setOutput('vulnerability_count', summary.total.toString());
    core.setOutput('critical_count', summary.critical.toString());
    core.setOutput('high_count', summary.high.toString());
    core.setOutput('medium_count', summary.medium.toString());
    core.setOutput('low_count', summary.low.toString());
    core.setOutput('policy_result', result.policyResult);

    if (sarifPath) {
      core.setOutput('sarif_path', sarifPath);
    }

    if (result.scanResultFile) {
      core.setOutput('json_path', result.scanResultFile);
    }

    if (sbomPath) {
      core.setOutput('sbom_path', sbomPath);
    }

    const githubToken = process.env.GITHUB_TOKEN;

    if (uploadSarif && sarifPath && githubToken) {
      try {
        await uploadSarifToGitHub(sarifPath, githubToken);
      } catch (error) {
        core.warning(`Failed to upload SARIF: ${error instanceof Error ? error.message : error}`);
      }
    }

    let issuesCreated = 0;
    if (createIssues && sarifReport && githubToken) {
      const issueConfig = createIssueConfig({
        createIssues: true,
        minSeverity: issueMinSeverity,
        labels: issueLabels,
        assignees: issueAssignees,
      });
      const issueCreator = new IssueCreator(githubToken, issueConfig);
      const issues = await issueCreator.createIssuesFromSarif(sarifReport, 'code');
      issuesCreated = issues.length;
      core.info(`Created ${issuesCreated} GitHub issues for vulnerabilities`);
    }
    core.setOutput('issues_created', issuesCreated.toString());

    let passed = true;
    let failureReason = '';

    if (reportFetchFailed) {
      passed = false;
      failureReason = `Failed to retrieve vulnerability report from Qualys cloud (exit code ${result.exitCode})`;
    } else if (usePolicyEvaluation) {
      if (result.exitCode === QScannerExitCode.POLICY_EVALUATION_DENY) {
        passed = false;
        failureReason = 'Policy evaluation result: DENY';
      } else if (result.exitCode === QScannerExitCode.POLICY_EVALUATION_AUDIT) {
        core.warning('Policy evaluation result: AUDIT');
      }
    } else {
      const thresholdConfig = createThresholdConfig({
        maxCritical,
        maxHigh,
        maxMedium,
        maxLow,
      });
      const evaluator = new ThresholdEvaluator(thresholdConfig);
      const evalResult = evaluator.evaluate(summary);
      passed = evalResult.passed;
      if (!passed) {
        failureReason = evalResult.failureReasons.join('; ');
      }
    }

    core.setOutput('scan_passed', passed.toString());

    if (!passed) {
      core.info('');
      core.error(`Scan FAILED: ${failureReason}`);
      if (!continueOnError) {
        core.setFailed(failureReason);
      }
    } else {
      core.info('');
      core.info('Scan PASSED');
    }

    runner.cleanup();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    core.setFailed(`Action failed: ${message}`);
  }
}

run();
