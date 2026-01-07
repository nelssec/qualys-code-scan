import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as zlib from 'zlib';
import * as crypto from 'crypto';
import { spawn, ChildProcess } from 'child_process';
import * as https from 'https';
import * as core from '@actions/core';
import {
  QScannerConfig,
  QScannerResult,
  QScannerExitCode,
  RepoScanOptions,
  SarifReport,
  VulnerabilitySummary,
} from '../types';

const QSCANNER_BINARY_URL =
  'https://github.com/nelssec/qualys-code-scan/releases/latest/download/qscanner.gz';
const QSCANNER_SHA256_URL =
  'https://github.com/nelssec/qualys-code-scan/releases/latest/download/qscanner.sha256';

export class QScannerRunner {
  private config: QScannerConfig;
  private binaryPath: string | null = null;
  private workDir: string;
  private accessToken: string | null = null;

  constructor(config: QScannerConfig) {
    this.config = config;
    this.workDir = path.join(os.tmpdir(), 'qscanner-github');
    if (!fs.existsSync(this.workDir)) {
      fs.mkdirSync(this.workDir, { recursive: true });
    }
  }

  async setup(): Promise<void> {
    const platform = this.getPlatform();
    const arch = this.getArchitecture();

    core.info(`Setting up QScanner for ${platform}-${arch}...`);

    if (platform !== 'linux' || arch !== 'amd64') {
      throw new Error(`QScanner binary only supports linux-amd64. Current: ${platform}-${arch}`);
    }

    const binaryName = 'qscanner';
    this.binaryPath = path.join(this.workDir, binaryName);

    if (fs.existsSync(this.binaryPath)) {
      core.info('QScanner binary already exists, skipping download.');
      await this.authenticate();
      return;
    }

    const gzPath = path.join(this.workDir, 'qscanner.gz');
    const sha256Path = path.join(this.workDir, 'qscanner.sha256');

    core.info('Downloading QScanner checksum...');
    await this.downloadFile(QSCANNER_SHA256_URL, sha256Path);
    const expectedHash = fs.readFileSync(sha256Path, 'utf-8').trim().split(/\s+/)[0];
    core.info(`Expected SHA256: ${expectedHash}`);

    core.info('Downloading QScanner binary...');
    await this.downloadFile(QSCANNER_BINARY_URL, gzPath);

    core.info('Verifying SHA256 checksum...');
    const actualHash = await this.calculateSha256(gzPath);
    if (actualHash !== expectedHash) {
      fs.unlinkSync(gzPath);
      fs.unlinkSync(sha256Path);
      throw new Error(`SHA256 checksum mismatch. Expected: ${expectedHash}, Got: ${actualHash}`);
    }
    core.info('Checksum verified.');

    core.info('Extracting QScanner binary...');
    await this.gunzipFile(gzPath, this.binaryPath);

    fs.unlinkSync(gzPath);
    fs.unlinkSync(sha256Path);
    fs.chmodSync(this.binaryPath, '755');

    core.info(`QScanner binary ready at ${this.binaryPath}`);
    await this.authenticate();
  }

  private gunzipFile(srcPath: string, destPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const src = fs.createReadStream(srcPath);
      const dest = fs.createWriteStream(destPath);
      const gunzip = zlib.createGunzip();

      src.pipe(gunzip).pipe(dest);

      dest.on('finish', () => {
        dest.close();
        resolve();
      });

      dest.on('error', reject);
      src.on('error', reject);
      gunzip.on('error', reject);
    });
  }

  private calculateSha256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);

      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  private async authenticate(): Promise<void> {
    if (!this.config.accessToken) {
      throw new Error('Access token is required');
    }
    this.accessToken = this.config.accessToken;
    core.info('Using provided access token for authentication');
  }

  async scanRepo(options: RepoScanOptions): Promise<QScannerResult> {
    if (!this.binaryPath) {
      throw new Error('QScanner not set up. Call setup() first.');
    }

    const args = this.buildCommonArgs(options);
    args.push('repo', options.scanPath);

    if (options.excludeDirs && options.excludeDirs.length > 0) {
      args.push('--exclude-dirs', options.excludeDirs.join(','));
    }

    if (options.excludeFiles && options.excludeFiles.length > 0) {
      args.push('--exclude-files', options.excludeFiles.join(','));
    }

    if (options.offlineScan) {
      args.push('--offline-scan=true');
    }

    if (options.showPerfStat) {
      args.push('--show-perf-stat');
    }

    return this.executeQScanner(args, options.outputDir);
  }

  parseSarifReport(reportPath: string): { summary: VulnerabilitySummary; report: SarifReport } {
    if (!fs.existsSync(reportPath)) {
      throw new Error(`SARIF report not found at ${reportPath}`);
    }

    const reportContent = fs.readFileSync(reportPath, 'utf-8');
    const report: SarifReport = JSON.parse(reportContent);

    const summary: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    if (report.runs && report.runs.length > 0) {
      for (const run of report.runs) {
        const ruleSeverityMap = new Map<string, number>();
        if (run.tool?.driver?.rules) {
          for (const rule of run.tool.driver.rules) {
            const ruleSeverity = rule.properties?.severity as number | undefined;
            if (rule.id && ruleSeverity !== undefined) {
              ruleSeverityMap.set(rule.id, ruleSeverity);
            }
          }
        }

        if (run.results) {
          for (const result of run.results) {
            summary.total++;

            let severity: number | undefined = result.properties?.severity as number | undefined;

            if (severity === undefined && result.ruleId) {
              severity = ruleSeverityMap.get(result.ruleId);
            }

            if (severity === undefined && result.level) {
              switch (result.level) {
                case 'error':
                  severity = 5;
                  break;
                case 'warning':
                  severity = 3;
                  break;
                case 'note':
                  severity = 2;
                  break;
                default:
                  severity = 1;
              }
            }

            if (severity === 5) {
              summary.critical++;
            } else if (severity === 4) {
              summary.high++;
            } else if (severity === 3) {
              summary.medium++;
            } else if (severity === 2) {
              summary.low++;
            } else {
              summary.informational++;
            }
          }
        }
      }
    }

    return { summary, report };
  }

  getBinaryPath(): string | null {
    return this.binaryPath;
  }

  getWorkDir(): string {
    return this.workDir;
  }

  cleanup(): void {
    if (this.workDir && fs.existsSync(this.workDir)) {
      try {
        const files = fs.readdirSync(this.workDir);
        for (const file of files) {
          if (file.endsWith('.json') || file.endsWith('.sarif')) {
            fs.unlinkSync(path.join(this.workDir, file));
          }
        }
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  private buildCommonArgs(options: RepoScanOptions): string[] {
    const args: string[] = [];

    args.push('--pod', this.config.pod);
    args.push('--mode', options.mode);

    if (options.scanTypes && options.scanTypes.length > 0) {
      args.push('--scan-types', options.scanTypes.join(','));
    }

    if (options.format && options.format.length > 0) {
      args.push('--format', options.format.join(','));
    }

    if (options.reportFormat && options.reportFormat.length > 0) {
      args.push('--report-format', options.reportFormat.join(','));
    }

    if (options.outputDir) {
      args.push('--output-dir', options.outputDir);
    }

    if (options.policyTags && options.policyTags.length > 0) {
      args.push('--policy-tags', options.policyTags.join(','));
    }

    if (options.timeout) {
      args.push('--scan-timeout', `${options.timeout}s`);
    }

    if (options.logLevel) {
      args.push('--log-level', options.logLevel);
    }

    if (this.config.proxy) {
      args.push('--proxy', this.config.proxy);
    }

    return args;
  }

  private async executeQScanner(args: string[], outputDir?: string): Promise<QScannerResult> {
    if (!this.binaryPath) {
      throw new Error('QScanner binary path not set');
    }

    if (!this.accessToken) {
      throw new Error('Access token not available. Call setup() first.');
    }

    const resultOutputDir = outputDir || path.join(this.workDir, 'output');
    if (!fs.existsSync(resultOutputDir)) {
      fs.mkdirSync(resultOutputDir, { recursive: true });
    }

    if (!args.includes('--output-dir')) {
      args.push('--output-dir', resultOutputDir);
    }

    core.info(`Executing: ${this.binaryPath} ${args.join(' ')}`);

    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';

      const proc: ChildProcess = spawn(this.binaryPath!, args, {
        env: {
          ...process.env,
          QUALYS_ACCESS_TOKEN: this.accessToken!,
        },
      });

      proc.stdout?.on('data', (data) => {
        const text = data.toString();
        stdout += text;
        process.stdout.write(text);
      });

      proc.stderr?.on('data', (data) => {
        const text = data.toString();
        stderr += text;
        process.stderr.write(text);
      });

      proc.on('close', (code) => {
        const exitCode = code ?? 1;
        const result = this.buildResult(exitCode, resultOutputDir, stdout, stderr);
        resolve(result);
      });

      proc.on('error', (err) => {
        reject(new Error(`Failed to execute QScanner: ${err.message}`));
      });
    });
  }

  private buildResult(
    exitCode: number,
    outputDir: string,
    stdout: string,
    stderr: string
  ): QScannerResult {
    let policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE' = 'NONE';
    if (exitCode === QScannerExitCode.SUCCESS) {
      policyResult = 'ALLOW';
    } else if (exitCode === QScannerExitCode.POLICY_EVALUATION_DENY) {
      policyResult = 'DENY';
    } else if (exitCode === QScannerExitCode.POLICY_EVALUATION_AUDIT) {
      policyResult = 'AUDIT';
    }

    let scanResultFile: string | undefined;
    let reportFile: string | undefined;

    if (fs.existsSync(outputDir)) {
      const files = fs.readdirSync(outputDir);
      for (const file of files) {
        if (file.endsWith('-ScanResult.json')) {
          scanResultFile = path.join(outputDir, file);
        } else if (file.endsWith('-Report.sarif.json')) {
          reportFile = path.join(outputDir, file);
        }
      }
    }

    return {
      exitCode,
      success: exitCode === QScannerExitCode.SUCCESS,
      policyResult,
      outputDir,
      scanResultFile,
      reportFile,
      stdout,
      stderr,
    };
  }

  private getPlatform(): string {
    const platform = os.platform();
    switch (platform) {
      case 'linux':
        return 'linux';
      case 'darwin':
        return 'darwin';
      case 'win32':
        return 'windows';
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  private getArchitecture(): string {
    const arch = os.arch();
    switch (arch) {
      case 'x64':
        return 'amd64';
      case 'arm64':
        return 'arm64';
      default:
        throw new Error(`Unsupported architecture: ${arch}`);
    }
  }

  private downloadFile(url: string, destPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!url.startsWith('https://')) {
        reject(new Error('Security error: Only HTTPS URLs are allowed for downloads'));
        return;
      }

      const file = fs.createWriteStream(destPath);

      https
        .get(url, (response) => {
          if (response.statusCode === 301 || response.statusCode === 302) {
            const redirectUrl = response.headers.location;
            if (redirectUrl) {
              if (!redirectUrl.startsWith('https://')) {
                file.close();
                fs.unlinkSync(destPath);
                reject(new Error('Security error: Redirect to non-HTTPS URL blocked'));
                return;
              }
              file.close();
              fs.unlinkSync(destPath);
              this.downloadFile(redirectUrl, destPath).then(resolve).catch(reject);
              return;
            }
          }

          if (response.statusCode !== 200) {
            reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
            return;
          }

          response.pipe(file);
          file.on('finish', () => {
            file.close();
            resolve();
          });
        })
        .on('error', (err) => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
    });
  }
}

export default QScannerRunner;
