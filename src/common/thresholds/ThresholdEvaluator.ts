import { VulnerabilitySummary, ThresholdConfig, TaskResult } from '../types';

export class ThresholdEvaluator {
  private config: ThresholdConfig;

  constructor(config: ThresholdConfig) {
    this.config = config;
  }

  evaluate(summary: VulnerabilitySummary): TaskResult {
    const failureReasons: string[] = [];

    if (this.config.maxCritical >= 0 && summary.critical > this.config.maxCritical) {
      failureReasons.push(
        `Found ${summary.critical} critical vulnerabilities (max allowed: ${this.config.maxCritical})`
      );
    }

    if (this.config.maxHigh >= 0 && summary.high > this.config.maxHigh) {
      failureReasons.push(
        `Found ${summary.high} high severity vulnerabilities (max allowed: ${this.config.maxHigh})`
      );
    }

    if (this.config.maxMedium >= 0 && summary.medium > this.config.maxMedium) {
      failureReasons.push(
        `Found ${summary.medium} medium severity vulnerabilities (max allowed: ${this.config.maxMedium})`
      );
    }

    if (this.config.maxLow >= 0 && summary.low > this.config.maxLow) {
      failureReasons.push(
        `Found ${summary.low} low severity vulnerabilities (max allowed: ${this.config.maxLow})`
      );
    }

    return {
      passed: failureReasons.length === 0,
      policyResult: 'NONE',
      failureReasons,
      summary,
    };
  }
}

export function createThresholdConfig(inputs: {
  maxCritical: string;
  maxHigh: string;
  maxMedium: string;
  maxLow: string;
}): ThresholdConfig {
  return {
    maxCritical: parseInt(inputs.maxCritical, 10),
    maxHigh: parseInt(inputs.maxHigh, 10),
    maxMedium: parseInt(inputs.maxMedium, 10),
    maxLow: parseInt(inputs.maxLow, 10),
  };
}
