import { VulnerabilitySummary, ThresholdConfig, TaskResult } from '../types';
export declare class ThresholdEvaluator {
    private config;
    constructor(config: ThresholdConfig);
    evaluate(summary: VulnerabilitySummary): TaskResult;
}
export declare function createThresholdConfig(inputs: {
    maxCritical: string;
    maxHigh: string;
    maxMedium: string;
    maxLow: string;
}): ThresholdConfig;
//# sourceMappingURL=ThresholdEvaluator.d.ts.map