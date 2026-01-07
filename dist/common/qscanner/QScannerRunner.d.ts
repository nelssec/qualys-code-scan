import { QScannerConfig, QScannerResult, RepoScanOptions, SarifReport, VulnerabilitySummary } from '../types';
export declare class QScannerRunner {
    private config;
    private binaryPath;
    private workDir;
    private accessToken;
    constructor(config: QScannerConfig);
    setup(): Promise<void>;
    private gunzipFile;
    private calculateSha256;
    private authenticate;
    scanRepo(options: RepoScanOptions): Promise<QScannerResult>;
    parseSarifReport(reportPath: string): {
        summary: VulnerabilitySummary;
        report: SarifReport;
    };
    getBinaryPath(): string | null;
    getWorkDir(): string;
    cleanup(): void;
    private buildCommonArgs;
    private executeQScanner;
    private buildResult;
    private getPlatform;
    private getArchitecture;
    private downloadFile;
}
export default QScannerRunner;
//# sourceMappingURL=QScannerRunner.d.ts.map