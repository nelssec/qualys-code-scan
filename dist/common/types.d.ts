export type AuthMethod = 'access-token';
export interface QScannerConfig {
    authMethod: AuthMethod;
    accessToken: string;
    pod: string;
    proxy?: string;
}
export declare const POD_GATEWAY_URLS: Record<string, string>;
export interface QScannerOptions {
    mode: 'inventory-only' | 'scan-only' | 'get-report' | 'evaluate-policy';
    scanTypes?: ('pkg' | 'secret' | 'malware' | 'fileinsight' | 'compliance')[];
    format?: ('json' | 'table' | 'spdx' | 'cyclonedx' | 'sarif')[];
    reportFormat?: ('table' | 'sarif' | 'json')[];
    outputDir?: string;
    policyTags?: string[];
    timeout?: number;
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
}
export interface RepoScanOptions extends QScannerOptions {
    scanPath: string;
    excludeDirs?: string[];
    excludeFiles?: string[];
    offlineScan?: boolean;
    showPerfStat?: boolean;
    maxNetworkRetries?: number;
    networkRetryWaitMin?: number;
    networkRetryWaitMax?: number;
}
export declare enum QScannerExitCode {
    SUCCESS = 0,
    GENERIC_ERROR = 1,
    INVALID_PARAMETER = 2,
    LOGGER_INIT_FAILED = 3,
    FILESYSTEM_ARTIFACT_FAILED = 5,
    IMAGE_ARTIFACT_FAILED = 6,
    IMAGE_ARCHIVE_ARTIFACT_FAILED = 7,
    IMAGE_STORAGE_DRIVER_ARTIFACT_FAILED = 8,
    CONTAINER_ARTIFACT_FAILED = 9,
    OTHER_ARTIFACT_FAILED = 10,
    METADATA_SCAN_FAILED = 11,
    OS_SCAN_FAILED = 12,
    SCA_SCAN_FAILED = 13,
    SECRET_SCAN_FAILED = 14,
    OS_NOT_FOUND = 15,
    MALWARE_SCAN_FAILED = 16,
    OS_NOT_SUPPORTED = 17,
    FILE_INSIGHT_SCAN_FAILED = 18,
    COMPLIANCE_SCAN_FAILED = 19,
    MANIFEST_SCAN_FAILED = 20,
    WINREGISTRY_SCAN_FAILED = 21,
    JSON_RESULT_HANDLER_FAILED = 30,
    CHANGELIST_CREATION_FAILED = 31,
    CHANGELIST_COMPRESSION_FAILED = 32,
    CHANGELIST_UPLOAD_FAILED = 33,
    SPDX_HANDLER_FAILED = 34,
    CDX_HANDLER_FAILED = 35,
    SBOM_COMPRESSION_FAILED = 36,
    SBOM_UPLOAD_FAILED = 37,
    SECRET_RESULT_CREATION_FAILED = 38,
    SECRET_RESULT_UPLOAD_FAILED = 39,
    FAILED_TO_GET_VULN_REPORT = 40,
    FAILED_TO_GET_POLICY_EVALUATION_RESULT = 41,
    POLICY_EVALUATION_DENY = 42,
    POLICY_EVALUATION_AUDIT = 43
}
export interface QScannerResult {
    exitCode: number;
    success: boolean;
    policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE';
    outputDir: string;
    scanResultFile?: string;
    reportFile?: string;
    stdout: string;
    stderr: string;
}
export interface SarifReport {
    $schema: string;
    version: string;
    runs: SarifRun[];
}
export interface SarifRun {
    tool: {
        driver: {
            name: string;
            version: string;
            rules: SarifRule[];
        };
    };
    results: SarifResult[];
}
export interface SarifRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    fullDescription?: {
        text: string;
    };
    defaultConfiguration?: {
        level: 'error' | 'warning' | 'note' | 'none';
    };
    properties?: Record<string, unknown>;
}
export interface SarifResult {
    ruleId: string;
    level: 'error' | 'warning' | 'note' | 'none';
    message: {
        text: string;
    };
    locations?: SarifLocation[];
    properties?: {
        qid?: number;
        cves?: string[];
        severity?: number;
        cvssScore?: number;
        packageName?: string;
        installedVersion?: string;
        fixedVersion?: string;
        [key: string]: unknown;
    };
}
export interface SarifLocation {
    physicalLocation?: {
        artifactLocation?: {
            uri: string;
        };
    };
    logicalLocations?: {
        name: string;
        kind: string;
    }[];
}
export interface VulnerabilitySummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
}
export interface ThresholdConfig {
    maxCritical: number;
    maxHigh: number;
    maxMedium: number;
    maxLow: number;
}
export interface TaskResult {
    passed: boolean;
    policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE';
    failureReasons: string[];
    summary: VulnerabilitySummary;
    reportPath?: string;
}
//# sourceMappingURL=types.d.ts.map