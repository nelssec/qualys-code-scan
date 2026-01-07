import { SarifReport } from '../types';
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
export declare class IssueCreator {
    private octokit;
    private config;
    private owner;
    private repo;
    constructor(token: string, config: IssueConfig);
    createIssuesFromSarif(report: SarifReport, scanType: 'container' | 'code'): Promise<CreatedIssue[]>;
    private getExistingQualysIssues;
    private createIssue;
    private buildIssueBody;
    private ensureLabelsExist;
    private getVulnId;
    private getSeverityLabel;
    private getSeverityColor;
    private truncate;
}
export declare function createIssueConfig(inputs: {
    createIssues: boolean;
    minSeverity: string;
    labels: string;
    assignees: string;
}): IssueConfig;
//# sourceMappingURL=IssueCreator.d.ts.map