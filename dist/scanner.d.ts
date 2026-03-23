export interface Finding {
    file: string;
    line: number;
    pattern: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
}
export declare class Scanner {
    private repoPath;
    private findings;
    constructor(repoPath: string);
    scan(): Promise<Finding[]>;
    private scanDirectory;
    private scanFile;
    private getSeverity;
}
//# sourceMappingURL=scanner.d.ts.map