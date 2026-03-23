export interface Rule {
    pattern: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    fileTypes?: string[];
}
export interface Finding {
    file: string;
    line: number;
    pattern: string;
    description: string;
    severity: Rule['severity'];
}
export declare class Scanner {
    private repoPath;
    private rulesDir?;
    private findings;
    private rules;
    constructor(repoPath: string, rulesDir?: string | undefined);
    scan(): Promise<Finding[]>;
    private loadRules;
    private scanDirectory;
    private scanFile;
}
//# sourceMappingURL=scanner.d.ts.map