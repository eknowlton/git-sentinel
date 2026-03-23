import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069]/;
export class Scanner {
    repoPath;
    rulesDir;
    findings = [];
    rules = [];
    constructor(repoPath, rulesDir) {
        this.repoPath = repoPath;
        this.rulesDir = rulesDir;
    }
    async scan() {
        this.findings = [];
        await this.loadRules();
        await this.scanDirectory(this.repoPath);
        return this.findings;
    }
    async loadRules() {
        const defaultRulesPath = path.join(__dirname, '../data/rules');
        const searchPaths = [defaultRulesPath];
        if (this.rulesDir)
            searchPaths.push(path.resolve(this.rulesDir));
        for (const searchPath of searchPaths) {
            if (!fs.existsSync(searchPath))
                continue;
            const files = await fs.promises.readdir(searchPath);
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const content = await fs.promises.readFile(path.join(searchPath, file), 'utf-8');
                    try {
                        const loadedRules = JSON.parse(content);
                        this.rules.push(...loadedRules);
                    }
                    catch (e) {
                        console.error(chalk.red(`Failed to parse rule file ${file}: ${e.message}`));
                    }
                }
            }
        }
    }
    async scanDirectory(dir) {
        const entries = await fs.promises.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.name === '.git')
                continue;
            if (entry.name === '...' || entry.name === ' .') {
                this.findings.push({
                    file: path.relative(this.repoPath, fullPath),
                    line: 0,
                    pattern: 'Suspicious filename',
                    description: `Detected suspicious file/directory name: "${entry.name}"`,
                    severity: 'high',
                });
            }
            if (entry.isDirectory()) {
                await this.scanDirectory(fullPath);
            }
            else if (entry.isFile()) {
                await this.scanFile(fullPath);
            }
        }
    }
    async scanFile(filePath) {
        try {
            const ext = path.extname(filePath).toLowerCase();
            const textExtensions = ['.js', '.ts', '.py', '.sh', '.bash', '.pl', '.rb', '.php', '.c', '.cpp', '.h', '.go', '.rs', '.txt', '.md', '.json', '.yml', '.yaml'];
            if (!textExtensions.includes(ext) && ext !== '')
                return;
            const content = await fs.promises.readFile(filePath, 'utf-8');
            const lines = content.split('\n');
            if (BIDI_CHARS.test(content)) {
                this.findings.push({
                    file: path.relative(this.repoPath, filePath),
                    line: 0,
                    pattern: 'BiDi (Bidirectional) Control Characters',
                    description: 'Detected Unicode control characters that can reorder code logic visually.',
                    severity: 'high',
                });
            }
            lines.forEach((line, index) => {
                if (line.length > 1000) {
                    this.findings.push({
                        file: path.relative(this.repoPath, filePath),
                        line: index + 1,
                        pattern: 'Very long line',
                        description: 'Detected a line longer than 1000 characters (common in obfuscated malware).',
                        severity: 'medium',
                    });
                }
                for (const rule of this.rules) {
                    // Check file type filter
                    if (rule.fileTypes && !rule.fileTypes.includes(ext))
                        continue;
                    const regex = new RegExp(rule.pattern, 'i');
                    if (regex.test(line)) {
                        this.findings.push({
                            file: path.relative(this.repoPath, filePath),
                            line: index + 1,
                            pattern: rule.pattern,
                            description: rule.description,
                            severity: rule.severity,
                        });
                    }
                }
            });
        }
        catch (error) {
            // Ignore
        }
    }
}
//# sourceMappingURL=scanner.js.map