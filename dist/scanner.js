import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069]/;
const SUSPICIOUS_PATTERNS = [
    // Reverse Shells
    { pattern: /sh -i/i, description: 'Interactive shell (sh -i)' },
    { pattern: /bash -i/i, description: 'Interactive shell (bash -i)' },
    { pattern: /nc -e/i, description: 'Netcat reverse shell' },
    { pattern: /nc\s+.*-l\s+-p\s+\d+/i, description: 'Netcat listener' },
    { pattern: /php -r.*fsockopen/i, description: 'PHP reverse shell' },
    { pattern: /python.*socket.*connect/i, description: 'Python reverse shell' },
    { pattern: /perl.*Socket.*inet_aton/i, description: 'Perl reverse shell' },
    { pattern: /ruby.*TCPSocket.new/i, description: 'Ruby reverse shell' },
    // Persistence
    { pattern: /crontab -e/i, description: 'Crontab modification' },
    { pattern: /systemctl.*enable/i, description: 'Systemd service enable' },
    { pattern: /cp.*\/etc\/init\.d/i, description: 'Initialization script modification' },
    // Tunnelling/Networking
    { pattern: /ssh -D \d+/i, description: 'SSH Dynamic Port Forwarding (SOCKS)' },
    { pattern: /ssh -R \d+/i, description: 'SSH Remote Port Forwarding' },
    { pattern: /curl.*\|.*sh/i, description: 'Piping curl to shell' },
    { pattern: /wget.*-O.*\|.*bash/i, description: 'Piping wget to bash' },
    // Obfuscation/Trojan-like
    { pattern: /eval\(.*base64_decode/i, description: 'Base64 obfuscated eval' },
    { pattern: /exec\(.*base64/i, description: 'Base64 obfuscated exec' },
];
export class Scanner {
    repoPath;
    findings = [];
    constructor(repoPath) {
        this.repoPath = repoPath;
    }
    async scan() {
        this.findings = [];
        await this.scanDirectory(this.repoPath);
        return this.findings;
    }
    async scanDirectory(dir) {
        const entries = await fs.promises.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            // Skip .git
            if (entry.name === '.git')
                continue;
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
            // For simplicity, we'll only scan text files or those that look like code/scripts
            const ext = path.extname(filePath).toLowerCase();
            const textExtensions = ['.js', '.ts', '.py', '.sh', '.bash', '.pl', '.rb', '.php', '.c', '.cpp', '.h', '.go', '.rs', '.txt', '.md', '.json', '.yml', '.yaml'];
            if (!textExtensions.includes(ext) && ext !== '') {
                // Maybe it's a binary, we'll skip for now unless specifically asked
                return;
            }
            const content = await fs.promises.readFile(filePath, 'utf-8');
            const lines = content.split(', '););
            // Check for BiDi (Trojan Source)
            if (BIDI_CHARS.test(content)) {
                this.findings.push({
                    file: path.relative(this.repoPath, filePath),
                    line: 0,
                    pattern: 'BiDi (Bidirectional) Control Characters',
                    description: 'Detected Unicode control characters that can reorder code logic visually.',
                    severity: 'high',
                });
            }
            // Pattern match
            lines.forEach((line, index) => {
                for (const { pattern, description } of SUSPICIOUS_PATTERNS) {
                    if (pattern.test(line)) {
                        this.findings.push({
                            file: path.relative(this.repoPath, filePath),
                            line: index + 1,
                            pattern: pattern.toString(),
                            description,
                            severity: this.getSeverity(description),
                        });
                    }
                }
            });
        }
        catch (error) {
            // Silent fail on unreadable files (e.g., binaries incorrectly identified as text)
        }
    }
    getSeverity(description) {
        if (description.includes('shell') || description.includes('Base64'))
            return 'high';
        if (description.includes('modification') || description.includes('SSH'))
            return 'medium';
        return 'low';
    }
}
//# sourceMappingURL=scanner.js.map