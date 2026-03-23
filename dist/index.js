import { Command } from 'commander';
import simpleGit from 'simple-git';
import path from 'path';
import fs from 'fs';
import chalk from 'chalk';
import { Scanner } from './scanner.js';
import { Sandbox } from './sandbox.js';
const program = new Command();
const git = simpleGit();
program
    .name('git-sentinel')
    .description('A security scanner for Git repositories that detects BiDi attacks and malicious patterns.')
    .version('1.0.0');
program
    .command('scan')
    .description('Scan a repository for malicious code patterns.')
    .argument('<url-or-path>', 'URL to a git repository or local path.')
    .option('-s, --run-script <script>', 'Execute a script from the repository in a sandbox.')
    .action(async (target, options) => {
    let repoPath = target;
    // Handle remote URLs
    if (target.startsWith('http') || target.startsWith('git@')) {
        const tempDir = path.join(process.cwd(), 'data/repos', Date.now().toString());
        console.log(chalk.blue(`Cloning ${target} to ${tempDir}...`));
        await fs.promises.mkdir(tempDir, { recursive: true });
        await git.clone(target, tempDir, ['--depth', '1']);
        repoPath = tempDir;
    }
    else {
        repoPath = path.resolve(target);
    }
    if (!fs.existsSync(repoPath)) {
        console.error(chalk.red(`Error: Path ${repoPath} does not exist.`));
        process.exit(1);
    }
    console.log(chalk.bold.green(`Scanning ${repoPath}...`));
    const scanner = new Scanner(repoPath);
    const findings = await scanner.scan();
    if (findings.length === 0) {
        console.log(chalk.green('No suspicious patterns found.'));
    }
    else {
        console.log(chalk.bold.red(`Found ${findings.length} potential issues:`));
        for (const finding of findings) {
            console.log(chalk.yellow(`
[${finding.severity.toUpperCase()}] ${finding.description}`));
            console.log(chalk.dim(`  File: ${finding.file}:${finding.line}`));
            console.log(chalk.dim(`  Pattern: ${finding.pattern}`));
        }
    }
    // Execute script in sandbox if requested
    if (options.runScript) {
        console.log(chalk.bold.cyan(`
Executing ${options.runScript} in an isolated sandbox...`));
        const sandbox = new Sandbox();
        try {
            const result = await sandbox.execute(repoPath, options.runScript);
            console.log(chalk.cyan('Sandbox Output:'));
            console.log(result.stdout);
            if (result.exitCode !== 0) {
                console.log(chalk.red(`Execution failed with code ${result.exitCode}`));
            }
            else {
                console.log(chalk.green('Execution completed successfully in the sandbox.'));
            }
        }
        catch (err) {
            console.error(chalk.red(`Sandbox Error: ${err.message}`));
        }
    }
});
program.parse(process.argv);
//# sourceMappingURL=index.js.map