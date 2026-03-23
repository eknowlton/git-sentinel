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
  .version('1.1.0');

program
  .command('scan')
  .description('Scan a repository for malicious code patterns.')
  .argument('<url-or-path>', 'URL to a git repository or local path.')
  .option('-s, --run-script <script>', 'Execute a script from the repository in a sandbox.')
  .option('-r, --rules-dir <dir>', 'Directory containing custom rule .json files.')
  .option('--keep-repo', 'Keep the cloned repository instead of deleting it after scan.')
  .action(async (target, options) => {
    let repoPath = target;
    let isTemp = false;

    // Robust Git URL Detection
    const isGitUrl = target.startsWith('http') || target.startsWith('git@') || target.endsWith('.git');

    if (isGitUrl) {
      const reposDir = path.join(process.cwd(), 'data/repos');
      if (!fs.existsSync(reposDir)) await fs.promises.mkdir(reposDir, { recursive: true });
      
      const repoName = target.split('/').pop()?.replace('.git', '') || Date.now().toString();
      const tempDir = path.join(reposDir, `${repoName}-${Date.now()}`);
      
      console.log(chalk.blue(`Cloning ${target} to ${tempDir}...`));
      try {
        await git.clone(target, tempDir, ['--depth', '1']);
        repoPath = tempDir;
        isTemp = true;
      } catch (err) {
        console.error(chalk.red(`Failed to clone repository: ${(err as Error).message}`));
        process.exit(1);
      }
    } else {
       repoPath = path.resolve(target);
    }

    if (!fs.existsSync(repoPath)) {
      console.error(chalk.red(`Error: Path ${repoPath} does not exist.`));
      process.exit(1);
    }

    console.log(chalk.bold.green(`Scanning ${repoPath}...`));
    const scanner = new Scanner(repoPath, options.rulesDir);
    const findings = await scanner.scan();

    if (findings.length === 0) {
      console.log(chalk.green('No suspicious patterns found.'));
    } else {
      console.log(chalk.bold.red(`Found ${findings.length} potential issues:`));
      for (const finding of findings) {
        console.log(chalk.yellow(`\n[${finding.severity.toUpperCase()}] ${finding.description}`));
        console.log(chalk.dim(`  File: ${finding.file}:${finding.line}`));
        console.log(chalk.dim(`  Pattern: ${finding.pattern}`));
      }
    }

    // Execute script in sandbox if requested
    if (options.runScript) {
      console.log(chalk.bold.cyan(`\nExecuting ${options.runScript} in an isolated sandbox...`));
      const sandbox = new Sandbox();
      try {
        const result = await sandbox.execute(repoPath, options.runScript);
        console.log(chalk.cyan('Sandbox Output:'));
        console.log(result.stdout);
        if (result.exitCode !== 0) {
          console.log(chalk.red(`Execution failed with code ${result.exitCode}`));
        } else {
          console.log(chalk.green('Execution completed successfully in the sandbox.'));
        }
      } catch (err) {
        console.error(chalk.red(`Sandbox Error: ${(err as Error).message}`));
      }
    }

    // Cleanup
    if (isTemp && !options.keepRepo) {
      console.log(chalk.dim(`Cleaning up temporary repository ${repoPath}...`));
      await fs.promises.rm(repoPath, { recursive: true, force: true });
    }
  });

program.parse(process.argv);
