import Docker from 'dockerode';
import path from 'path';
import fs from 'fs';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const IMAGE_NAME = 'git-sentinel-sandbox';
export class Sandbox {
    docker;
    constructor() {
        this.docker = new Docker();
    }
    /**
     * Builds the sandbox image if it doesn't exist.
     */
    async buildImage() {
        const images = (await this.docker.listImages());
        if (images.some(img => img.RepoTags?.includes(`${IMAGE_NAME}:latest`))) {
            return;
        }
        console.log('Building sandbox image...');
        const dockerfilePath = path.join(__dirname, '../data/sandbox/Dockerfile');
        const contextDir = path.dirname(dockerfilePath);
        return new Promise((resolve, reject) => {
            // Using child_process.spawn for easier build context handling
            const build = spawn('docker', ['build', '-t', IMAGE_NAME, contextDir]);
            build.stdout.on('data', (data) => console.log(data.toString()));
            build.stderr.on('data', (data) => console.error(data.toString()));
            build.on('close', (code) => {
                if (code === 0)
                    resolve();
                else
                    reject(new Error(`Docker build failed with code ${code}`));
            });
        });
    }
    /**
     * Executes a command in the sandbox.
     * @param repoPath Absolute path to the repository on the host.
     * @param command The command to execute (e.g., './configure').
     * @returns stdout and stderr.
     */
    async execute(repoPath, command) {
        await this.buildImage();
        const container = await this.docker.createContainer({
            Image: IMAGE_NAME,
            Cmd: ['/bin/sh', '-c', command],
            HostConfig: {
                Binds: [`${repoPath}:/repo:ro`], // Read-only mount
                NetworkMode: 'none', // NO NETWORK
                Memory: 512 * 1024 * 1024, // 512MB
                NanoCpus: 500000000, // 0.5 CPU
            },
            WorkingDir: '/repo',
            Tty: false,
        });
        await container.start();
        // Wait for the container to finish
        const result = await container.wait();
        // Get logs
        const logs = await container.logs({ stdout: true, stderr: true });
        // Dockerode logs are multiplexed, let's simplify for now
        const output = logs.toString('utf-8');
        await container.remove();
        return {
            stdout: output,
            stderr: '', // Docker logs are combined here for simplicity
            exitCode: result.StatusCode,
        };
    }
}
//# sourceMappingURL=sandbox.js.map