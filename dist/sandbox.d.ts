export declare class Sandbox {
    private docker;
    constructor();
    /**
     * Builds the sandbox image if it doesn't exist.
     */
    buildImage(): Promise<void>;
    /**
     * Executes a command in the sandbox.
     * @param repoPath Absolute path to the repository on the host.
     * @param command The command to execute (e.g., './configure').
     * @returns stdout and stderr.
     */
    execute(repoPath: string, command: string): Promise<{
        stdout: string;
        stderr: string;
        exitCode: number;
    }>;
}
//# sourceMappingURL=sandbox.d.ts.map