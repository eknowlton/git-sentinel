# Git Sentinel

Git Sentinel is a powerful security scanner designed to analyze Git repositories for malicious code patterns, BiDi (bidirectional) attacks, and obfuscated malware. It helps developers and security researchers safely inspect untrusted repositories before running scripts or including them in their projects.

## Features

- **Repository Scanning**: Scan local directories or remote Git repositories by URL.
- **BiDi Attack Detection**: Identifies Unicode control characters (BiDi) that can visually reorder code logic to hide malicious intent.
- **Pattern Matching**: Uses a robust set of predefined rules to detect reverse shells, persistence mechanisms, dropper behaviors, and obfuscation.
- **Custom Rules**: Extend the scanner with your own JSON-based rule sets.
- **Isolated Sandbox**: Safely execute repository scripts (like `./configure` or install scripts) in an isolated, non-networked Docker container.
- **Suspicious Filename Detection**: Flags files with names like `...` or ` .` commonly used by malware.
- **Obfuscation Detection**: Identifies excessively long lines and common obfuscation techniques (Base64 eval, character concatenation).

## Installation

### Prerequisites

- [Node.js](https://nodejs.org/) (v16 or higher)
- [Docker](https://www.docker.com/) (required for sandbox execution)
- [Git](https://git-scm.com/)

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/youruser/git-sentinel.git
   cd git-sentinel
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the project:
   ```bash
   npm run build
   ```

## Usage

You can run Git Sentinel directly using `ts-node` or by building and running with `node`.

### Scanning a Repository

Scan a local directory:
```bash
npm start -- scan /path/to/local/repo
```

Scan a remote repository:
```bash
npm start -- scan https://github.com/malicious/repo.git
```

### Options

| Option | Shortcut | Description |
|--------|----------|-------------|
| `--run-script <script>` | `-s` | Execute a specific script from the repo in an isolated sandbox. |
| `--rules-dir <dir>` | `-r` | Include custom JSON rule files from a specific directory. |
| `--keep-repo` | | Do not delete the cloned repository after the scan completes. |
| `--version` | `-v` | Show the version number. |
| `--help` | `-h` | Show help information. |

### Example with Sandbox

To scan a repository and safely test its `install.sh` script:
```bash
npm start -- scan https://github.com/example/repo.git -s ./install.sh
```

## Custom Rules

Custom rules are JSON files containing an array of rule objects.

Example `custom-rules/my-rules.json`:
```json
[
  {
    "pattern": "rm -rf /",
    "description": "Attempted destruction of the root directory",
    "severity": "critical"
  }
]
```

Run with custom rules:
```bash
npm start -- scan ./target-repo -r ./custom-rules
```

## How the Sandbox Works

The sandbox uses Docker to create an isolated environment with the following constraints:
- **No Network**: The container has no internet access (`--network none`).
- **Read-Only Mount**: The repository is mounted as read-only at `/repo`.
- **Resource Limits**: Limited to 512MB RAM and 0.5 CPU core.
- **Non-Privileged User**: Scripts run as a restricted `sentinel` user.
- **Base Image**: Uses a lightweight Alpine Linux image with `bash`, `python3`, and `coreutils` pre-installed.

## License

ISC License. See `package.json` for details.
