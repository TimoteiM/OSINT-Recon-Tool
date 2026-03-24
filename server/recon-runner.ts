import { spawn, type ChildProcessWithoutNullStreams } from "child_process";
import fs from "fs";
import path from "path";

type Platform = NodeJS.Platform;

type SpawnProcess = (
  command: string,
  args: string[],
  options: {
    timeout: number;
    env: NodeJS.ProcessEnv;
  },
) => ChildProcessWithoutNullStreams;

type ResolvePythonCommandOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: Platform;
  fileExists?: (candidate: string) => boolean;
};

type RunReconOptions = ResolvePythonCommandOptions & {
  companyName: string;
  selectedSources?: string[];
  spawnProcess?: SpawnProcess;
};

export function resolvePythonCommand({
  cwd = process.cwd(),
  env = process.env,
  platform = process.platform,
  fileExists = fs.existsSync,
}: ResolvePythonCommandOptions = {}): string {
  if (env.OSINT_PYTHON_PATH) {
    return env.OSINT_PYTHON_PATH;
  }

  const localVenvCandidates =
    platform === "win32"
      ? [path.join(cwd, ".venv", "Scripts", "python.exe"), path.join(cwd, ".venv", "bin", "python")]
      : [path.join(cwd, ".venv", "bin", "python"), path.join(cwd, ".venv", "Scripts", "python.exe")];

  const configuredCandidates = [env.PYTHON].filter(
    (candidate): candidate is string => Boolean(candidate),
  );

  for (const candidate of [...configuredCandidates, ...localVenvCandidates]) {
    if (candidate && fileExists(candidate)) {
      return candidate;
    }
  }

  return platform === "win32" ? "python" : "python3";
}

export async function runRecon({
  companyName,
  selectedSources = [],
  cwd = process.cwd(),
  env = process.env,
  platform = process.platform,
  fileExists = fs.existsSync,
  spawnProcess = spawn as SpawnProcess,
}: RunReconOptions): Promise<{ data: unknown; logs: string }> {
  const scriptPath = path.resolve(cwd, "osint_engine.py");
  const pythonCommand = resolvePythonCommand({ cwd, env, platform, fileExists });
  const parsedTimeout = Number(env.RECON_TIMEOUT_MS);
  const timeout = Number.isFinite(parsedTimeout) && parsedTimeout > 0 ? parsedTimeout : 600_000;

  return await new Promise((resolve, reject) => {
    const child = spawnProcess(pythonCommand, [scriptPath, companyName], {
      timeout,
      env: {
        ...env,
        PYTHONUNBUFFERED: "1",
        OSINT_SELECTED_SOURCES: JSON.stringify(selectedSources),
      },
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    child.once("error", (error: Error) => {
      reject(error);
    });

    child.once("close", (_code: number | null, signal: NodeJS.Signals | null) => {
      const trimmedStdout = stdout.trim();
      const trimmedStderr = stderr.trim();

      if (!trimmedStdout && signal === "SIGTERM") {
        reject(
          new Error(
            JSON.stringify({
              error: "OSINT scan exceeded the configured timeout before producing JSON output",
              raw_output: "",
              logs: trimmedStderr.slice(-1000),
            }),
          ),
        );
        return;
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve({ data: parsed, logs: stderr.slice(-2000) });
      } catch {
        reject(
          new Error(
            JSON.stringify({
              error: "Failed to parse OSINT output",
              raw_output: stdout.slice(-500),
              logs: stderr.slice(-1000),
            }),
          ),
        );
      }
    });
  });
}
