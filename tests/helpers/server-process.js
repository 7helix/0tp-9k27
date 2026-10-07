// Starts bin/server.js as a real child process for tests.
import { spawn } from 'node:child_process';

// Resolves once both startup lines have been printed (they can arrive in separate chunks).
const READY = /listening on :(\d+)[\s\S]*auth: .*\n/;

export function startServer(env, { timeoutMs = 8000 } = {}) {
  const child = spawn(process.execPath, ['bin/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  const exited = new Promise((resolve) => child.on('exit', resolve));

  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start: ${stdout} ${stderr}`)), timeoutMs);
    child.stdout.on('data', () => {
      const match = READY.exec(stdout);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    child.on('exit', (code) => reject(new Error(`server exited ${code}: ${stderr}`)));
  });

  return {
    ready,
    output: () => stdout,
    async stop() {
      child.kill('SIGTERM');
      await exited;
    },
  };
}

// For configs the server should refuse. If a safeguard is broken the server would keep running, so
// we only wait a bounded time and report that case instead of hanging the test run.
export async function expectStartupFailure(env, { timeoutMs = 6000 } = {}) {
  const child = spawn(process.execPath, ['bin/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  const exitCode = await Promise.race([
    new Promise((resolve) => child.on('exit', resolve)),
    new Promise((resolve) => setTimeout(() => {
      child.kill('SIGKILL');
      resolve('server kept running');
    }, timeoutMs)),
  ]);

  return { exitCode, stderr };
}
