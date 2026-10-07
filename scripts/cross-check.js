#!/usr/bin/env node
// Feeds the same random HOTP/TOTP inputs to every implementation we can run (Node, Python, Java, Go)
// and requires identical codes. The inputs include keys shorter and longer than the hash block size
// (HMAC hashes long keys first, a classic place for ports to differ), all three hashes, 6 to 10
// digits, time step boundaries, and counters past 2^32.
//
//   node scripts/cross-check.js [cases] [seed]
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { hotp, totp, base32Encode } from '../src/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'];

// small seeded generator so a failing run can be repeated
function seededRandom(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function makeCases(count = 300, seed = 0xBEEF) {
  const random = seededRandom(seed);
  const below = (max) => Math.floor(random() * max);

  const edgeTimes = [0, 29_999, 30_000, 59_999, 60_000, 1_111_111_109_000, 2_000_000_000_000, 4_102_444_799_000];
  const edgeCounters = [0, 1, 2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 40 + 12345];
  const keyLengths = [1, 10, 20, 32, 63, 64, 65, 100, 127, 128, 129, 200];

  const cases = [];
  for (let i = 0; i < count; i++) {
    const secret = Buffer.from(Array.from({ length: keyLengths[i % keyLengths.length] }, () => below(256)));
    const kind = random() < 0.5 ? 'totp' : 'hotp';

    let n;
    if (kind === 'totp') {
      n = random() < 0.3 ? edgeTimes[below(edgeTimes.length)] : below(4_100_000_000) * 1000 + below(1000);
    } else {
      n = random() < 0.3 ? edgeCounters[below(edgeCounters.length)] : below(2 ** 40);
    }

    cases.push({
      kind,
      b32: base32Encode(secret),
      secret,
      n,
      digits: 6 + below(5),
      alg: ALGORITHMS[below(ALGORITHMS.length)],
    });
  }
  return cases;
}

export function reference(c) {
  if (c.kind === 'totp') return totp(c.secret, { time: c.n, digits: c.digits, algorithm: c.alg });
  return hotp(c.secret, c.n, { digits: c.digits, algorithm: c.alg });
}

const IMPLEMENTATIONS = [
  {
    name: 'python',
    command: 'python3',
    probe: ['--version'],
    args: [path.join(root, 'ports/python/otp_fortress.py'), 'batch'],
    cwd: root,
  },
  {
    name: 'java',
    command: 'java',
    probe: ['-version'],
    args: [path.join(root, 'ports/java/OtpFortress.java'), 'batch'],
    cwd: root,
  },
  {
    name: 'go',
    command: 'go',
    probe: ['version'],
    args: ['run', './cmd/otpf', 'batch'],
    cwd: path.join(root, 'ports/go'),
  },
];

const isInstalled = (impl) => spawnSync(impl.command, impl.probe, { stdio: 'ignore' }).status === 0;

// Returns { compared, skipped, mismatches, cases }.
export function crossCheck(cases = makeCases()) {
  const input = cases.map((c) => `${c.kind} ${c.b32} ${c.n} ${c.digits} ${c.alg}`).join('\n') + '\n';
  const expected = cases.map(reference);
  const result = { compared: ['node'], skipped: [], mismatches: [], cases: cases.length };

  for (const impl of IMPLEMENTATIONS) {
    if (!isInstalled(impl)) {
      result.skipped.push(impl.name);
      continue;
    }

    const run = spawnSync(impl.command, impl.args, {
      cwd: impl.cwd,
      input,
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (run.status !== 0) {
      result.mismatches.push({ impl: impl.name, error: (run.stderr || 'non-zero exit').slice(0, 400) });
      continue;
    }

    result.compared.push(impl.name);
    const lines = run.stdout.trim().split('\n');
    if (lines.length !== cases.length) {
      result.mismatches.push({ impl: impl.name, error: `expected ${cases.length} lines, got ${lines.length}` });
      continue;
    }
    lines.forEach((got, i) => {
      if (got !== expected[i]) {
        result.mismatches.push({ impl: impl.name, case: { ...cases[i], secret: undefined }, got, want: expected[i] });
      }
    });
  }
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const count = Number(process.argv[2] || 300);
  const seed = Number(process.argv[3] || 0xBEEF);
  const result = crossCheck(makeCases(count, seed));

  console.log(
    `cases: ${result.cases} | compared: ${result.compared.join(', ')} | `
    + `skipped (toolchain missing): ${result.skipped.join(', ') || 'none'}`,
  );
  if (result.mismatches.length) {
    console.error(JSON.stringify(result.mismatches.slice(0, 5), null, 2));
    process.exit(1);
  }
  console.log('all implementations agree');
}
