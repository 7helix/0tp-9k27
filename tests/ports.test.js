import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { crossCheck, makeCases, reference } from '../scripts/cross-check.js';

const have = (cmd, args) => spawnSync(cmd, args, { stdio: 'ignore' }).status === 0;
const haveJava = have('java', ['-version']), haveGo = have('go', ['version']);

test('cross-check cases are well-formed and cover the awkward inputs', () => {
  const cases = makeCases(240, 7);
  assert.equal(cases.length, 240);
  assert.deepEqual(new Set(cases.map((c) => c.alg)), new Set(['SHA1', 'SHA256', 'SHA512']));
  assert.deepEqual(new Set(cases.map((c) => c.digits)), new Set([6, 7, 8, 9, 10]));
  assert.ok(
    cases.some((c) => c.secret.length > 128) && cases.some((c) => c.secret.length === 1),
    'keys longer than the SHA-512 block and tiny keys',
  );
  assert.ok(cases.some((c) => c.kind === 'hotp' && c.n >= 2 ** 32), 'counters beyond 32 bits');
  assert.ok(
    cases.every((c) => /^\d+$/.test(reference(c)) && reference(c).length === c.digits),
    'leading zeros preserved',
  );
});

test('Python, Java (and Go when installed) agree with the Node reference on 300 random cases', { timeout: 240_000 }, () => {
  const res = crossCheck(makeCases(300, 0xBEEF));
  assert.deepEqual(res.mismatches, [], JSON.stringify(res.mismatches.slice(0, 3)));
  assert.ok(res.compared.includes('python'), 'python is always available here');
  if (haveJava) assert.ok(res.compared.includes('java'));
  if (haveGo) assert.ok(res.compared.includes('go'));
});
test('a different seed also agrees (guards against a lucky sample)', { timeout: 240_000 }, () => {
  const res = crossCheck(makeCases(150, Math.floor(Math.random() * 1e9)));
  assert.deepEqual(res.mismatches, []);
});

test('Java port self-test passes (RFC vectors, window, replay, base32)', { skip: !haveJava && 'java not installed' }, () => {
  const r = spawnSync('java', ['ports/java/OtpFortress.java', 'selftest'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^OK java port/);
});
test('Java and Python batch modes reject malformed lines instead of crashing', { skip: !haveJava && 'java not installed' }, () => {
  const bad = 'nope\ntotp !!! 1 6 SHA1\ntotp GEZDGNBVGY3TQOJQ 1000 5 SHA1\ntotp GEZDGNBVGY3TQOJQ 1000 6 MD5\nhotp GEZDGNBVGY3TQOJQ -1 6 SHA1\ntotp GEZDGNBVGY3TQOJQ 59000 6 SHA1\n';
  for (const [cmd, args] of [['java', ['ports/java/OtpFortress.java', 'batch']], ['python3', ['ports/python/otp_fortress.py', 'batch']]]) {
    const r = spawnSync(cmd, args, { input: bad, encoding: 'utf8' });
    assert.equal(r.status, 0, `${cmd}: ${r.stderr}`);
    const lines = r.stdout.trim().split('\n');
    assert.deepEqual(lines.slice(0, 5), Array(5).fill('ERR'), cmd);
    assert.match(lines[5], /^\d{6}$/);
  }
});
test('Go port: go vet + go test', { skip: !haveGo && 'go not installed (CI runs this)', timeout: 180_000 }, () => {
  for (const args of [['vet', './...'], ['test', './...']]) { const r = spawnSync('go', args, { cwd: 'ports/go', encoding: 'utf8' }); assert.equal(r.status, 0, r.stdout + r.stderr); }
});
