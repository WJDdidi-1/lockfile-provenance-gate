import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { test } from 'node:test';

import { parseLockfile } from '../lib/lockfile.js';
import { validatePolicy } from '../lib/policy.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'provenance-gate.js');

function fixture(name, file) {
  return path.join(root, 'test', 'fixtures', name, file);
}

function runCheck(name, extra = []) {
  return spawnSync(
    process.execPath,
    [
      bin,
      'check',
      fixture(name, 'package-lock.json'),
      '--policy',
      fixture(name, 'policy.json'),
      '--offline',
      ...extra,
    ],
    { encoding: 'utf8', timeout: 20000 },
  );
}

function packageRows(stdout, packageName) {
  return stdout
    .split('\n')
    .filter((line) => line.includes(packageName) && !line.startsWith('PACKAGE'));
}

test('offline check prints the required row and exits 2 when it cannot verify', () => {
  const result = runCheck('offline');
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stdout, /^PACKAGE\s+VERSION\s+INTEGRITY\s+STATUS$/mu);

  const rows = packageRows(result.stdout, '@acme/widget');
  assert.equal(rows.length, 1, result.stdout);
  assert.match(rows[0], /@acme\/widget/u);
  assert.match(rows[0], /\b1\.2\.3\b/u);
  assert.match(rows[0], /sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==/u);
  assert.match(rows[0], /\bunverified$/u);
  assert.match(result.stdout, /1 required, 0 verified, 1 unverified, 0 missing, 0 mismatch/u);
});

test('a policy pin that does not match the lockfile exits 1 with mismatch', () => {
  const result = runCheck('mismatch');
  assert.equal(result.status, 1, result.stderr);

  const rows = packageRows(result.stdout, 'pinned');
  assert.equal(rows.length, 1, result.stdout);
  assert.match(rows[0], /\b2\.0\.0\b/u);
  assert.match(rows[0], /\bmismatch$/u);
  assert.match(result.stdout, /1 required, 0 verified, 0 unverified, 0 missing, 1 mismatch/u);
});

test('a policy package absent from the lockfile exits 1 with missing', () => {
  const result = runCheck('missing');
  assert.equal(result.status, 1, result.stderr);

  const beta = packageRows(result.stdout, 'beta');
  assert.equal(beta.length, 1, result.stdout);
  assert.match(beta[0], /\b0\.9\.0\b/u);
  assert.match(beta[0], /\bmissing$/u);

  const alpha = packageRows(result.stdout, 'alpha');
  assert.equal(alpha.length, 1, result.stdout);
  assert.match(alpha[0], /\bunverified$/u);
  assert.match(result.stdout, /2 required, 0 verified, 1 unverified, 1 missing, 0 mismatch/u);
});

test('--json emits schemaVersion 1 and the same rows', () => {
  const result = runCheck('offline', ['--json']);
  assert.equal(result.status, 2, result.stderr);

  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.ok, false);
  assert.equal(receipt.exitCode, 2);
  assert.equal(receipt.packages.length, 1);
  assert.deepEqual(
    Object.keys(receipt.packages[0]).sort(),
    ['integrity', 'package', 'reason', 'status', 'version'],
  );
  assert.equal(receipt.packages[0].package, '@acme/widget');
  assert.equal(receipt.packages[0].version, '1.2.3');
  assert.equal(receipt.packages[0].status, 'unverified');
  assert.equal(
    receipt.packages[0].integrity,
    'sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==',
  );
  assert.deepEqual(receipt.summary, {
    required: 1,
    verified: 0,
    unverified: 1,
    missing: 0,
    mismatch: 0,
    exempt: 0,
  });
});

test('an empty requirement set exits 0', () => {
  const result = runCheck('empty');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /0 required, 0 verified, 0 unverified, 0 missing, 0 mismatch/u);
});

test('exempted requirements exit 0 and are not printed as verdict rows', () => {
  const result = runCheck('exempt', ['--json']);
  assert.equal(result.status, 0, result.stderr);

  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.packages.length, 0);
  assert.equal(receipt.summary.exempt, 1);
});

test('package-lock v3 parsing handles scoped and nested packages and skips links', () => {
  const parsed = parseLockfile({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root', version: '1.0.0' },
      'node_modules/foo': { version: '1.0.0', integrity: 'sha512-AAAA' },
      'node_modules/foo/node_modules/@scope/bar': { version: '2.0.0', integrity: 'sha512-BBBB' },
      'node_modules/linked': { version: '1.0.0', link: true, resolved: '../linked' },
      'packages/workspace': { name: 'workspace', version: '1.0.0' },
    },
  });
  assert.deepEqual(
    parsed.entries.map((entry) => `${entry.name}@${entry.version}`),
    ['@scope/bar@2.0.0', 'foo@1.0.0'],
  );
});

test('policy aliases and explicit integrity pins are accepted', () => {
  const policy = validatePolicy({
    require: {
      packages: {
        'left-pad': {
          version: '1.3.0',
          integrity: 'sha512-X03fT4hPQbJ7CwZ2F7l4A8Qm3QYB8z5tQf3nQw7w6j0K1J2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a8b9c0d1e2f==',
        },
      },
    },
    expected: {
      repository: 'git+https://github.com/stevemao/left-pad.git',
      workflow: '.github/workflows/release.yml',
    },
  });
  assert.equal(policy.mode, 'allowlist');
  assert.equal(policy.allowlist.length, 1);
  assert.equal(policy.allowlist[0].name, 'left-pad');
  assert.equal(policy.allowlist[0].version, '1.3.0');
  assert.match(policy.allowlist[0].integrity, /^sha512-/u);
  assert.equal(policy.repository, 'github.com/stevemao/left-pad');
  assert.equal(policy.workflow, '.github/workflows/release.yml');
});

test('a policy cannot silently require nothing or exempt a package without a reason', () => {
  assert.throws(
    () => validatePolicy({ mode: 'allowlist', allowlist: [] }),
    /allowlist is empty/u,
  );
  assert.throws(
    () => validatePolicy({ mode: 'all', exemptions: ['left-pad'] }),
    /must include a reason/u,
  );
});
