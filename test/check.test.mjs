import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { test } from 'node:test';

import { parseLockfile } from '../lib/lockfile.js';
import { validatePolicy } from '../lib/policy.js';
import { loadTrustRoot } from '../lib/trust-root.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'provenance-gate.js');
const bundles = path.join(root, 'test', 'fixtures', 'bundles');

function fixture(name, file) {
  return path.join(root, 'test', 'fixtures', name, file);
}

function runCheck(name, extra = []) {
  const args = [
    bin,
    'check',
    fixture(name, 'package-lock.json'),
    '--policy',
    fixture(name, 'policy.json'),
    '--offline',
  ];
  if (!extra.includes('--cache')) args.push('--cache', bundles);
  args.push(...extra);
  return spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 20000 });
}

function receiptOf(result) {
  assert.equal(result.signal, null, result.stderr);
  return JSON.parse(result.stdout);
}

function rowFor(receipt, packageName) {
  const rows = receipt.packages.filter((item) => item.package === packageName);
  assert.equal(rows.length, 1, JSON.stringify(receipt.packages, null, 2));
  return rows[0];
}

const WIDGET_INTEGRITY =
  'sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==';
const WIDGET_COMMIT = '1111111111111111111111111111111111111111';

test('a cached bundle whose subject and source match policy is verified offline', () => {
  const result = runCheck('offline');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^PACKAGE\s+VERSION\s+INTEGRITY\s+STATUS\s+REASON$/mu);

  const rows = result.stdout
    .split('\n')
    .filter((line) => line.includes('@acme/widget') && !line.startsWith('PACKAGE'));
  assert.equal(rows.length, 1, result.stdout);
  assert.match(rows[0], /\b1\.2\.3\b/u);
  assert.match(rows[0], /\bverified\b/u);
  assert.match(result.stdout, /1 required, 1 verified, 0 missing, 0 mismatch, 0 error/u);
});

test('the JSON receipt carries the verified provenance identity', () => {
  const result = runCheck('offline', ['--json']);
  assert.equal(result.status, 0, result.stderr);

  const receipt = receiptOf(result);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.ok, true);
  assert.equal(receipt.exitCode, 0);
  assert.equal(receipt.offline, true);

  const widget = rowFor(receipt, '@acme/widget');
  for (const key of [
    'package',
    'version',
    'commit',
    'sourceRepository',
    'workflow',
    'verified',
    'reason',
  ]) {
    assert.ok(Object.hasOwn(widget, key), `receipt row is missing ${key}`);
  }
  assert.equal(widget.package, '@acme/widget');
  assert.equal(widget.version, '1.2.3');
  assert.equal(widget.integrity, WIDGET_INTEGRITY);
  assert.equal(widget.commit, WIDGET_COMMIT);
  assert.equal(widget.sourceRepository, 'github.com/acme/widget');
  assert.equal(widget.workflow, '.github/workflows/release.yml');
  assert.equal(widget.verified, true);
  assert.equal(widget.status, 'verified');
  assert.equal(widget.reason, 'provenance verified');

  assert.deepEqual(receipt.summary, {
    required: 1,
    verified: 1,
    missing: 0,
    mismatch: 0,
    error: 0,
    exempt: 0,
  });
});

test('a bundle attesting a different source repository is a mismatch', () => {
  const result = runCheck('repo-mismatch', ['--json']);
  assert.equal(result.status, 1, result.stderr);

  const receipt = receiptOf(result);
  const beta = rowFor(receipt, 'beta');
  assert.equal(beta.status, 'mismatch');
  assert.equal(beta.verified, false);
  assert.equal(beta.sourceRepository, 'github.com/acme/beta');
  assert.match(beta.reason, /source repository github\.com\/acme\/beta does not match policy github\.com\/acme\/gamma/u);
});

test('a bundle attesting a different workflow is a mismatch', () => {
  const result = runCheck('workflow-mismatch', ['--json']);
  assert.equal(result.status, 1, result.stderr);

  const receipt = receiptOf(result);
  const gamma = rowFor(receipt, 'gamma');
  assert.equal(gamma.status, 'mismatch');
  assert.equal(gamma.verified, false);
  assert.equal(gamma.sourceRepository, 'github.com/acme/gamma');
  assert.equal(gamma.workflow, '.github/workflows/build.yml');
  assert.match(gamma.reason, /attestation workflow \.github\/workflows\/build\.yml does not match policy/u);
});

test('an attestation that does not cover the lockfile digest is a mismatch', () => {
  const result = runCheck('digest-mismatch', ['--json']);
  assert.equal(result.status, 1, result.stderr);

  const receipt = receiptOf(result);
  const widget = rowFor(receipt, '@acme/widget');
  assert.equal(widget.status, 'mismatch');
  assert.equal(widget.verified, false);
  assert.match(widget.reason, /sha512 digest .* does not match lockfile integrity/u);
});

test('a required package with no cached bundle is missing, not unverified', () => {
  const result = runCheck('missing', ['--json']);
  assert.equal(result.status, 1, result.stderr);

  const receipt = receiptOf(result);
  const alpha = rowFor(receipt, 'alpha');
  assert.equal(alpha.status, 'missing');
  assert.equal(alpha.verified, false);
  assert.match(alpha.reason, /no cached attestation bundle for alpha@1\.2\.3/u);

  const beta = rowFor(receipt, 'beta');
  assert.equal(beta.status, 'missing');
  assert.match(beta.reason, /not present in the lockfile/u);

  assert.deepEqual(receipt.summary, {
    required: 2,
    verified: 0,
    missing: 2,
    mismatch: 0,
    error: 0,
    exempt: 0,
  });
});

test('offline verification never falls back to the network when the cache is absent', () => {
  const emptyCache = path.join(root, 'test', 'fixtures', 'does-not-exist');
  const result = runCheck('offline', ['--cache', emptyCache, '--json']);
  // It reports missing promptly instead of attempting a registry fetch.
  assert.equal(result.status, 1, result.stderr);
  const receipt = receiptOf(result);
  const widget = rowFor(receipt, '@acme/widget');
  assert.equal(widget.status, 'missing');
  assert.match(widget.reason, /no cached attestation bundle/u);
});

test('a bundle with an invalid DSSE signature is a verification error', () => {
  const result = runCheck('broken', ['--json']);
  assert.equal(result.status, 2, result.stderr);

  const receipt = receiptOf(result);
  assert.equal(receipt.ok, false);
  const broken = rowFor(receipt, 'broken');
  assert.equal(broken.status, 'error');
  assert.equal(broken.verified, false);
  assert.match(broken.reason, /DSSE signature does not verify/u);
});

test('a signed publish attestation does not satisfy the provenance policy', () => {
  const result = runCheck('publish-only', ['--json']);
  assert.equal(result.status, 1, result.stderr);

  const receipt = receiptOf(result);
  const published = rowFor(receipt, 'publish-only');
  assert.equal(published.status, 'mismatch');
  assert.equal(published.verified, false);
  assert.match(published.reason, /no verifiable Sigstore provenance attestation/u);
});

test('a tampered transparency-log promise is a verification error', () => {
  const result = runCheck('tlog-broken', ['--json']);
  assert.equal(result.status, 2, result.stderr);

  const receipt = receiptOf(result);
  const broken = rowFor(receipt, 'tlog-broken');
  assert.equal(broken.status, 'error');
  assert.equal(broken.verified, false);
  assert.match(broken.reason, /signed entry timestamp .* does not verify/u);
});

test('a lockfile entry with no integrity hash is a policy mismatch', () => {
  const result = runCheck('no-integrity', ['--json']);
  assert.equal(result.status, 1, result.stderr);

  const receipt = receiptOf(result);
  const item = rowFor(receipt, 'no-integrity');
  assert.equal(item.status, 'mismatch');
  assert.equal(item.verified, false);
  assert.match(item.reason, /has no integrity hash to bind provenance to/u);
});

test('a policy integrity pin that does not match the lockfile exits 1 with mismatch', () => {
  const result = runCheck('mismatch');
  assert.equal(result.status, 1, result.stderr);

  const rows = result.stdout
    .split('\n')
    .filter((line) => line.includes('pinned') && !line.startsWith('PACKAGE'));
  assert.equal(rows.length, 1, result.stdout);
  assert.match(rows[0], /\b2\.0\.0\b/u);
  assert.match(rows[0], /\bmismatch\b/u);
  assert.match(result.stdout, /1 required, 0 verified, 0 missing, 1 mismatch, 0 error/u);
});

test('an empty requirement set exits 0', () => {
  const result = runCheck('empty');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /0 required, 0 verified, 0 missing, 0 mismatch, 0 error/u);
});

test('exempted requirements exit 0 and are not printed as verdict rows', () => {
  const result = runCheck('exempt', ['--json']);
  assert.equal(result.status, 0, result.stderr);

  const receipt = receiptOf(result);
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.packages.length, 0);
  assert.equal(receipt.summary.exempt, 1);
});

test('the bundled Sigstore trust root parses without network access', () => {
  const trustRoot = loadTrustRoot();
  assert.ok(trustRoot.roots.length > 0);
  assert.ok(trustRoot.tlogs.length > 0);
  for (const tlog of trustRoot.tlogs) assert.ok(tlog.publicKey);
});

test('an inline policy trust root is parsed without touching the filesystem', () => {
  const raw = readFileSync(path.join(bundles, 'trust-root.json'), 'utf8');
  const trustRoot = loadTrustRoot({ policyTrustRoot: raw });
  assert.equal(trustRoot.roots.length, 1);
  assert.equal(trustRoot.tlogs.length, 1);
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
  assert.throws(() => validatePolicy({ mode: 'allowlist', allowlist: [] }), /allowlist is empty/u);
  assert.throws(() => validatePolicy({ mode: 'all', exemptions: ['left-pad'] }), /must include a reason/u);
});
