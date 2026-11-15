#!/usr/bin/env node
// Runs the checked-in examples offline and asserts their documented exit codes
// and verdicts.  No network access and no dependencies: this is a smoke test
// for the examples, runnable with `npm run example` from the repository root.
//
// The bundles under examples/*/cache are generated test data signed by a
// throwaway fixture PKI.  They are not real registry attestations, and the
// fixture trust root must never be used for a production policy.

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const bin = path.join(repoRoot, 'bin', 'provenance-gate.js');

const cases = [
  {
    label: 'verified example',
    dir: 'offline-check',
    packageName: '@acme/widget',
    version: '1.2.3',
    expectedExit: 0,
    expectedStatus: 'verified',
    expectedSummary: { required: 1, verified: 1, missing: 0, mismatch: 0, error: 0 },
  },
  {
    label: 'expected failure: publish attestation is not build provenance',
    dir: 'publish-only',
    packageName: 'publish-only',
    version: '1.0.0',
    expectedExit: 1,
    expectedStatus: 'mismatch',
    expectedSummary: { required: 1, verified: 0, missing: 0, mismatch: 1, error: 0 },
  },
];

function displayPath(absolute) {
  return path.relative(repoRoot, absolute).split(path.sep).join('/');
}

function fail(message) {
  console.error(`  FAIL: ${message}`);
  return false;
}

let failed = 0;
console.log('lockfile-provenance-gate runnable examples');
console.log('offline; bundles are generated test data, not real attestations');
console.log('');

for (const [index, example] of cases.entries()) {
  const dir = path.join(here, example.dir);
  const lockfile = path.join(dir, 'package-lock.json');
  const policy = path.join(dir, 'provenance.json');
  const cache = path.join(dir, 'cache');
  const command = [
    'provenance-gate',
    'check',
    displayPath(lockfile),
    '--policy',
    displayPath(policy),
    '--cache',
    displayPath(cache),
    '--offline',
  ];
  const result = spawnSync(
    process.execPath,
    [bin, ...command.slice(1), '--json'],
    { cwd: repoRoot, encoding: 'utf8' },
  );

  console.log(`${index + 1}. ${example.label}`);
  console.log(`   $ ${command.join(' ')}`);
  if (result.error) {
    failed += 1;
    console.log(`   FAIL: could not run the CLI: ${result.error.message}`);
    console.log('');
    continue;
  }
  if (result.stderr.trim() !== '') console.log(`   stderr: ${result.stderr.trim()}`);

  let receipt;
  try {
    receipt = JSON.parse(result.stdout);
  } catch {
    failed += 1;
    console.log('   FAIL: stdout was not a JSON receipt');
    console.log(`   stdout: ${result.stdout.trim()}`);
    console.log('');
    continue;
  }

  const row = receipt.packages?.[0];
  const summary = receipt.summary ?? {};
  const checks = [
    ['exit code', result.status, example.expectedExit],
    ['receipt exitCode', receipt.exitCode, example.expectedExit],
    ['receipt ok', receipt.ok, example.expectedExit === 0],
    ['receipt offline', receipt.offline, true],
    ['package', row && `${row.package}@${row.version}`, `${example.packageName}@${example.version}`],
    ['status', row?.status, example.expectedStatus],
  ];
  for (const [key, expected] of Object.entries(example.expectedSummary)) {
    checks.push([`summary.${key}`, summary[key], expected]);
  }

  const problems = checks.filter(([, actual, expected]) => actual !== expected);
  if (row) {
    console.log(`   ${row.package}@${row.version}: ${row.status} - ${row.reason}`);
  }
  console.log(
    `   summary: ${summary.required} required, ${summary.verified} verified, `
      + `${summary.missing} missing, ${summary.mismatch} mismatch, ${summary.error} error`,
  );
  console.log(`   exit: ${result.status} (expected ${example.expectedExit})`);
  if (problems.length > 0) {
    failed += 1;
    for (const [name, actual, expected] of problems) {
      console.log(`   FAIL: ${name} was ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
    }
  } else {
    console.log('   PASS');
  }
  console.log('');
}

if (failed > 0) {
  console.error(`${failed} example(s) did not behave as documented.`);
  process.exitCode = 1;
} else {
  console.log(`All ${cases.length} examples behaved as documented.`);
}
