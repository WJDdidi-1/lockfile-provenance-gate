import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'lockfile-provenance-gate.mjs');
const aliasLockfile = path.join(root, 'test', 'fixtures', 'alias', 'package-lock.json');
const fixtureBundle = path.join(root, 'test', 'fixtures', 'bundles', 'acme_widget@1.2.3.json');
const fixtureTrustRoot = path.join(root, 'test', 'fixtures', 'bundles', 'trust-root.json');
const packageVersion = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version;

test('--version prints the package version', () => {
  const out = execFileSync(process.execPath, [bin, '--version'], { encoding: 'utf8' });
  if (!/^\d+\.\d+\.\d+/.test(out.trim())) throw new Error('unexpected version: ' + out);
});

test('--help names the tool and the offline cache options', () => {
  const out = execFileSync(process.execPath, [bin, '--help'], { encoding: 'utf8' });
  if (!out.includes('lockfile-provenance-gate')) throw new Error('help does not name the tool');
  if (!out.includes('--cache')) throw new Error('help does not document --cache');
  if (!out.includes('--offline')) throw new Error('help does not document --offline');
});

function npmInvocation(args) {
  // Running under `npm test` gives us the exact npm entry point, which avoids
  // platform-specific .cmd shims.  Direct `node --test` falls back to npm.
  const npmCli = process.env.npm_execpath;
  if (npmCli) return { command: process.execPath, args: [npmCli, ...args] };
  return {
    command: process.platform === 'win32' ? 'npm.cmd' : 'npm',
    args,
    shell: process.platform === 'win32',
  };
}

function runNpm(args, options = {}) {
  const invocation = npmInvocation(args);
  return spawnSync(invocation.command, invocation.args, {
    encoding: 'utf8',
    timeout: 60000,
    ...options,
    ...(invocation.shell ? { shell: true } : {}),
  });
}

function installedCli(installDir) {
  return path.join(installDir, 'node_modules', 'lockfile-provenance-gate', 'bin', 'provenance-gate.js');
}

function receiptOf(result) {
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`stdout is not JSON: ${error.message}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }
}

function runGateCli(binPath, { cwd, lockfile, policy, cache, npmCache }) {
  const env = { ...process.env };
  if (npmCache) env.npm_config_cache = npmCache;
  return spawnSync(
    process.execPath,
    [binPath, 'check', lockfile, '--policy', policy, '--cache', cache, '--offline', '--json'],
    { cwd, encoding: 'utf8', timeout: 20000, env },
  );
}

function runInstalledCheck(installDir, options) {
  return runGateCli(installedCli(installDir), options);
}

// Pack the checkout and install the tarball into a clean, temporary prefix.
// Tests that exercise the installed CLI use this helper so they run against the
// published file set rather than the source tree.
function packAndInstallCli(workDir) {
  const packDir = path.join(workDir, 'pack');
  const installDir = path.join(workDir, 'install');
  const npmCache = path.join(workDir, 'npm-cache');
  mkdirSync(packDir, { recursive: true });
  mkdirSync(installDir, { recursive: true });

  const packed = runNpm(['pack', '--silent', '--pack-destination', packDir], {
    cwd: root,
    env: { ...process.env, npm_config_cache: npmCache },
  });
  if (packed.error) throw packed.error;
  if (packed.status !== 0) {
    throw new Error(`npm pack failed (${packed.status}):\n${packed.stdout}\n${packed.stderr}`);
  }
  const tarballs = readdirSync(packDir).filter((file) => file.endsWith('.tgz'));
  if (tarballs.length !== 1) throw new Error(`expected one tarball, got ${JSON.stringify(tarballs)}`);
  const tarball = path.join(packDir, tarballs[0]);

  writeFileSync(
    path.join(installDir, 'package.json'),
    `${JSON.stringify({ name: 'clean-install-probe', version: '1.0.0', private: true }, null, 2)}\n`,
  );
  const installed = runNpm(
    ['install', tarball, '--ignore-scripts', '--no-audit', '--no-fund', '--offline'],
    { cwd: installDir, env: { ...process.env, npm_config_cache: npmCache } },
  );
  if (installed.error) throw installed.error;
  if (installed.status !== 0) {
    throw new Error(`npm install failed (${installed.status}):\n${installed.stdout}\n${installed.stderr}`);
  }
  if (!existsSync(installedCli(installDir))) {
    throw new Error('the packed tarball did not install the provenance-gate CLI');
  }
  const installedVersion = execFileSync(process.execPath, [installedCli(installDir), '--version'], {
    encoding: 'utf8',
  }).trim();
  if (installedVersion !== packageVersion) {
    throw new Error(`installed CLI reports ${installedVersion}, expected ${packageVersion}`);
  }
  return { installDir, npmCache };
}

function writePolicy(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

// Write a policy whose allowlist entry names either the real published package
// or the local alias. Both spellings must select the aliased lockfile entry.
function writeAliasPolicy(file, { cacheDir, name }) {
  writeFileSync(
    file,
    `${JSON.stringify(
      {
        mode: 'allowlist',
        sourceRepository: 'https://github.com/acme/widget',
        workflow: '.github/workflows/release.yml',
        trustRoot: path.join(cacheDir, 'trust-root.json'),
        allowlist: [{ name, version: '1.2.3' }],
      },
      null,
      2,
    )}\n`,
  );
}

test('the packed tarball installs cleanly and its CLI verifies an aliased project', () => {
  const workDir = mkdtempSync(path.join(os.tmpdir(), 'provenance-gate-pack-'));
  try {
    const { installDir, npmCache } = packAndInstallCli(workDir);

    // Build the project outside the checkout: only the lockfile, its policy and
    // the offline cache the installed CLI is allowed to read.
    const projectDir = path.join(workDir, 'project');
    const cacheDir = path.join(projectDir, 'cache');
    const lockfile = path.join(projectDir, 'package-lock.json');
    mkdirSync(cacheDir, { recursive: true });
    copyFileSync(aliasLockfile, lockfile);
    copyFileSync(fixtureBundle, path.join(cacheDir, 'acme_widget@1.2.3.json'));
    copyFileSync(fixtureTrustRoot, path.join(cacheDir, 'trust-root.json'));

    const policyByRealName = path.join(projectDir, 'policy-real-name.json');
    const policyByAlias = path.join(projectDir, 'policy-alias.json');
    writeAliasPolicy(policyByRealName, { cacheDir, name: '@acme/widget' });
    writeAliasPolicy(policyByAlias, { cacheDir, name: 'widget' });

    const checkArgs = { cwd: projectDir, lockfile, cache: cacheDir, npmCache };

    const verify = runInstalledCheck(installDir, { ...checkArgs, policy: policyByRealName });
    if (verify.error) throw verify.error;
    if (verify.status !== 0) {
      throw new Error(`installed CLI did not verify the alias (${verify.status}):\n${verify.stdout}\n${verify.stderr}`);
    }
    const verified = receiptOf(verify);
    if (verified.packages.length !== 1) {
      throw new Error(`expected one verified package, got:\n${verify.stdout}`);
    }
    const widget = verified.packages.find((item) => item.package === '@acme/widget');
    if (!widget || widget.status !== 'verified' || widget.verified !== true) {
      throw new Error(`installed CLI did not verify @acme/widget:\n${verify.stdout}`);
    }

    // The policy may also use the local alias. It selects the same entry, but
    // the lookup, attestation and receipt still use the real package.
    const aliasVerify = runInstalledCheck(installDir, { ...checkArgs, policy: policyByAlias });
    if (aliasVerify.error) throw aliasVerify.error;
    if (aliasVerify.status !== 0) {
      throw new Error(
        `installed CLI did not resolve an alias-named policy (${aliasVerify.status}):\n${aliasVerify.stdout}\n${aliasVerify.stderr}`,
      );
    }
    const aliasReceipt = receiptOf(aliasVerify);
    if (aliasReceipt.packages.length !== 1) {
      throw new Error(`expected one verified package from the alias policy, got:\n${aliasVerify.stdout}`);
    }
    if (aliasReceipt.packages.some((item) => item.package !== '@acme/widget')) {
      throw new Error(`the alias policy reported the install name instead of the real package:\n${aliasVerify.stdout}`);
    }

    // A tampered integrity hash is still a policy failure (exit 1), not a pass
    // and not an execution error.
    const tamperedLockfile = path.join(projectDir, 'package-lock.tampered.json');
    const lockfileData = JSON.parse(readFileSync(lockfile, 'utf8'));
    lockfileData.packages['node_modules/widget'].integrity = lockfileData.packages[
      'node_modules/widget'
    ].integrity.replace('W3ZD', 'AAAA');
    writeFileSync(tamperedLockfile, `${JSON.stringify(lockfileData, null, 2)}\n`);

    const mismatch = runInstalledCheck(installDir, {
      ...checkArgs,
      lockfile: tamperedLockfile,
      policy: policyByRealName,
    });
    if (mismatch.error) throw mismatch.error;
    if (mismatch.status !== 1) {
      throw new Error(`tampered alias integrity should exit 1, got ${mismatch.status}:\n${mismatch.stdout}\n${mismatch.stderr}`);
    }
    const failed = receiptOf(mismatch);
    const failedWidget = failed.packages.find((item) => item.package === '@acme/widget');
    if (!failedWidget || failedWidget.status !== 'mismatch' || failedWidget.verified !== false) {
      throw new Error(`tampered alias integrity was not a mismatch:\n${mismatch.stdout}`);
    }
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
});

test('the packed tarball reports git and mixed entries as unverifiable and keeps registry-only checks green', () => {
  const workDir = mkdtempSync(path.join(os.tmpdir(), 'provenance-gate-pack-unverifiable-'));
  try {
    const { installDir, npmCache } = packAndInstallCli(workDir);

    // Only the lockfiles, policies and offline cache are visible to the
    // installed CLI; nothing under the checkout is reachable by relative path.
    const projectDir = path.join(workDir, 'project');
    const cacheDir = path.join(projectDir, 'cache');
    mkdirSync(cacheDir, { recursive: true });
    copyFileSync(fixtureBundle, path.join(cacheDir, 'acme_widget@1.2.3.json'));
    copyFileSync(fixtureTrustRoot, path.join(cacheDir, 'trust-root.json'));

    const gitOnlyLockfile = path.join(projectDir, 'git-only-lock.json');
    const gitOnlyPolicy = path.join(projectDir, 'git-only-policy.json');
    copyFileSync(
      path.join(root, 'test', 'fixtures', 'unverifiable-git', 'package-lock.json'),
      gitOnlyLockfile,
    );
    writePolicy(gitOnlyPolicy, { mode: 'all' });

    const mixedLockfile = path.join(projectDir, 'mixed-lock.json');
    const mixedPolicy = path.join(projectDir, 'mixed-policy.json');
    copyFileSync(
      path.join(root, 'test', 'fixtures', 'unverifiable-mixed', 'package-lock.json'),
      mixedLockfile,
    );
    writePolicy(mixedPolicy, {
      mode: 'all',
      sourceRepository: 'https://github.com/acme/widget',
      workflow: '.github/workflows/release.yml',
      trustRoot: path.join(cacheDir, 'trust-root.json'),
    });

    const registryLockfile = path.join(projectDir, 'registry-lock.json');
    const registryPolicy = path.join(projectDir, 'registry-policy.json');
    copyFileSync(path.join(root, 'test', 'fixtures', 'offline', 'package-lock.json'), registryLockfile);
    writePolicy(registryPolicy, {
      mode: 'allowlist',
      sourceRepository: 'https://github.com/acme/widget',
      workflow: '.github/workflows/release.yml',
      trustRoot: path.join(cacheDir, 'trust-root.json'),
      allowlist: [{ name: '@acme/widget', version: '1.2.3' }],
    });

    const exemptPolicy = path.join(projectDir, 'git-only-exempt-policy.json');
    writePolicy(exemptPolicy, {
      mode: 'all',
      exemptions: [{ package: 'loud-cron', reason: 'pinned git checkout, reviewed by hand' }],
    });

    const cases = [
      {
        label: 'git-only lockfile',
        lockfile: gitOnlyLockfile,
        policy: gitOnlyPolicy,
        expectExit: 1,
        expectSummary: {
          required: 1,
          verified: 0,
          missing: 0,
          mismatch: 0,
          unverifiable: 1,
          error: 0,
          exempt: 0,
        },
        verify(receipt) {
          assert.equal(receipt.ok, false);
          assert.equal(receipt.exitCode, 1);
          const row = receipt.packages.find((item) => item.package === 'loud-cron');
          assert.ok(row, `no loud-cron row:\n${JSON.stringify(receipt.packages, null, 2)}`);
          assert.equal(row.version, '0.1.0');
          assert.equal(row.integrity, null);
          assert.equal(row.status, 'unverifiable');
          assert.equal(row.verified, false);
          assert.equal(row.sourceType, 'git');
          assert.match(row.resolved, /^git\+ssh:\/\/git@github\.com\/WJDdidi-1\/loud-cron\.git#/u);
          assert.match(row.reason, /git dependency resolved from git\+ssh:\/\//u);
          assert.match(row.reason, /no registry integrity hash or provenance/u);
        },
      },
      {
        label: 'mixed registry and git lockfile',
        lockfile: mixedLockfile,
        policy: mixedPolicy,
        expectExit: 1,
        expectSummary: {
          required: 2,
          verified: 1,
          missing: 0,
          mismatch: 0,
          unverifiable: 1,
          error: 0,
          exempt: 0,
        },
        verify(receipt) {
          assert.equal(receipt.ok, false);
          assert.equal(receipt.exitCode, 1);
          const rows = receipt.packages.filter((item) => item.package === '@acme/widget');
          assert.equal(rows.length, 2, JSON.stringify(receipt.packages, null, 2));
          const verified = rows.find((item) => item.status === 'verified');
          const unverifiable = rows.find((item) => item.status === 'unverifiable');
          assert.equal(verified?.version, '1.2.3');
          assert.equal(verified?.verified, true);
          assert.equal(unverifiable?.version, '1.2.3');
          assert.equal(unverifiable?.verified, false);
          assert.equal(unverifiable?.sourceType, 'git');
          assert.match(unverifiable?.resolved ?? '', /^git\+ssh:\/\/git@github\.com\/acme\/widget\.git#/u);
        },
      },
      {
        label: 'registry-only control',
        lockfile: registryLockfile,
        policy: registryPolicy,
        expectExit: 0,
        expectSummary: {
          required: 1,
          verified: 1,
          missing: 0,
          mismatch: 0,
          unverifiable: 0,
          error: 0,
          exempt: 0,
        },
        verify(receipt) {
          assert.equal(receipt.ok, true);
          assert.equal(receipt.exitCode, 0);
          const row = receipt.packages.find((item) => item.package === '@acme/widget');
          assert.equal(row?.status, 'verified');
          assert.equal(row?.verified, true);
        },
      },
      {
        label: 'git-only lockfile with an exemption',
        lockfile: gitOnlyLockfile,
        policy: exemptPolicy,
        expectExit: 0,
        expectSummary: {
          required: 0,
          verified: 0,
          missing: 0,
          mismatch: 0,
          unverifiable: 0,
          error: 0,
          exempt: 1,
        },
        verify(receipt) {
          assert.equal(receipt.ok, true);
          assert.equal(receipt.exitCode, 0);
          assert.equal(receipt.packages.length, 0);
          assert.equal(receipt.summary.exempt, 1);
        },
      },
    ];

    for (const example of cases) {
      const args = {
        cwd: projectDir,
        lockfile: example.lockfile,
        policy: example.policy,
        cache: cacheDir,
        npmCache,
      };
      const installed = runInstalledCheck(installDir, args);
      const checkout = runGateCli(bin, args);
      assert.equal(installed.signal, null, installed.stderr);
      assert.equal(checkout.signal, null, checkout.stderr);
      assert.equal(
        installed.status,
        example.expectExit,
        `${example.label}: installed CLI exited ${installed.status}:\n${installed.stdout}\n${installed.stderr}`,
      );
      assert.equal(
        checkout.status,
        example.expectExit,
        `${example.label}: checkout CLI exited ${checkout.status}:\n${checkout.stdout}\n${checkout.stderr}`,
      );

      const installedReceipt = receiptOf(installed);
      const checkoutReceipt = receiptOf(checkout);
      const { generatedAt: installedAt, ...installedComparable } = installedReceipt;
      const { generatedAt: checkoutAt, ...checkoutComparable } = checkoutReceipt;
      assert.equal(typeof installedAt, 'string');
      assert.equal(typeof checkoutAt, 'string');
      assert.deepEqual(
        installedComparable,
        checkoutComparable,
        `${example.label}: the packed CLI diverged from the checkout on the same fixtures`,
      );
      assert.deepEqual(installedReceipt.summary, example.expectSummary, `${example.label}: summary`);
      example.verify(installedReceipt);
    }
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
});
