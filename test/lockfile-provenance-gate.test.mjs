import { test } from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'lockfile-provenance-gate.mjs');
const aliasLockfile = path.join(root, 'test', 'fixtures', 'alias', 'package-lock.json');
const aliasPolicy = path.join(root, 'test', 'fixtures', 'alias', 'policy.json');
const bundles = path.join(root, 'test', 'fixtures', 'bundles');

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

test('the packed tarball installs cleanly and its CLI verifies an aliased lockfile', () => {
  const workDir = mkdtempSync(path.join(os.tmpdir(), 'provenance-gate-pack-'));
  const packDir = path.join(workDir, 'pack');
  const installDir = path.join(workDir, 'install');
  const cacheDir = path.join(workDir, 'npm-cache');
  mkdirSync(packDir);
  mkdirSync(installDir);
  try {
    const packed = runNpm(['pack', '--silent', '--pack-destination', packDir], {
      cwd: root,
      env: { ...process.env, npm_config_cache: cacheDir },
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
      { cwd: installDir, env: { ...process.env, npm_config_cache: cacheDir } },
    );
    if (installed.error) throw installed.error;
    if (installed.status !== 0) {
      throw new Error(`npm install failed (${installed.status}):\n${installed.stdout}\n${installed.stderr}`);
    }
    if (!existsSync(installedCli(installDir))) {
      throw new Error('the packed tarball did not install the provenance-gate CLI');
    }

    const env = { ...process.env, npm_config_cache: cacheDir };
    const verify = spawnSync(
      process.execPath,
      [installedCli(installDir), 'check', aliasLockfile, '--policy', aliasPolicy, '--cache', bundles, '--offline', '--json'],
      { encoding: 'utf8', timeout: 20000, env },
    );
    if (verify.error) throw verify.error;
    if (verify.status !== 0) {
      throw new Error(`installed CLI did not verify the alias (${verify.status}):\n${verify.stdout}\n${verify.stderr}`);
    }
    const verified = receiptOf(verify);
    const widget = verified.packages.find((item) => item.package === '@acme/widget');
    if (!widget || widget.status !== 'verified' || widget.verified !== true) {
      throw new Error(`installed CLI did not verify @acme/widget:\n${verify.stdout}`);
    }

    // A tampered integrity hash is still a policy failure (exit 1), not a pass
    // and not an execution error.
    const tamperedLockfile = path.join(workDir, 'package-lock.json');
    const lockfileData = JSON.parse(readFileSync(aliasLockfile, 'utf8'));
    lockfileData.packages['node_modules/widget'].integrity = lockfileData.packages[
      'node_modules/widget'
    ].integrity.replace('W3ZD', 'AAAA');
    writeFileSync(tamperedLockfile, `${JSON.stringify(lockfileData, null, 2)}\n`);

    const mismatch = spawnSync(
      process.execPath,
      [
        installedCli(installDir),
        'check',
        tamperedLockfile,
        '--policy',
        aliasPolicy,
        '--cache',
        bundles,
        '--offline',
        '--json',
      ],
      { encoding: 'utf8', timeout: 20000, env },
    );
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
