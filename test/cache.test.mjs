// End-to-end tests for the hermetic `--cache` store: fetch from a registry,
// persist bundles and the trust root, replay offline, and never turn a missing
// or corrupt cache entry into a pass.

import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'provenance-gate.js');
const lockfile = path.join(root, 'test', 'fixtures', 'offline', 'package-lock.json');
const fixtureTrustRoot = path.join(root, 'test', 'fixtures', 'bundles', 'trust-root.json');
const fixtureBundle = path.join(root, 'test', 'fixtures', 'bundles', 'acme_widget@1.2.3.json');

function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

function receiptOf(result) {
  assert.equal(result.signal, null, result.stderr);
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    assert.fail(`stdout is not JSON: ${error.message}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }
}

function rowFor(receipt, packageName) {
  const rows = receipt.packages.filter((item) => item.package === packageName);
  assert.equal(rows.length, 1, JSON.stringify(receipt.packages, null, 2));
  return rows[0];
}

function tempDir() {
  return mkdtempSync(path.join(os.tmpdir(), 'provenance-gate-cache-'));
}

function writePolicy(file, { registry, trustRoot } = {}) {
  const policy = {
    mode: 'allowlist',
    sourceRepository: 'https://github.com/acme/widget',
    workflow: '.github/workflows/release.yml',
    allowlist: [{ name: '@acme/widget', version: '1.2.3' }],
  };
  if (registry) policy.registry = registry;
  if (trustRoot) policy.trustRoot = trustRoot;
  writeFileSync(file, `${JSON.stringify(policy, null, 2)}\n`);
  return file;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}

function attestationDocument() {
  return {
    attestations: [
      {
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: JSON.parse(readFileSync(fixtureBundle, 'utf8')),
      },
    ],
  };
}

test('a registry fetch writes bundles and the trust root, then replays hermetically offline', async () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'cache');
  const policyFile = writePolicy(path.join(dir, 'policy.json'));
  const document = attestationDocument();
  const requests = [];
  const server = http.createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    requests.push(pathname);
    if (pathname.startsWith('/-/npm/v1/attestations/')) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(document));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end('{"error":"not found"}');
  });
  const registry = await listen(server);

  try {
    const first = await runCli([
      'check',
      lockfile,
      '--policy',
      policyFile,
      '--cache',
      cacheDir,
      '--registry',
      registry,
      '--trust-root',
      fixtureTrustRoot,
      '--json',
    ]);
    assert.equal(first.status, 0, first.stderr);
    const firstReceipt = receiptOf(first);
    const firstWidget = rowFor(firstReceipt, '@acme/widget');
    assert.equal(firstWidget.status, 'verified');
    assert.equal(firstWidget.verified, true);
    assert.equal(firstWidget.fromCache, false);
    assert.ok(requests.length >= 1);
    assert.match(requests[0], /\/-\/npm\/v1\/attestations\//u);

    const cachedBundle = path.join(cacheDir, 'acme_widget@1.2.3.json');
    assert.ok(existsSync(cachedBundle), 'the fetched bundle is written to the cache');
    const cachedDocument = JSON.parse(readFileSync(cachedBundle, 'utf8'));
    assert.equal(cachedDocument.attestations.length, 1);
    assert.ok(cachedDocument.attestations[0].bundle.verificationMaterial);
    assert.ok(existsSync(path.join(cacheDir, 'trusted-root.json')), 'the trust root is written to the cache');

    await close(server);

    const second = await runCli(['check', lockfile, '--policy', policyFile, '--cache', cacheDir, '--offline', '--json']);
    assert.equal(second.status, 0, second.stderr);
    const secondReceipt = receiptOf(second);
    const secondWidget = rowFor(secondReceipt, '@acme/widget');
    assert.equal(secondReceipt.offline, true);
    assert.equal(secondWidget.status, 'verified');
    assert.equal(secondWidget.verified, true);
    assert.equal(secondWidget.fromCache, true);
    for (const key of ['package', 'version', 'integrity', 'commit', 'sourceRepository', 'workflow', 'reason']) {
      assert.deepEqual(secondWidget[key], firstWidget[key], `offline replay changed ${key}`);
    }
    assert.deepEqual(secondReceipt.summary, firstReceipt.summary);
  } finally {
    await close(server).catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a cache entry that is not valid JSON is a verification error, not a pass', async () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'cache');
  const policyFile = writePolicy(path.join(dir, 'policy.json'));
  mkdirSync(cacheDir, { recursive: true });
  copyFileSync(fixtureTrustRoot, path.join(cacheDir, 'trusted-root.json'));
  const bundleFile = path.join(cacheDir, 'acme_widget@1.2.3.json');

  try {
    writeFileSync(bundleFile, '{ this is not json\n');
    const corrupt = await runCli(['check', lockfile, '--policy', policyFile, '--cache', cacheDir, '--offline', '--json']);
    assert.equal(corrupt.status, 2, corrupt.stderr);
    const corruptReceipt = receiptOf(corrupt);
    assert.equal(corruptReceipt.ok, false);
    const corruptWidget = rowFor(corruptReceipt, '@acme/widget');
    assert.equal(corruptWidget.status, 'error');
    assert.equal(corruptWidget.verified, false);
    assert.match(corruptWidget.reason, /cannot parse cached attestation/u);

    writeFileSync(bundleFile, '{}\n');
    const wrongShape = await runCli([
      'check',
      lockfile,
      '--policy',
      policyFile,
      '--cache',
      cacheDir,
      '--offline',
      '--json',
    ]);
    assert.equal(wrongShape.status, 2, wrongShape.stderr);
    const wrongReceipt = receiptOf(wrongShape);
    const wrongWidget = rowFor(wrongReceipt, '@acme/widget');
    assert.equal(wrongWidget.status, 'error');
    assert.equal(wrongWidget.verified, false);
    assert.match(wrongWidget.reason, /not an npm attestation document/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt cached trust root is an error and does not fall back silently', async () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'cache');
  const policyFile = writePolicy(path.join(dir, 'policy.json'));
  mkdirSync(cacheDir, { recursive: true });
  copyFileSync(fixtureBundle, path.join(cacheDir, 'acme_widget@1.2.3.json'));
  writeFileSync(path.join(cacheDir, 'trusted-root.json'), '{ not a trust root\n');

  try {
    const result = await runCli(['check', lockfile, '--policy', policyFile, '--cache', cacheDir, '--offline', '--json']);
    assert.equal(result.status, 2, result.stderr);
    const receipt = receiptOf(result);
    assert.equal(receipt.ok, false);
    assert.equal(receipt.packages.length, 0);
    assert.match(receipt.error, /cannot parse trust root/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a required bundle missing from the cache exits non-zero without touching the registry', async () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'cache');
  const policyFile = writePolicy(path.join(dir, 'policy.json'));
  mkdirSync(cacheDir, { recursive: true });
  copyFileSync(fixtureTrustRoot, path.join(cacheDir, 'trusted-root.json'));
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(attestationDocument()));
  });
  const registry = await listen(server);

  try {
    const result = await runCli([
      'check',
      lockfile,
      '--policy',
      policyFile,
      '--cache',
      cacheDir,
      '--registry',
      registry,
      '--offline',
      '--json',
    ]);
    assert.equal(result.status, 1, result.stderr);
    const receipt = receiptOf(result);
    assert.equal(receipt.ok, false);
    const widget = rowFor(receipt, '@acme/widget');
    assert.equal(widget.status, 'missing');
    assert.equal(widget.verified, false);
    assert.match(widget.reason, /no cached attestation bundle for @acme\/widget@1\.2\.3/u);
    assert.deepEqual(requests, [], '--offline must never contact the registry');
  } finally {
    await close(server).catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a registry error during a cache fill is an error, not a missing attestation', async () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'cache');
  const policyFile = writePolicy(path.join(dir, 'policy.json'));
  const server = http.createServer((request, response) => {
    response.writeHead(500, { 'content-type': 'application/json' });
    response.end('{"error":"boom"}');
  });
  const registry = await listen(server);
  writePolicy(policyFile, { registry });

  try {
    const result = await runCli([
      'check',
      lockfile,
      '--policy',
      policyFile,
      '--cache',
      cacheDir,
      '--trust-root',
      fixtureTrustRoot,
      '--json',
    ]);
    assert.equal(result.status, 2, result.stderr);
    const receipt = receiptOf(result);
    assert.equal(receipt.ok, false);
    const widget = rowFor(receipt, '@acme/widget');
    assert.equal(widget.status, 'error');
    assert.equal(widget.verified, false);
    assert.match(widget.reason, /registry answered 500/u);
    assert.ok(!existsSync(path.join(cacheDir, 'acme_widget@1.2.3.json')));
  } finally {
    await close(server).catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a registry that only advertises bundles in the packument still fills the cache', async () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'cache');
  const policyFile = writePolicy(path.join(dir, 'policy.json'));
  const document = attestationDocument();
  const requests = [];
  const server = http.createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    requests.push(pathname);
    if (pathname.startsWith('/-/npm/v1/attestations/')) {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end('{"error":"not found"}');
      return;
    }
    if (pathname === '/@acme/widget') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(
        JSON.stringify({
          versions: {
            '1.2.3': { dist: { attestations: { url: '/custom/attestation.json' } } },
          },
        }),
      );
      return;
    }
    if (pathname === '/custom/attestation.json') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(document));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end('{"error":"not found"}');
  });
  const registry = await listen(server);
  writePolicy(policyFile, { registry });

  try {
    const first = await runCli([
      'check',
      lockfile,
      '--policy',
      policyFile,
      '--cache',
      cacheDir,
      '--trust-root',
      fixtureTrustRoot,
      '--json',
    ]);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(rowFor(receiptOf(first), '@acme/widget').status, 'verified');
    assert.deepEqual(requests, [
      '/-/npm/v1/attestations/@acme/widget@1.2.3',
      '/@acme/widget',
      '/custom/attestation.json',
    ]);

    await close(server);
    const second = await runCli(['check', lockfile, '--policy', policyFile, '--cache', cacheDir, '--offline', '--json']);
    assert.equal(second.status, 0, second.stderr);
    assert.equal(rowFor(receiptOf(second), '@acme/widget').status, 'verified');
  } finally {
    await close(server).catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
});
