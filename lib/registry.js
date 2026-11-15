// Resolve a lockfile entry to its npm attestation document.
//
// Milestone 2 deliberately has no network code: it reads attestation bundles
// from a cache directory so verification is hermetic and can run in CI while
// the registry is unreachable.  A package with no cached bundle is reported as
// missing rather than being mistaken for a package with no provenance.

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { FetchError, isNonEmptyString, isPlainObject, safePackageId } from './util.js';

function normalizeAttestations(data) {
  if (data === null || data === undefined) return [];
  let entries;
  if (Array.isArray(data)) entries = data;
  else if (Array.isArray(data.attestations)) entries = data.attestations;
  else if (isPlainObject(data.bundle)) entries = [{ predicateType: data.predicateType, bundle: data.bundle }];
  else if (isPlainObject(data.dsseEnvelope)) {
    // A bare Sigstore bundle, as written by `cosign download attestation`
    // or copied out of npm's registry response.
    entries = [{ predicateType: data.predicateType, bundle: data }];
  } else {
    entries = [];
  }

  const attestations = [];
  for (const entry of entries) {
    if (!isPlainObject(entry)) continue;
    if (isPlainObject(entry.bundle)) {
      attestations.push({ predicateType: entry.predicateType, bundle: entry.bundle });
    } else if (isPlainObject(entry.dsseEnvelope)) {
      attestations.push({ predicateType: entry.predicateType, bundle: entry });
    }
  }
  return attestations;
}

export function cacheCandidates(cacheDir, name, version) {
  const flat = `${safePackageId(name, version)}.json`;
  const encoded = `${encodeURIComponent(name)}@${encodeURIComponent(version)}.json`;
  // Older caches used a double underscore for scoped packages.  Keep reading
  // that spelling so a cache written by the previous milestone still works.
  const safeVersion = String(version).replace(/[^A-Za-z0-9._-]/gu, '_');
  const legacy = `${String(name).replace(/^@/u, '').replace(/[\\/]/gu, '__')}@${safeVersion}`;
  const candidates = [
    path.join(cacheDir, flat),
    path.join(cacheDir, encoded),
    path.join(cacheDir, `${legacy}.json`),
    path.join(cacheDir, 'bundles', flat),
    path.join(cacheDir, 'attestations', flat),
    path.join(cacheDir, 'attestations', encoded),
    path.join(cacheDir, safePackageId(name, version), 'attestation.json'),
  ];
  // A cache may mirror the npm scope as a directory: @scope/name/1.2.3.json.
  if (name.startsWith('@') && name.split('/').length === 2) {
    const scopeDir = path.join(cacheDir, ...name.split('/'));
    candidates.push(path.join(scopeDir, `${safeVersion}.json`));
  }
  return candidates;
}

export function readCachedAttestations(cacheDir, name, version) {
  if (!cacheDir) return undefined;
  for (const candidate of cacheCandidates(cacheDir, name, version)) {
    if (!existsSync(candidate)) continue;
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(candidate, 'utf8'));
    } catch (error) {
      throw new FetchError(`cannot parse cached attestation ${candidate}: ${error.message}`);
    }
    return {
      attestations: normalizeAttestations(parsed),
      cachePath: candidate,
      fromCache: true,
    };
  }
  return undefined;
}

export function resolveAttestations({ name, version, cacheDir, offline = false } = {}) {
  const cached = readCachedAttestations(cacheDir, name, version);
  if (cached) return cached;

  const where = cacheDir ? ` in ${cacheDir}` : '';
  const mode = offline ? ' while running offline' : '';
  return {
    attestations: [],
    missing: true,
    fromCache: false,
    reason: `no cached attestation bundle for ${name}@${version}${where}${mode}`,
  };
}
