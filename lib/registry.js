// Resolve a lockfile entry to its npm attestation document and, when a cache
// directory is configured, persist what was fetched so later `--offline` runs
// are hermetic.  A cached bundle is authoritative: it is never silently
// re-fetched, and an unreadable or malformed cache entry is an error rather
// than a missing attestation that could be mistaken for "nothing to check".

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { FetchError, isNonEmptyString, isPlainObject, safePackageId } from './util.js';

export const DEFAULT_REGISTRY = 'https://registry.npmjs.org';
const DEFAULT_TIMEOUT_MS = 20000;

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

// A cache file is allowed to say "this package has no attestations" with an
// empty array.  Anything else that parses but yields no bundles is corrupt
// cache data, not a package without provenance.
function cacheDocumentEntries(data) {
  if (Array.isArray(data)) return data;
  if (isPlainObject(data) && Array.isArray(data.attestations)) return data.attestations;
  return undefined;
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

export function cacheWritePath(cacheDir, name, version) {
  return path.join(cacheDir, `${safePackageId(name, version)}.json`);
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
    const attestations = normalizeAttestations(parsed);
    if (attestations.length === 0) {
      const entries = cacheDocumentEntries(parsed);
      if (!Array.isArray(entries)) {
        throw new FetchError(`cached attestation ${candidate} is not an npm attestation document`);
      }
      if (entries.length > 0) {
        throw new FetchError(`cached attestation ${candidate} contains no usable attestation bundles`);
      }
    }
    return {
      attestations,
      cachePath: candidate,
      fromCache: true,
    };
  }
  return undefined;
}

export function writeCachedAttestations(cacheDir, name, version, data) {
  if (!cacheDir) return undefined;
  const target = cacheWritePath(cacheDir, name, version);
  const temporary = `${target}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(temporary, `${JSON.stringify(data, null, 2)}\n`);
    renameSync(temporary, target);
    return target;
  } catch (error) {
    try {
      if (existsSync(temporary)) unlinkSync(temporary);
    } catch {
      // Best effort cleanup; the original write error is the useful one.
    }
    throw new FetchError(`cannot write cached attestation ${target}: ${error.message}`);
  }
}

function normalizeRegistry(registry) {
  const value = isNonEmptyString(registry) ? registry.trim() : DEFAULT_REGISTRY;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new FetchError(`registry "${value}" is not a valid URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new FetchError(`registry "${value}" must use http:// or https://`);
  }
  return url.toString().replace(/\/+$/u, '');
}

function encodedPackageName(name) {
  // npm keeps the leading "@" and encodes only the scope separator.  Both
  // encodings are accepted by the public registry; this is the spelling npm
  // itself puts in dist.attestations.url.
  if (name.startsWith('@')) return `@${encodeURIComponent(name.slice(1)).replace(/%2f/giu, '%2F')}`;
  return encodeURIComponent(name);
}

export function attestationUrl(registry, name, version) {
  return `${registry}/-/npm/v1/attestations/${encodedPackageName(name)}@${encodeURIComponent(version)}`;
}

function packumentUrl(registry, name) {
  return `${registry}/${encodedPackageName(name)}`;
}

async function fetchJson(url, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof fetch !== 'function') {
    throw new FetchError('this Node.js runtime has no fetch(); Node 18 or newer is required');
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(url, {
        headers: {
          accept: 'application/json',
          'user-agent': 'lockfile-provenance-gate/0.1.0 (+https://github.com/WJDdidi-1/lockfile-provenance-gate)',
        },
        signal: controller.signal,
      });
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new FetchError(`registry request timed out after ${timeoutMs}ms: ${url}`);
      }
      throw new FetchError(
        `cannot reach registry ${url}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    if (response.status === 404) return { status: 404, data: undefined };
    if (!response.ok) {
      throw new FetchError(`registry answered ${response.status} ${response.statusText} for ${url}`);
    }

    let text;
    try {
      text = await response.text();
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new FetchError(`registry request timed out after ${timeoutMs}ms: ${url}`);
      }
      throw new FetchError(
        `cannot read registry response from ${url}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    try {
      return { status: response.status, data: JSON.parse(text) };
    } catch (error) {
      throw new FetchError(`registry returned invalid JSON for ${url}: ${error.message}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

// Registries that do not implement the attestations endpoint can still
// advertise bundles from the packument's dist.attestations.url.
async function fetchFromPackument(registry, name, version, options) {
  const { status, data } = await fetchJson(packumentUrl(registry, name), options);
  if (status === 404 || !isPlainObject(data)) return undefined;
  const metadata = data.versions?.[version];
  if (!isPlainObject(metadata)) return undefined;
  const advertised = metadata.dist?.attestations?.url;
  if (!isNonEmptyString(advertised)) return undefined;
  let absolute;
  try {
    absolute = new URL(advertised, `${registry}/`).toString();
  } catch {
    return undefined;
  }
  const response = await fetchJson(absolute, options);
  return response.status === 404 ? undefined : response.data;
}

async function fetchAttestations({ name, version, registry, timeoutMs }) {
  const base = normalizeRegistry(registry);
  let data;
  const { status, data: endpointData } = await fetchJson(attestationUrl(base, name, version), { timeoutMs });
  if (status !== 404) data = endpointData;

  if (data === undefined) {
    data = await fetchFromPackument(base, name, version, { timeoutMs });
  }

  if (data === undefined) {
    return {
      attestations: [],
      missing: true,
      registry: base,
      fromCache: false,
      reason: `registry ${base} has no attestation for ${name}@${version}`,
    };
  }

  const attestations = normalizeAttestations(data);
  const entries = cacheDocumentEntries(data);
  if (attestations.length === 0) {
    if (!Array.isArray(entries)) {
      throw new FetchError(`registry attestation response for ${name}@${version} is not an attestation document`);
    }
    if (entries.length > 0) {
      throw new FetchError(
        `registry attestation response for ${name}@${version} contains no usable attestation bundles`,
      );
    }
  }
  return { attestations, registry: base, fromCache: false, raw: data };
}

export async function resolveAttestations({
  name,
  version,
  registry,
  cacheDir,
  offline = false,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const cached = readCachedAttestations(cacheDir, name, version);
  if (cached) return cached;

  if (offline) {
    const where = cacheDir ? ` in ${cacheDir}` : '';
    return {
      attestations: [],
      missing: true,
      fromCache: false,
      reason: `no cached attestation bundle for ${name}@${version}${where} while running offline`,
    };
  }

  const fetched = await fetchAttestations({ name, version, registry, timeoutMs });
  if (cacheDir && fetched.raw !== undefined) {
    const cachePath = writeCachedAttestations(cacheDir, name, version, fetched.raw);
    return { ...fetched, cachePath };
  }
  return fetched;
}
