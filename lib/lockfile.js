// Parse package-lock.json v1, v2 and v3 into a flat list of registry
// packages.  Local workspaces, links and git/file dependencies are skipped:
// they have no npm registry attestation to resolve.

import { readFileSync } from 'node:fs';
import { LockfileError, isNonEmptyString, isPlainObject } from './util.js';

const MARKER = 'node_modules/';

function nameFromPackagesKey(key) {
  if (!key.includes(MARKER)) return undefined;
  const name = key.slice(key.lastIndexOf(MARKER) + MARKER.length);
  if (!name || name.startsWith('.')) return undefined;
  // A scoped name has exactly one slash; anything deeper is not a package key.
  const parts = name.split('/');
  if (name.startsWith('@')) {
    return parts.length === 2 && parts[0].length > 1 && parts[1].length > 0 ? name : undefined;
  }
  return parts.length === 1 ? name : undefined;
}

function isRegistryResolved(resolved) {
  if (!isNonEmptyString(resolved)) return true;
  return /^https?:\/\//iu.test(resolved);
}

function entryRecord(name, entry, key) {
  return {
    name,
    version: entry.version,
    integrity: isNonEmptyString(entry.integrity) ? entry.integrity.trim() : null,
    resolved: isNonEmptyString(entry.resolved) ? entry.resolved : null,
    dev: entry.dev === true,
    optional: entry.optional === true,
    peer: entry.peer === true,
    lockPath: key,
  };
}

function usable(entry) {
  if (!isPlainObject(entry)) return false;
  if (entry.link === true || entry.inBundle === true) return false;
  if (!isNonEmptyString(entry.version)) return false;
  // Git, file and workspace dependencies either have a non-http(s) "resolved"
  // location or no registry tarball at all.  They cannot carry npm provenance.
  if (!isRegistryResolved(entry.resolved)) return false;
  return true;
}

function fromPackages(packages) {
  const records = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (key === '' || !usable(entry)) continue;
    const name = nameFromPackagesKey(key);
    if (!name) continue;
    records.push(entryRecord(name, entry, key));
  }
  return records;
}

function fromDependencies(dependencies, trail = []) {
  const records = [];
  if (!isPlainObject(dependencies)) return records;
  for (const [name, entry] of Object.entries(dependencies)) {
    if (!isPlainObject(entry) || !usable(entry)) continue;
    records.push(entryRecord(name, entry, trail.concat(name).join(' > ')));
    if (isPlainObject(entry.dependencies)) {
      records.push(...fromDependencies(entry.dependencies, trail.concat(name)));
    }
  }
  return records;
}

export function parseLockfile(value, source = '<lockfile>') {
  let data = value;
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data);
    } catch (error) {
      throw new LockfileError(`cannot parse lockfile ${source}: ${error.message}`);
    }
  }
  if (!isPlainObject(data)) {
    throw new LockfileError(`lockfile ${source} is not a JSON object`);
  }

  let records = [];
  if (isPlainObject(data.packages) && Object.keys(data.packages).length > 0) {
    records = fromPackages(data.packages);
  }
  // v1 lockfiles only have "dependencies".  In v2/v3 the packages map is the
  // source of truth and the nested dependencies tree is a compatibility copy.
  if (records.length === 0 && isPlainObject(data.dependencies)) {
    records = fromDependencies(data.dependencies);
  }

  const seen = new Set();
  const entries = [];
  for (const record of records) {
    const key = [record.name, record.version, record.integrity ?? ''].join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push(record);
  }
  entries.sort((left, right) => {
    const byName = left.name.localeCompare(right.name);
    if (byName !== 0) return byName;
    const byVersion = left.version.localeCompare(right.version);
    if (byVersion !== 0) return byVersion;
    return left.lockPath.localeCompare(right.lockPath);
  });

  return {
    lockfileVersion: data.lockfileVersion ?? null,
    name: isNonEmptyString(data.name) ? data.name : undefined,
    version: isNonEmptyString(data.version) ? data.version : undefined,
    entries,
    source,
  };
}

export function readLockfile(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    throw new LockfileError(`cannot read lockfile ${file}: ${error.message}`);
  }
  return parseLockfile(text, file);
}

// A package entry can be present in the lockfile with a missing integrity
// field (for example a local `file:` dependency that still has a version).  The
// checker needs to distinguish that from "not in the lockfile at all".
export function entriesByName(lockfile) {
  const index = new Map();
  for (const entry of lockfile.entries) {
    const list = index.get(entry.name) ?? [];
    list.push(entry);
    index.set(entry.name, list);
  }
  return index;
}
