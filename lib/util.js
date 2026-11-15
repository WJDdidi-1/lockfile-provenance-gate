// Small, dependency-free helpers shared by the CLI and the checker.

import { readFileSync } from 'node:fs';
import path from 'node:path';

export class GateError extends Error {
  constructor(message, exitCode = 2) {
    super(message);
    this.name = 'GateError';
    this.exitCode = exitCode;
  }
}

export class PolicyError extends GateError {
  constructor(message) {
    super(message, 2);
    this.name = 'PolicyError';
  }
}

export class LockfileError extends GateError {
  constructor(message) {
    super(message, 2);
    this.name = 'LockfileError';
  }
}

export class FetchError extends GateError {
  constructor(message) {
    super(message, 2);
    this.name = 'FetchError';
  }
}

export class VerificationError extends GateError {
  constructor(message) {
    super(message, 2);
    this.name = 'VerificationError';
  }
}

export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

export function firstString(...values) {
  for (const value of values) {
    if (isNonEmptyString(value)) return value.trim();
  }
  return undefined;
}

export function readJsonFile(file, what = 'JSON file') {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    throw new GateError(`cannot read ${what} ${file}: ${error.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new GateError(`cannot parse ${what} ${file}: ${error.message}`);
  }
}

// Normalise the many ways a policy can spell "the repository I trust" to
// "github.com/org/repo".  Used for equality checks only; the raw value is kept
// for display.
export function normalizeRepository(value) {
  let raw = value;
  if (isPlainObject(raw)) {
    raw = firstString(raw.url, raw.repository, raw.uri, raw.source, raw.href, raw.git);
  }
  if (!isNonEmptyString(raw)) return undefined;

  let text = raw.trim().replace(/^git\+/u, '');
  // scp-style remotes: git@github.com:org/repo.git
  if (!text.includes('://') && /^(?:[^@/\s]+@)?[^:/\s]+:.+$/u.test(text)) {
    const match = /^(?:[^@/\s]+@)?([^:/\s]+):(.+)$/u.exec(text);
    if (match) text = `https://${match[1]}/${match[2]}`;
  }
  if (!text.includes('://')) text = `https://${text.replace(/^\/+/u, '')}`;

  let url;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  if (!['http:', 'https:', 'ssh:', 'git:'].includes(url.protocol)) return undefined;

  let pathname = url.pathname;
  try {
    pathname = decodeURIComponent(pathname);
  } catch {
    // Keep the encoded form; it is still stable for comparison.
  }
  pathname = pathname.replace(/\/+$/u, '').replace(/\.git$/iu, '');
  const at = pathname.indexOf('@');
  if (at >= 0) pathname = pathname.slice(0, at);
  const host = url.hostname.toLowerCase().replace(/^www\./u, '');
  const normalized = `${host}${pathname}`.replace(/\/+$/u, '').toLowerCase();
  return normalized || undefined;
}

// Returns { path, ref } where path is a workflow file path such as
// ".github/workflows/release.yml" and ref is an optional git ref.
export function normalizeWorkflow(value) {
  let raw = value;
  let ref;
  if (isPlainObject(raw)) {
    ref = firstString(raw.ref, raw.gitRef);
    raw = firstString(raw.path, raw.workflow, raw.entryPoint, raw.file, raw.uri, raw.url);
  }
  if (!isNonEmptyString(raw)) return undefined;

  let text = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//iu.test(text)) {
    try {
      text = new URL(text).pathname;
    } catch {
      // Fall through and treat it as a path.
    }
  }
  if (text.startsWith('git+')) text = text.slice(4);
  text = text.replace(/[?#].*$/u, '');
  const at = text.indexOf('@');
  if (at > 0) {
    if (!ref) ref = text.slice(at + 1);
    text = text.slice(0, at);
  }
  text = text.replace(/^\/+/u, '').replace(/\/+$/u, '');
  const marker = text.indexOf('.github/');
  if (marker > 0) text = text.slice(marker);
  return { path: text, ref };
}

export function workflowPathsEqual(expected, actual) {
  const left = normalizeWorkflow(expected)?.path;
  const right = normalizeWorkflow(actual)?.path;
  if (!left || !right) return false;
  if (left === right) return true;
  // A policy is allowed to name only "release.yml".
  if (!left.includes('/')) return right.split('/').at(-1) === left;
  if (!right.includes('/')) return left.split('/').at(-1) === right;
  // Tolerate one side carrying a repository prefix.
  return left.endsWith(`/${right}`) || right.endsWith(`/${left}`);
}

export function parsePackageRef(input) {
  if (!isNonEmptyString(input)) return undefined;
  const text = input.trim();
  let name;
  let version;
  if (text.startsWith('@')) {
    const slash = text.indexOf('/');
    if (slash < 0) return undefined;
    const at = text.indexOf('@', slash);
    if (at < 0) {
      name = text;
    } else {
      name = text.slice(0, at);
      version = text.slice(at + 1) || undefined;
    }
  } else {
    const at = text.indexOf('@');
    if (at < 0) {
      name = text;
    } else {
      name = text.slice(0, at);
      version = text.slice(at + 1) || undefined;
    }
  }
  if (!name) return undefined;
  return { name, version };
}

export function normalizeDigestAlgorithm(value) {
  if (!isNonEmptyString(value)) return undefined;
  const algorithm = value.toLowerCase().replace(/-/gu, '');
  return ['sha1', 'sha256', 'sha384', 'sha512'].includes(algorithm) ? algorithm : undefined;
}

// SRI strings are unordered sets of "algorithm-base64" tokens.  Compare by
// decoded digest so "sha512-X sha1-Y" and "sha1-Y sha512-X" are equal, while a
// policy that names an algorithm the lockfile does not carry is a mismatch.
export function integrityDigests(integrity) {
  const digests = new Map();
  if (!isNonEmptyString(integrity)) return digests;
  for (const token of integrity.trim().split(/\s+/u)) {
    const match = /^([a-z0-9]+)-([A-Za-z0-9+/=_-]+)$/iu.exec(token);
    if (!match) continue;
    const algorithm = normalizeDigestAlgorithm(match[1]);
    if (!algorithm) continue;
    try {
      digests.set(algorithm, Buffer.from(match[2], 'base64').toString('hex').toLowerCase());
    } catch {
      // Ignore a malformed token; a policy that needs it will fail to match.
    }
  }
  return digests;
}

// Object-shaped counterpart to integrityDigests(), used when matching an
// in-toto subject digest against the SRI string in package-lock.json.
export function integrityToDigests(integrity) {
  const result = {};
  for (const [algorithm, digest] of integrityDigests(integrity)) result[algorithm] = digest;
  return result;
}

export function validateIntegrity(integrity) {
  if (!isNonEmptyString(integrity)) return undefined;
  const digests = integrityDigests(integrity);
  if (digests.size === 0) {
    throw new PolicyError(`integrity "${integrity}" is not a supported SRI string (expected e.g. sha512-...)`);
  }
  return integrity.trim();
}

export function integrityMatches(expected, actual) {
  const wanted = integrityDigests(expected);
  const got = integrityDigests(actual);
  if (wanted.size === 0 || got.size === 0) return false;
  for (const [algorithm, digest] of wanted) {
    if (got.get(algorithm) !== digest) return false;
  }
  return true;
}

export function safePackageId(name, version) {
  const clean = (value) => String(value).replace(/[^A-Za-z0-9._-]/gu, '_');
  return `${clean(String(name).replace(/^@/u, ''))}@${clean(version)}`;
}

export function packageLabel(name, version) {
  return version ? `${name}@${version}` : String(name);
}

export function resolveRelative(baseFile, value) {
  if (!isNonEmptyString(value)) return undefined;
  if (path.isAbsolute(value)) return value;
  return path.resolve(path.dirname(baseFile), value);
}
