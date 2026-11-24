// Orchestrate one check: read the lockfile and policy, resolve each selected
// package's cached attestation, verify the Sigstore bundle offline, and bind
// the result to the source repository/workflow the policy trusts.

import { entryMatchesName, readLockfile } from './lockfile.js';
import { expectedIdentity, findExemption, loadPolicy, selectTargets } from './policy.js';
import { DEFAULT_REGISTRY, resolveAttestations } from './registry.js';
import { extractSource, matchIdentity, matchSubject, verifyBundle } from './sigstore.js';
import { cacheTrustRoot, loadTrustRoot } from './trust-root.js';
import {
  integrityMatches,
  integrityToDigests,
  isNonEmptyString,
  isPlainObject,
  packageLabel,
} from './util.js';

export const STATUSES = Object.freeze(['verified', 'mismatch', 'missing', 'error']);

function provenanceType(predicateType) {
  if (typeof predicateType !== 'string') return false;
  const value = predicateType.toLowerCase();
  return value.includes('slsa') || value.includes('provenance');
}

function bundleHasCertificate(bundle) {
  const material = bundle?.verificationMaterial;
  if (!isPlainObject(material)) return false;
  if (Array.isArray(material.x509CertificateChain?.certificates)) return true;
  if (Array.isArray(material.x509CertificateChain)) return true;
  return Boolean(material.x509Certificate || material.certificate);
}

function chooseIdentitySource(source, verified) {
  const identity = verified.identities?.[0];
  return {
    commit: source.commit ?? null,
    repository: source.repository ?? identity?.repository ?? null,
    workflow: source.workflow ?? identity?.workflow ?? null,
    ref: source.workflowRef ?? identity?.ref ?? null,
    identity: identity?.uri ?? null,
    predicateType: source.predicateType ?? verified.statement?.predicateType,
  };
}

function evaluateAttestation({ attestation, name, version, digests, expected, trustRoot }) {
  const bundle = attestation?.bundle;
  let predicateType = attestation?.predicateType ?? bundle?.dsseEnvelope?.predicateType;
  if (!isPlainObject(bundle)) {
    return { kind: 'unverifiable', predicateType, reason: 'attestation entry has no bundle' };
  }
  // A signed publish attestation is not build provenance.  Only a SLSA /
  // provenance predicate may satisfy the policy, even when its subject and
  // certificate identity happen to match.
  if (isNonEmptyString(predicateType) && !provenanceType(predicateType)) {
    return { kind: 'ignored', predicateType };
  }
  if (!bundleHasCertificate(bundle)) {
    return {
      kind: 'unverifiable',
      predicateType,
      reason: 'provenance bundle has no X.509 certificate chain (cannot be verified offline)',
    };
  }

  let verified;
  try {
    verified = verifyBundle(bundle, trustRoot);
  } catch (error) {
    return {
      kind: 'crypto-error',
      predicateType,
      reason: error instanceof Error ? error.message : String(error),
    };
  }

  predicateType = verified.statement.predicateType ?? predicateType;
  if (!provenanceType(predicateType)) {
    return { kind: 'ignored', predicateType };
  }

  const subject = matchSubject(verified.statement, name, version, digests);
  if (!subject.ok) {
    return {
      kind: 'subject-error',
      predicateType,
      verified,
      source: chooseIdentitySource(extractSource(verified.statement), verified),
      reason: subject.reason,
    };
  }

  const source = extractSource(verified.statement);
  const identity = matchIdentity(source, verified.certificate, expected);
  const details = chooseIdentitySource(source, verified);
  if (!identity.ok) {
    return {
      kind: 'policy-error',
      predicateType: details.predicateType ?? predicateType,
      verified,
      source: details,
      reason: identity.reason,
    };
  }

  return {
    kind: 'success',
    predicateType: details.predicateType ?? predicateType,
    verified,
    source: details,
    subject,
    reason: 'provenance verified',
  };
}

function makeRow({
  packageName,
  version,
  integrity,
  status,
  verified = false,
  reason,
  commit = null,
  sourceRepository = null,
  workflow = null,
  ...extra
}) {
  return {
    package: packageName,
    version: version ?? null,
    integrity: integrity ?? null,
    commit,
    sourceRepository,
    workflow,
    verified,
    status,
    reason,
    ...extra,
  };
}

function failedRow(entry, status, exitCode, reason, extra = {}) {
  return makeRow({
    packageName: entry.name,
    version: entry.version,
    integrity: entry.integrity,
    status,
    reason,
    exitCode,
    ...extra,
  });
}

async function evaluateTarget(target, context) {
  const { entry, allowEntry } = target;

  if (allowEntry?.integrity && !integrityMatches(allowEntry.integrity, entry.integrity)) {
    return failedRow(
      entry,
      'mismatch',
      1,
      `lockfile integrity does not match the integrity pinned by policy for ${packageLabel(entry.name, entry.version)}`,
    );
  }

  if (!isNonEmptyString(entry.integrity)) {
    return failedRow(
      entry,
      'mismatch',
      1,
      `lockfile entry ${packageLabel(entry.name, entry.version)} has no integrity hash to bind provenance to`,
    );
  }

  const digests = integrityToDigests(entry.integrity);
  if (Object.keys(digests).length === 0) {
    return failedRow(
      entry,
      'error',
      2,
      `lockfile integrity "${entry.integrity}" has no supported digest algorithm`,
    );
  }

  let resolution;
  try {
    resolution = await resolveAttestations({
      name: entry.name,
      version: entry.version,
      registry: context.registry,
      cacheDir: context.cacheDir,
      offline: context.offline,
      timeoutMs: context.timeoutMs,
    });
  } catch (error) {
    return failedRow(entry, 'error', 2, error instanceof Error ? error.message : String(error));
  }

  const attestations = resolution.attestations ?? [];
  if (attestations.length === 0) {
    return failedRow(
      entry,
      'missing',
      1,
      resolution.reason ?? `no attestation bundle available for ${packageLabel(entry.name, entry.version)}`,
      { fromCache: Boolean(resolution.fromCache), cachePath: resolution.cachePath ?? null },
    );
  }

  const expected = expectedIdentity(context.policy, allowEntry);
  const candidates = attestations
    .map((attestation) => ({ attestation, slsa: provenanceType(attestation.predicateType) }))
    .sort((left, right) => Number(right.slsa) - Number(left.slsa));

  const outcomes = candidates.map(({ attestation }) =>
    evaluateAttestation({
      attestation,
      name: entry.name,
      version: entry.version,
      digests,
      expected,
      trustRoot: context.trustRoot,
    }),
  );

  const audit = {
    fromCache: Boolean(resolution.fromCache),
    cachePath: resolution.cachePath ?? null,
  };

  const success = outcomes.find((outcome) => outcome.kind === 'success');
  if (success) {
    return makeRow({
      packageName: entry.name,
      version: entry.version,
      integrity: entry.integrity,
      status: 'verified',
      verified: true,
      reason: success.reason,
      commit: success.source.commit ?? null,
      sourceRepository: success.source.repository ?? null,
      workflow: success.source.workflow ?? null,
      predicateType: success.predicateType,
      certificateIdentity: success.source.identity ?? null,
      logIndex: success.verified.tlog?.logIndex ?? null,
      integratedTime: success.verified.tlog?.integratedTime ?? null,
      exitCode: 0,
      ...audit,
    });
  }

  const policyError = outcomes.find((outcome) => outcome.kind === 'policy-error');
  if (policyError) {
    return failedRow(entry, 'mismatch', 1, policyError.reason, {
      commit: policyError.source?.commit ?? null,
      sourceRepository: policyError.source?.repository ?? null,
      workflow: policyError.source?.workflow ?? null,
      predicateType: policyError.predicateType,
      certificateIdentity: policyError.source?.identity ?? null,
      ...audit,
    });
  }

  const subjectError = outcomes.find((outcome) => outcome.kind === 'subject-error');
  if (subjectError) {
    return failedRow(entry, 'mismatch', 1, subjectError.reason, {
      commit: subjectError.source?.commit ?? null,
      sourceRepository: subjectError.source?.repository ?? null,
      workflow: subjectError.source?.workflow ?? null,
      predicateType: subjectError.predicateType,
      certificateIdentity: subjectError.source?.identity ?? null,
      ...audit,
    });
  }

  const cryptoError = outcomes.find((outcome) => outcome.kind === 'crypto-error');
  if (cryptoError) {
    return failedRow(entry, 'error', 2, cryptoError.reason, {
      predicateType: cryptoError.predicateType,
      ...audit,
    });
  }

  const unverifiable = outcomes.find((outcome) => outcome.kind === 'unverifiable');
  if (unverifiable) {
    return failedRow(entry, 'error', 2, unverifiable.reason, {
      predicateType: unverifiable.predicateType,
      ...audit,
    });
  }

  return failedRow(
    entry,
    'mismatch',
    1,
    `no verifiable Sigstore provenance attestation found for ${packageLabel(entry.name, entry.version)}`,
    audit,
  );
}

// Explain why a lockfile entry was filtered out of the selected targets.
// Naming the flag is important: "not present in the lockfile" sends people
// looking for a missing dependency when the package is right there in
// package-lock.json and the policy simply excluded it.
function exclusionReasons(entry, policy) {
  const reasons = [];
  if (!policy.includeDev && entry.dev) reasons.push('includeDev=false (it is a dev dependency)');
  if (!policy.includeOptional && entry.optional) {
    reasons.push('includeOptional=false (it is an optional dependency)');
  }
  if (!policy.includePeer && entry.peer) reasons.push('includePeer=false (it is a peer dependency)');
  return reasons;
}

function eligible(entry, policy) {
  return exclusionReasons(entry, policy).length === 0;
}

// The required name (and, when pinned, version) exists in the lockfile but the
// policy's dependency-type filters removed it before verification.
function filteredEntry(lockfile, allowEntry, policy) {
  return lockfile.entries.find(
    (entry) =>
      entryMatchesName(entry, allowEntry.name) &&
      (allowEntry.version === undefined || entry.version === allowEntry.version) &&
      exclusionReasons(entry, policy).length > 0,
  );
}

function excludedByFilterRow(policy, entry, allowEntry) {
  const reasons = exclusionReasons(entry, policy).join(' and ');
  return makeRow({
    packageName: allowEntry.name,
    version: allowEntry.version ?? entry.version,
    integrity: allowEntry.integrity ?? entry.integrity,
    status: 'missing',
    reason: `policy requires ${packageLabel(allowEntry.name, allowEntry.version)}, which is in the lockfile but excluded because ${reasons}`,
    exitCode: 1,
  });
}

function missingAllowlistRow(policy, lockfile, allowEntry) {
  const sameName = lockfile.entries.filter(
    (entry) => entryMatchesName(entry, allowEntry.name) && eligible(entry, policy),
  );
  if (allowEntry.version) {
    // A package that was filtered out is present, so do not call it absent.
    // Prefer the exact requirement over the generic version-mismatch wording.
    const filtered = filteredEntry(lockfile, allowEntry, policy);
    if (filtered) return excludedByFilterRow(policy, filtered, allowEntry);
    if (sameName.length > 0) {
      const actual = sameName.map((entry) => packageLabel(entry.name, entry.version)).join(', ');
      return makeRow({
        packageName: allowEntry.name,
        version: allowEntry.version,
        integrity: allowEntry.integrity,
        status: 'mismatch',
        reason: `policy requires version ${allowEntry.version}, but the lockfile contains ${actual}`,
        exitCode: 1,
      });
    }
  } else {
    // Reaching the missing list without an eligible match means any surviving
    // same-name entry must have been removed by a dependency-type filter.
    const filtered = filteredEntry(lockfile, allowEntry, policy);
    if (filtered) return excludedByFilterRow(policy, filtered, allowEntry);
  }
  return makeRow({
    packageName: allowEntry.name,
    version: allowEntry.version,
    integrity: allowEntry.integrity,
    status: 'missing',
    reason: allowEntry.version
      ? `policy requires ${packageLabel(allowEntry.name, allowEntry.version)}, which is not present in the lockfile`
      : `policy requires ${allowEntry.name}, which is not present in the lockfile`,
    exitCode: 1,
  });
}

function sortRows(rows) {
  return rows.slice().sort((left, right) => {
    const byName = String(left.package).localeCompare(String(right.package));
    if (byName !== 0) return byName;
    const byVersion = String(left.version ?? '').localeCompare(String(right.version ?? ''));
    if (byVersion !== 0) return byVersion;
    return String(left.status).localeCompare(String(right.status));
  });
}

export function exitCodeFor(rows) {
  let code = 0;
  for (const item of rows) {
    if (item.status === 'mismatch' || item.status === 'missing') code = Math.max(code, 1);
    if (item.status === 'error') code = Math.max(code, 2);
  }
  return code;
}

function summarize(rows, exempt) {
  return {
    required: rows.length,
    verified: rows.filter((item) => item.status === 'verified').length,
    missing: rows.filter((item) => item.status === 'missing').length,
    mismatch: rows.filter((item) => item.status === 'mismatch').length,
    error: rows.filter((item) => item.status === 'error').length,
    exempt,
  };
}

function findEntryExemption(policy, entry) {
  const direct = findExemption(policy, entry.name, entry.version);
  if (direct || !entry.aliased) return direct;
  for (const installName of entry.installNames) {
    if (installName === entry.name) continue;
    const exempt = findExemption(policy, installName, entry.version);
    if (exempt) return exempt;
  }
  return undefined;
}

export async function runCheck({
  lockfilePath,
  policyPath,
  cacheDir,
  trustRootPath,
  registry,
  offline = false,
  timeoutMs = 20000,
} = {}) {
  const policy = loadPolicy(policyPath);
  const lockfile = readLockfile(lockfilePath);
  const { targets, missing } = selectTargets(policy, lockfile);

  const configuredRegistry =
    registry ??
    policy.registry ??
    process.env.PROVENANCE_GATE_REGISTRY ??
    process.env.NPM_CONFIG_REGISTRY ??
    process.env.npm_config_registry ??
    DEFAULT_REGISTRY;

  let exempt = 0;
  const active = [];
  for (const target of targets) {
    if (findEntryExemption(policy, target.entry)) {
      exempt += 1;
      continue;
    }
    active.push(target);
  }

  const rows = [];
  if (active.length > 0) {
    const trustRoot = loadTrustRoot({
      explicit: trustRootPath,
      policyTrustRoot: policy.trustRoot,
      cacheDir,
    });
    if (cacheDir && !offline) {
      // Persist the exact trust root used for this run.  A later --offline run
      // then verifies against the same anchors instead of silently falling
      // back to the built-in public-good root.
      cacheTrustRoot(cacheDir, trustRoot);
    }
    for (const target of active) {
      rows.push(
        await evaluateTarget(target, {
          policy,
          trustRoot,
          cacheDir,
          offline,
          registry: configuredRegistry,
          timeoutMs,
        }),
      );
    }
  }

  for (const allowEntry of missing) {
    if (findExemption(policy, allowEntry.name, allowEntry.version)) {
      exempt += 1;
      continue;
    }
    rows.push(missingAllowlistRow(policy, lockfile, allowEntry));
  }

  const packages = sortRows(rows);
  const summary = summarize(packages, exempt);
  const exitCode = exitCodeFor(packages);

  return {
    ok: exitCode === 0,
    exitCode,
    lockfile: lockfilePath,
    policy: policyPath,
    registry: configuredRegistry,
    lockfileVersion: lockfile.lockfileVersion,
    offline: Boolean(offline),
    summary,
    packages,
  };
}

function pad(value, width) {
  return `${value}${' '.repeat(Math.max(0, width - value.length))}`;
}

export function formatTable(result) {
  const headers = ['PACKAGE', 'VERSION', 'INTEGRITY', 'STATUS', 'REASON'];
  const rows = result.packages.map((item) => [
    item.package,
    item.version ?? '-',
    item.integrity ?? '-',
    item.status,
    item.reason ?? '-',
  ]);
  const widths = headers.map((header, column) =>
    Math.max(header.length, ...rows.map((cells) => String(cells[column]).length)),
  );
  const line = (cells) => cells.map((cell, column) => pad(String(cell), widths[column])).join('  ').trimEnd();
  const lines = [line(headers), widths.map((width) => '-'.repeat(width)).join('  ')];
  for (const cells of rows) lines.push(line(cells));

  const { summary } = result;
  lines.push('');
  lines.push(
    `${summary.required} required, ${summary.verified} verified, ${summary.missing} missing, ` +
      `${summary.mismatch} mismatch, ${summary.error} error` +
      (summary.exempt > 0 ? `, ${summary.exempt} exempt` : ''),
  );
  return `${lines.join('\n')}\n`;
}
