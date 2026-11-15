// Orchestrate one check: read the lockfile and policy, decide which lockfile
// entries the policy requires, and emit one verdict row per requirement.
//
// Milestone 1 deliberately does not claim cryptographic verification.  A
// required package that is present and consistent with the policy is reported
// as "unverified" (and the command exits 2), never as a false pass.  Later
// milestones replace that verdict with an offline Sigstore bundle result.

import { entriesByName, readLockfile } from './lockfile.js';
import { findExemption, loadPolicy } from './policy.js';
import { integrityMatches, isNonEmptyString, packageLabel } from './util.js';

export const STATUSES = Object.freeze(['unverified', 'missing', 'mismatch']);

function row(packageName, version, integrity, status, reason) {
  return {
    package: packageName,
    version: version ?? null,
    integrity: integrity ?? null,
    status,
    reason,
  };
}

function include(entry, policy) {
  if (!policy.includeDev && entry.dev) return false;
  if (!policy.includeOptional && entry.optional) return false;
  if (!policy.includePeer && entry.peer) return false;
  return true;
}

function exemptionFor(policy, name, version) {
  return findExemption(policy, name, version);
}

function rowKey(item) {
  return `${item.package}\u0000${item.version ?? ''}\u0000${item.status}`;
}

function dedupeRows(rows) {
  const seen = new Set();
  return rows.filter((item) => {
    const key = rowKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function fromAll(policy, lockfile) {
  const rows = [];
  let exempt = 0;
  for (const entry of lockfile.entries) {
    if (!include(entry, policy)) continue;
    if (exemptionFor(policy, entry.name, entry.version)) {
      exempt += 1;
      continue;
    }
    if (!isNonEmptyString(entry.integrity)) {
      rows.push(
        row(
          entry.name,
          entry.version,
          null,
          'mismatch',
          `lockfile entry ${packageLabel(entry.name, entry.version)} has no integrity hash to bind provenance to`,
        ),
      );
      continue;
    }
    rows.push(
      row(
        entry.name,
        entry.version,
        entry.integrity,
        'unverified',
        'no attestation bundle was available to verify provenance',
      ),
    );
  }
  return { rows, exempt };
}

function fromAllowlist(policy, lockfile) {
  const index = entriesByName(lockfile);
  const rows = [];
  let exempt = 0;

  for (const allowEntry of policy.allowlist) {
    const allMatches = (index.get(allowEntry.name) ?? []).filter((entry) => include(entry, policy));
    if (allMatches.length === 0) {
      if (exemptionFor(policy, allowEntry.name, allowEntry.version)) {
        exempt += 1;
        continue;
      }
      rows.push(
        row(
          allowEntry.name,
          allowEntry.version,
          allowEntry.integrity,
          'missing',
          allowEntry.version
            ? `policy requires ${packageLabel(allowEntry.name, allowEntry.version)}, which is not present in the lockfile`
            : `policy requires ${allowEntry.name}, which is not present in the lockfile`,
        ),
      );
      continue;
    }

    let matches = allMatches;
    if (allowEntry.version) {
      matches = allMatches.filter((entry) => entry.version === allowEntry.version);
      if (matches.length === 0) {
        const actual = allMatches.map((entry) => packageLabel(entry.name, entry.version)).join(', ');
        if (exemptionFor(policy, allowEntry.name, allowEntry.version)) {
          exempt += 1;
          continue;
        }
        rows.push(
          row(
            allowEntry.name,
            allowEntry.version,
            allowEntry.integrity,
            'mismatch',
            `policy requires version ${allowEntry.version}, but the lockfile contains ${actual}`,
          ),
        );
        continue;
      }
    }

    for (const entry of matches) {
      if (exemptionFor(policy, entry.name, entry.version)) {
        exempt += 1;
        continue;
      }
      if (!isNonEmptyString(entry.integrity)) {
        rows.push(
          row(
            entry.name,
            entry.version,
            null,
            'mismatch',
            `lockfile entry ${packageLabel(entry.name, entry.version)} has no integrity hash to bind provenance to`,
          ),
        );
        continue;
      }
      if (allowEntry.integrity && !integrityMatches(allowEntry.integrity, entry.integrity)) {
        rows.push(
          row(
            entry.name,
            entry.version,
            entry.integrity,
            'mismatch',
            `lockfile integrity does not match the integrity pinned by policy for ${packageLabel(entry.name, entry.version)}`,
          ),
        );
        continue;
      }
      rows.push(
        row(
          entry.name,
          entry.version,
          entry.integrity,
          'unverified',
          'no attestation bundle was available to verify provenance',
        ),
      );
    }
  }

  return { rows, exempt };
}

function summarize(rows, exempt) {
  return {
    required: rows.length,
    verified: rows.filter((item) => item.status === 'verified').length,
    unverified: rows.filter((item) => item.status === 'unverified').length,
    missing: rows.filter((item) => item.status === 'missing').length,
    mismatch: rows.filter((item) => item.status === 'mismatch').length,
    exempt,
  };
}

export function exitCodeFor(rows) {
  if (rows.some((item) => item.status === 'missing' || item.status === 'mismatch')) return 1;
  if (rows.some((item) => item.status === 'unverified')) return 2;
  return 0;
}

export function runCheck({ lockfilePath, policyPath } = {}) {
  const policy = loadPolicy(policyPath);
  const lockfile = readLockfile(lockfilePath);
  const selected = policy.mode === 'all' ? fromAll(policy, lockfile) : fromAllowlist(policy, lockfile);
  const packages = dedupeRows(selected.rows).sort((left, right) => {
    const byName = left.package.localeCompare(right.package);
    if (byName !== 0) return byName;
    const byVersion = String(left.version ?? '').localeCompare(String(right.version ?? ''));
    if (byVersion !== 0) return byVersion;
    return left.status.localeCompare(right.status);
  });
  const summary = summarize(packages, selected.exempt);
  const exitCode = exitCodeFor(packages);

  return {
    ok: exitCode === 0,
    exitCode,
    lockfile: lockfilePath,
    policy: policyPath,
    lockfileVersion: lockfile.lockfileVersion,
    summary,
    packages,
  };
}

function pad(value, width) {
  return `${value}${' '.repeat(Math.max(0, width - value.length))}`;
}

export function formatTable(result) {
  const headers = ['PACKAGE', 'VERSION', 'INTEGRITY', 'STATUS'];
  const rows = result.packages.map((item) => [
    item.package,
    item.version ?? '-',
    item.integrity ?? '-',
    item.status,
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
    `${summary.required} required, ${summary.verified} verified, ${summary.unverified} unverified, ` +
      `${summary.missing} missing, ${summary.mismatch} mismatch` +
      (summary.exempt > 0 ? `, ${summary.exempt} exempt` : ''),
  );
  if (result.exitCode === 2 && summary.required > 0) {
    lines.push('cannot verify any required package: no attestation bundle was available');
  }
  return `${lines.join('\n')}\n`;
}
