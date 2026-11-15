// Load and validate provenance policy files.
//
// A policy either requires provenance for every registry package in the
// lockfile ("all") or for a named allowlist.  A hand-written policy is hard to
// get subtly wrong: common spellings are accepted, but anything ambiguous is
// rejected instead of being silently ignored.  A policy that does not actually
// constrain provenance is worse than no policy.

import path from 'node:path';
import {
  firstString,
  isNonEmptyString,
  isPlainObject,
  normalizeRepository,
  normalizeWorkflow,
  parsePackageRef,
  PolicyError,
  readJsonFile,
  validateIntegrity,
} from './util.js';

function readPolicyJson(file) {
  try {
    return readJsonFile(file, 'policy file');
  } catch (error) {
    throw new PolicyError(error.message);
  }
}

function aliases(object, keys) {
  if (!isPlainObject(object)) return undefined;
  for (const key of keys) {
    if (isNonEmptyString(object[key])) return object[key].trim();
  }
  return undefined;
}

function normalizeMode(policy) {
  let mode;
  if (isNonEmptyString(policy.mode)) {
    const value = policy.mode.trim().toLowerCase();
    if (['all', 'every', 'everything', 'require-all', 'require_all'].includes(value)) mode = 'all';
    else if (['allowlist', 'allow-list', 'list', 'named', 'explicit', 'some'].includes(value)) mode = 'allowlist';
    else throw new PolicyError(`unknown policy mode "${policy.mode}" (expected "all" or "allowlist")`);
  }

  if (!mode) {
    if (policy.requireAll === true || policy.allPackages === true || policy.all === true) mode = 'all';
    else if (isNonEmptyString(policy.require)) {
      const value = policy.require.trim().toLowerCase();
      if (['all', 'everything', 'every'].includes(value)) mode = 'all';
      else if (['allowlist', 'allow-list', 'list', 'named'].includes(value)) mode = 'allowlist';
    }
  }

  if (!mode && isPlainObject(policy.require)) {
    if (policy.require.all === true) mode = 'all';
    else if (
      Array.isArray(policy.require.packages) ||
      isPlainObject(policy.require.packages) ||
      Array.isArray(policy.require.allowlist)
    ) {
      mode = 'allowlist';
    }
  }

  if (!mode && Array.isArray(policy.require)) mode = 'allowlist';
  for (const key of [
    'allowlist',
    'allowedPackages',
    'requirePackages',
    'requiredPackages',
    'requires',
    'required',
    'allow',
    'include',
    'packages',
  ]) {
    if (!mode && policy[key] !== undefined) mode = 'allowlist';
  }
  if (!mode) {
    throw new PolicyError(
      'policy must require provenance for all packages or for a named allowlist (set "mode": "all" or "mode": "allowlist" with an allowlist)',
    );
  }
  return mode;
}

function optionSource(input) {
  if (isPlainObject(input)) {
    return firstString(
      input.sourceRepository,
      input.sourceRepositoryUri,
      input.sourceRepositoryURI,
      input.expectedRepository,
      input.repository,
      input.repo,
      input.uri,
    );
  }
  return isNonEmptyString(input) ? input : undefined;
}

function optionWorkflow(input) {
  if (isPlainObject(input)) {
    return firstString(input.workflow, input.workflowPath, input.workflowFile, input.path, input.entryPoint);
  }
  return isNonEmptyString(input) ? input : undefined;
}

function extractGlobalSource(policy) {
  const sourceObject = isPlainObject(policy.source) ? policy.source : undefined;
  const expectedObject = isPlainObject(policy.expected) ? policy.expected : undefined;
  const repository = firstString(
    aliases(policy, [
      'sourceRepository',
      'sourceRepositoryUri',
      'sourceRepositoryURI',
      'expectedRepository',
      'trustedRepository',
    ]),
    optionSource(policy.repository),
    optionSource(policy.source),
    optionSource(expectedObject),
  );
  const workflow = firstString(
    aliases(policy, ['workflow', 'workflowPath', 'workflowFile', 'expectedWorkflow', 'expectedWorkflowPath']),
    optionWorkflow(sourceObject),
    optionWorkflow(policy.source),
    optionWorkflow(expectedObject),
  );
  const ref = firstString(policy.ref, policy.gitRef, sourceObject?.ref, expectedObject?.ref);
  return { repository, workflow, ref };
}

function packageObjectEntries(value) {
  if (Array.isArray(value)) return value;
  if (!isPlainObject(value)) return [];
  return Object.entries(value).map(([name, entry]) => {
    if (entry === true || entry === null) return { name };
    if (isNonEmptyString(entry)) {
      // { "left-pad": "1.3.0" } uses the key as the package name.  A full
      // "name@version" string in the value is treated as a package reference.
      const ref = parsePackageRef(entry);
      if (ref?.version && ref.name === name) return { name, version: ref.version };
      return { name, version: entry };
    }
    if (isPlainObject(entry)) return { name, ...entry };
    return { name };
  });
}

function normalizeAllowEntry(entry, index) {
  if (isNonEmptyString(entry)) {
    const ref = parsePackageRef(entry);
    if (!ref?.name) throw new PolicyError(`allowlist entry ${index + 1} ("${entry}") is not a package name`);
    return { ...ref, raw: entry };
  }
  if (!isPlainObject(entry)) {
    throw new PolicyError(`allowlist entry ${index + 1} must be a package name or an object`);
  }
  const rawName = firstString(entry.name, entry.package, entry.packageName, entry.id);
  const ref = parsePackageRef(rawName);
  if (!ref?.name) throw new PolicyError(`allowlist entry ${index + 1} has no package name`);
  const version = firstString(entry.version, entry.versions?.[0], ref.version);
  const integrity = validateIntegrity(firstString(entry.integrity, entry.expectedIntegrity, entry.sri));
  const repository = firstString(
    entry.sourceRepository,
    entry.sourceRepositoryUri,
    entry.expectedRepository,
    entry.repository,
    entry.repo,
  );
  const workflow = firstString(entry.workflow, entry.workflowPath, entry.expectedWorkflow, entry.workflowFile);
  const workflowRef = firstString(entry.ref, entry.gitRef);
  return {
    name: ref.name,
    version,
    integrity,
    repository,
    workflow,
    ref: workflowRef,
    raw: entry,
  };
}

function extractAllowlist(policy) {
  const candidates = [
    policy.allowlist,
    policy.allowedPackages,
    policy.requirePackages,
    policy.requiredPackages,
    policy.requires,
    policy.required,
    policy.allow,
    policy.include,
    policy.packages,
    Array.isArray(policy.require) ? policy.require : undefined,
    isPlainObject(policy.require) ? policy.require.packages ?? policy.require.allowlist : undefined,
  ];
  const source = candidates.find((candidate) => candidate !== undefined);
  if (source === undefined) return [];
  return packageObjectEntries(source).map(normalizeAllowEntry);
}

function normalizeExemption(entry, index) {
  if (isNonEmptyString(entry)) {
    throw new PolicyError(
      `exemption ${index + 1} ("${entry}") must include a reason (use {"package": "...", "reason": "..."})`,
    );
  }
  if (!isPlainObject(entry)) throw new PolicyError(`exemption ${index + 1} must be an object with a reason`);
  const name = firstString(entry.name, entry.package, entry.packageName, entry.id);
  if (!name) throw new PolicyError(`exemption ${index + 1} has no package name`);
  const version = firstString(entry.version);
  const reason = firstString(entry.reason, entry.justification, entry.why);
  if (!reason) {
    throw new PolicyError(`exemption for ${version ? `${name}@${version}` : name} must include a non-empty reason`);
  }
  return { name, version, reason, raw: entry };
}

function extractExemptions(policy) {
  const value =
    policy.exemptions ?? policy.exempt ?? policy.exempted ?? policy.ignore ?? policy.ignored ?? policy.waivers;
  if (value === undefined) return [];
  if (Array.isArray(value)) return value.map(normalizeExemption);
  if (isPlainObject(value)) {
    return Object.entries(value).flatMap(([name, entry], index) => {
      // {"left-pad": false} is a readable way to say "not exempt".
      if (entry === false) return [];
      const ref = parsePackageRef(name);
      const packageName = ref?.name ?? name;
      if (isNonEmptyString(entry)) {
        return [normalizeExemption({ package: packageName, version: ref?.version, reason: entry }, index)];
      }
      if (isPlainObject(entry)) {
        return [normalizeExemption({ package: packageName, version: ref?.version, ...entry }, index)];
      }
      return [normalizeExemption({ package: packageName, version: ref?.version }, index)];
    });
  }
  throw new PolicyError('exemptions must be an array or an object keyed by package');
}

function boolOption(policy, names, fallback) {
  for (const name of names) {
    if (typeof policy[name] === 'boolean') return policy[name];
  }
  return fallback;
}

function normalizeRegistry(policy) {
  let value = aliases(policy, ['registry', 'registryUrl', 'npmRegistry']);
  if (isPlainObject(policy.registry)) value = firstString(policy.registry.url, policy.registry.uri);
  if (!value) return undefined;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new PolicyError(`registry "${value}" is not a valid URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new PolicyError(`registry "${value}" must use http:// or https://`);
  }
  return url.toString().replace(/\/+$/u, '');
}

function normalizeTrustRoot(policy, policyFile) {
  const value =
    policy.trustRoot ??
    policy.trustedRoot ??
    policy['trust-root'] ??
    policy.sigstoreTrustRoot ??
    policy.caFile ??
    policy.ca;
  if (value === undefined) return undefined;
  if (isNonEmptyString(value) && !value.trim().startsWith('{')) {
    return path.isAbsolute(value) ? value : path.resolve(path.dirname(policyFile), value);
  }
  return value;
}

export function validatePolicy(value, policyFile = '<policy>') {
  if (!isPlainObject(value)) throw new PolicyError(`policy ${policyFile} must be a JSON object`);
  const mode = normalizeMode(value);
  const allowlist = mode === 'allowlist' ? extractAllowlist(value) : [];
  if (mode === 'allowlist' && allowlist.length === 0) {
    throw new PolicyError('policy mode is "allowlist" but the allowlist is empty');
  }
  const exemptions = extractExemptions(value);
  const globalSource = extractGlobalSource(value);

  let repository;
  if (globalSource.repository) {
    repository = normalizeRepository(globalSource.repository);
    if (!repository) {
      throw new PolicyError(`sourceRepository "${globalSource.repository}" is not a repository URL`);
    }
  }
  let workflow;
  if (globalSource.workflow) {
    workflow = normalizeWorkflow(globalSource.workflow);
    if (!workflow?.path) {
      throw new PolicyError(`workflow "${globalSource.workflow}" is not a workflow path`);
    }
  }

  for (const entry of allowlist) {
    if (entry.repository) {
      entry.normalizedRepository = normalizeRepository(entry.repository);
      if (!entry.normalizedRepository) throw new PolicyError(`repository for ${entry.name} is not a repository URL`);
    }
    if (entry.workflow) {
      entry.normalizedWorkflow = normalizeWorkflow(entry.workflow);
      if (!entry.normalizedWorkflow?.path) throw new PolicyError(`workflow for ${entry.name} is not a workflow path`);
    }
  }

  return {
    file: policyFile,
    raw: value,
    mode,
    allowlist,
    exemptions,
    sourceRepository: globalSource.repository,
    repository,
    sourceRepositoryRef: globalSource.ref ?? workflow?.ref,
    workflow: workflow?.path,
    workflowRef: globalSource.ref ?? workflow?.ref,
    trustRoot: normalizeTrustRoot(value, policyFile),
    registry: normalizeRegistry(value),
    includeDev: boolOption(value, ['includeDev', 'dev'], true),
    includeOptional: boolOption(value, ['includeOptional', 'optional'], true),
    includePeer: boolOption(value, ['includePeer', 'peer'], true),
  };
}

export function loadPolicy(file) {
  return validatePolicy(readPolicyJson(file), file);
}

export function findExemption(policy, name, version) {
  return policy.exemptions.find(
    (entry) => entry.name === name && (entry.version === undefined || entry.version === version),
  );
}

// Select the lockfile entries the policy requires to carry provenance.
// Allowlisted packages that are absent from the lockfile are returned as
// missing targets so a typo cannot silently weaken the gate.
export function selectTargets(policy, lockfile) {
  const eligible = lockfile.entries.filter((entry) => {
    if (!policy.includeDev && entry.dev) return false;
    if (!policy.includeOptional && entry.optional) return false;
    if (!policy.includePeer && entry.peer) return false;
    return true;
  });

  if (policy.mode === 'all') {
    return { targets: eligible.map((entry) => ({ entry, allowEntry: undefined })), missing: [] };
  }

  const targets = [];
  const missing = [];
  for (const allowEntry of policy.allowlist) {
    const matches = eligible.filter(
      (entry) =>
        entry.name === allowEntry.name &&
        (allowEntry.version === undefined || entry.version === allowEntry.version),
    );
    if (matches.length === 0) {
      missing.push(allowEntry);
      continue;
    }
    for (const entry of matches) targets.push({ entry, allowEntry });
  }

  const seen = new Set();
  const unique = [];
  for (const target of targets) {
    const key = `${target.entry.name}\u0000${target.entry.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(target);
  }
  return { targets: unique, missing };
}

export function expectedIdentity(policy, allowEntry) {
  const repository =
    allowEntry?.normalizedRepository ??
    (allowEntry?.repository ? normalizeRepository(allowEntry.repository) : policy.repository);
  const workflow =
    allowEntry?.normalizedWorkflow?.path ??
    (allowEntry?.workflow ? normalizeWorkflow(allowEntry.workflow)?.path : policy.workflow);
  const workflowRef =
    allowEntry?.ref ?? allowEntry?.normalizedWorkflow?.ref ?? policy.workflowRef;
  return { repository, workflow, workflowRef };
}
