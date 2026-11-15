// Offline verification of a Sigstore bundle:
//   - DSSE signature over the in-toto statement
//   - X.509 chain anchored in the configured trust root
//   - certificate validity at the transparency-log integration time
//   - Rekor signed entry timestamp (SET) over the canonicalized entry
//   - subject name/digest matching the lockfile entry
//   - certificate identity and SLSA predicate repository/workflow matching

import { createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import {
  VerificationError,
  firstString,
  isNonEmptyString,
  isPlainObject,
  normalizeRepository,
  normalizeWorkflow,
  parsePackageRef,
  workflowPathsEqual,
} from './util.js';

export function sha256(data) {
  return createHash('sha256').update(data).digest();
}

export function hashHex(algorithm, data) {
  return createHash(algorithm).update(data).digest('hex');
}

export function decodeBase64(value, what = 'base64 value') {
  if (!isNonEmptyString(value)) throw new VerificationError(`missing ${what}`);
  try {
    return Buffer.from(value, 'base64');
  } catch (error) {
    throw new VerificationError(`cannot decode ${what}: ${error.message}`);
  }
}

export function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'utf8'),
    type,
    Buffer.from(` ${payload.length} `, 'utf8'),
    payload,
  ]);
}

function certificateFromInput(input) {
  try {
    if (input instanceof X509Certificate) return input;
    if (Buffer.isBuffer(input)) return new X509Certificate(input);
    if (typeof input === 'string') return new X509Certificate(input);
    if (isPlainObject(input)) {
      if (input.rawBytes) return new X509Certificate(Buffer.from(input.rawBytes, 'base64'));
      if (input.der) return new X509Certificate(Buffer.from(input.der, 'base64'));
      if (input.pem) return new X509Certificate(input.pem);
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function bundleCertificateInputs(material) {
  const chain = material?.x509CertificateChain;
  if (Array.isArray(chain)) return chain;
  if (Array.isArray(chain?.certificates)) return chain.certificates;
  if (material?.x509Certificate) return [material.x509Certificate];
  if (material?.certificate) return [material.certificate];
  return [];
}

function certificateRaw(cert) {
  return cert.raw;
}

function sameCertificate(left, right) {
  return certificateRaw(left).equals(certificateRaw(right));
}

function isIssuedBy(child, issuer) {
  try {
    return child.checkIssued(issuer) && child.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

function certificateTime(cert, field) {
  const value = cert[field];
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function formatCertificate(cert) {
  const subject = cert.subject?.replace(/\n/gu, ', ') ?? '';
  const issuer = cert.issuer?.replace(/\n/gu, ', ') ?? '';
  return subject ? `${subject} (issuer: ${issuer})` : `issuer ${issuer}`;
}

function assertCertificateValidAt(cert, time) {
  const notBefore = certificateTime(cert, 'validFrom');
  const notAfter = certificateTime(cert, 'validTo');
  if (notBefore && time < notBefore) {
    throw new VerificationError(`certificate ${formatCertificate(cert)} is not valid before ${notBefore.toISOString()}`);
  }
  if (notAfter && time > notAfter) {
    throw new VerificationError(`certificate ${formatCertificate(cert)} expired at ${notAfter.toISOString()}`);
  }
}

// Build a chain from the leaf to one of the trust-root anchors.  Bundle chains
// often contain only the leaf; missing intermediates are found in the trusted
// root's certificate authorities.
export function buildCertificateChain(leaf, extraCertificates, trustRoot, signingTime) {
  const roots = trustRoot.roots;
  const candidates = [];
  const seen = new Set();
  for (const entry of extraCertificates.concat(trustRoot.intermediates, roots)) {
    const cert = entry instanceof X509Certificate ? entry : entry.cert;
    if (!cert) continue;
    const fingerprint = createHash('sha256').update(cert.raw).digest('hex');
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    candidates.push(cert);
  }

  const isRoot = (cert) => roots.some((entry) => sameCertificate(cert, entry.cert));

  function search(current, path, depth) {
    if (isRoot(current)) return path;
    if (depth >= 8) return undefined;
    for (const issuer of candidates) {
      if (sameCertificate(current, issuer)) continue;
      if (!isIssuedBy(current, issuer)) continue;
      if (issuer.ca === false) continue;
      const found = search(issuer, path.concat(issuer), depth + 1);
      if (found) return found;
    }
    return undefined;
  }

  const chain = search(leaf, [leaf], 0);
  if (!chain) {
    throw new VerificationError(
      `certificate chain for ${formatCertificate(leaf)} does not anchor in a trusted Sigstore root`,
    );
  }
  if (leaf.ca === true) throw new VerificationError('bundle signing certificate is a CA certificate');
  for (const cert of chain) assertCertificateValidAt(cert, signingTime);
  return chain;
}

export function certificateIdentities(cert) {
  const san = cert.subjectAltName ?? '';
  const identities = [];
  for (const match of san.matchAll(/URI:([^,\n]+)/gu)) {
    const uri = match[1].trim();
    identities.push(parseIdentityUri(uri));
  }
  return identities;
}

export function parseIdentityUri(uri) {
  let text = uri;
  let ref;
  const atRefs = text.indexOf('@refs/');
  if (atRefs >= 0) {
    ref = text.slice(atRefs + 1);
    text = text.slice(0, atRefs);
  }

  let url;
  try {
    url = new URL(text);
  } catch {
    return { uri, repository: normalizeRepository(text), workflow: undefined, ref };
  }
  const segments = url.pathname.split('/').filter(Boolean);
  let repository;
  let workflow;
  if (segments.length >= 4 && segments[2] === '.github' && segments[3] === 'workflows') {
    repository = `${url.hostname}/${segments[0]}/${segments[1]}`.toLowerCase();
    workflow = segments.slice(2).join('/');
  } else {
    repository = normalizeRepository(`${url.protocol}//${url.host}${url.pathname}`);
    workflow = undefined;
  }
  return { uri, repository, workflow, ref };
}

function refsEqual(expected, actual) {
  if (!expected || !actual) return false;
  if (expected === actual) return true;
  const shorten = (value) => value.replace(/^refs\/heads\//u, '').replace(/^refs\/tags\//u, '');
  return shorten(expected) === shorten(actual);
}

export function extractSource(statement) {
  const predicate = statement.predicate ?? {};
  const buildDefinition = predicate.buildDefinition ?? {};
  const external = buildDefinition.externalParameters ?? {};
  const workflow = external.workflow;

  let repository;
  let workflowPath;
  let ref;

  if (isNonEmptyString(workflow)) {
    repository = normalizeRepository(workflow);
  } else if (isPlainObject(workflow)) {
    repository = normalizeRepository(workflow.repository ?? workflow.uri);
    workflowPath = firstString(workflow.path, workflow.workflow, workflow.entryPoint);
    ref = firstString(workflow.ref, workflow.gitRef);
  }

  repository ??= normalizeRepository(
    external.sourceRepositoryURI ?? external.sourceRepository ?? external.repository,
  );
  workflowPath ??= firstString(external.workflowPath, external.buildConfig?.workflow);

  const configSource = predicate.invocation?.configSource;
  if (isPlainObject(configSource)) {
    repository ??= normalizeRepository(configSource.uri ?? configSource.repository);
    workflowPath ??= firstString(configSource.entryPoint, configSource.workflow, configSource.path);
    ref ??= firstString(configSource.ref, configSource.digest?.ref);
  }

  repository ??= normalizeRepository(
    predicate.repository ?? predicate.sourceRepository ?? predicate.sourceRepositoryUri ?? predicate.source,
  );
  workflowPath ??= firstString(
    predicate.workflow,
    predicate.workflowPath,
    predicate.buildConfig?.workflow,
    predicate.buildDefinition?.buildType?.workflow,
  );

  let commit;
  const dependencies = buildDefinition.resolvedDependencies ?? predicate.materials ?? [];
  if (Array.isArray(dependencies)) {
    for (const dependency of dependencies) {
      if (!isPlainObject(dependency)) continue;
      const digest = dependency.digest ?? {};
      commit = firstString(digest.gitCommit, digest.sha1, digest.sha256, digest.sha512);
      if (commit) break;
    }
  }
  commit ??= firstString(predicate.gitCommit, predicate.commit, configSource?.digest?.gitCommit);

  const invocationId =
    firstString(predicate.runDetails?.metadata?.invocationId) ??
    firstString(predicate.metadata?.buildInvocationId);

  return {
    repository,
    workflow: workflowPath ? normalizeWorkflow(workflowPath)?.path ?? workflowPath : undefined,
    workflowRef: ref,
    commit,
    invocationId,
    predicateType: statement.predicateType,
    raw: { repository: repository ?? null, workflow: workflowPath ?? null, ref: ref ?? null },
  };
}

function purlPackage(value) {
  if (!isNonEmptyString(value)) return undefined;
  let text = value.trim();
  if (text.startsWith('pkg:npm/')) text = text.slice('pkg:npm/'.length);
  try {
    text = decodeURIComponent(text);
  } catch {
    // keep as-is
  }
  return parsePackageRef(text);
}

// Match the signed in-toto subject (name + digest) against the lockfile entry.
// The digest comparison is what ties the attestation to the exact tarball in
// the lockfile; the name/version comparison prevents one package's statement
// from being used for another.
export function matchSubject(statement, name, version, lockfileDigests) {
  const subjects = Array.isArray(statement.subject) ? statement.subject : [];
  if (subjects.length === 0) {
    return { ok: false, reason: 'attestation statement has no subject' };
  }

  let nameMismatch;
  for (const subject of subjects) {
    if (!isPlainObject(subject)) continue;
    const ref = purlPackage(subject.name);
    if (!ref?.name) {
      nameMismatch ??= `subject name "${subject.name}" is not an npm package reference`;
      continue;
    }
    if (ref.name !== name) {
      nameMismatch ??= `attestation subject is ${ref.name}, not ${name}`;
      continue;
    }
    if (ref.version && version && ref.version !== version) {
      nameMismatch ??= `attestation subject is version ${ref.version}, not ${version}`;
      continue;
    }

    const digest = isPlainObject(subject.digest) ? subject.digest : {};
    let common = false;
    let mismatch;
    for (const algorithm of ['sha512', 'sha384', 'sha256', 'sha1']) {
      const expected = lockfileDigests[algorithm];
      if (!expected) continue;
      const actual = digest[algorithm];
      if (!actual) continue;
      common = true;
      if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
        mismatch = `${algorithm} digest ${String(actual).toLowerCase()} does not match lockfile integrity ${String(expected).toLowerCase()}`;
        break;
      }
    }
    if (!common) {
      return {
        ok: false,
        reason: `attestation subject has no digest algorithm in common with the lockfile integrity (${Object.keys(lockfileDigests).join(', ') || 'none'})`,
      };
    }
    if (mismatch) return { ok: false, reason: mismatch };
    return { ok: true, subject, packageName: ref.name, version: ref.version };
  }

  return { ok: false, reason: nameMismatch ?? `attestation subject does not name ${name}@${version}` };
}

// Compare the SLSA source and signing-certificate identity against policy.
// Both must agree when both carry the information: a statement can claim any
// repository, but the Fulcio certificate identity is what the OIDC issuer
// actually signed.
export function matchIdentity(source, cert, expected) {
  const failures = [];
  const expectedRepository = expected.repository;

  if (expectedRepository) {
    if (source.repository && source.repository !== expectedRepository) {
      failures.push(
        `attestation source repository ${source.repository} does not match policy ${expectedRepository}`,
      );
    }
    if (source.workflow && expected.workflow && !workflowPathsEqual(expected.workflow, source.workflow)) {
      failures.push(`attestation workflow ${source.workflow} does not match policy ${expected.workflow}`);
    }
    if (source.workflowRef && expected.workflowRef && !refsEqual(expected.workflowRef, source.workflowRef)) {
      failures.push(`attestation ref ${source.workflowRef} does not match policy ${expected.workflowRef}`);
    }
  }

  const identities = certificateIdentities(cert);
  if (expectedRepository || expected.workflow) {
    if (identities.length === 0) {
      failures.push('signing certificate has no URI subject alternative name to bind the source identity');
    } else {
      const matched = identities.some((identity) => {
        if (expectedRepository) {
          const sameRepo =
            identity.repository === expectedRepository ||
            identity.uri.toLowerCase().startsWith(`https://${expectedRepository}/`) ||
            identity.uri.toLowerCase().startsWith(`http://${expectedRepository}/`);
          if (!sameRepo) return false;
        }
        if (expected.workflow) {
          if (!identity.workflow) return false;
          if (!workflowPathsEqual(expected.workflow, identity.workflow)) return false;
        }
        if (expected.workflowRef && identity.ref && !refsEqual(expected.workflowRef, identity.ref)) return false;
        return true;
      });
      if (!matched) {
        failures.push(
          `signing certificate identity ${identities.map((identity) => identity.uri).join(', ')} does not match policy ${[
            expectedRepository,
            expected.workflow,
          ]
            .filter(Boolean)
            .join(' ')}`,
        );
      }
    }
  }

  return {
    ok: failures.length === 0,
    reason: failures.join('; '),
    failures,
    identities,
  };
}

function verifySignedEntryTimestamp(entry, trustedLog) {
  const set = entry.inclusionPromise?.signedEntryTimestamp;
  if (!isNonEmptyString(set)) {
    throw new VerificationError('transparency log entry has no signed inclusion promise');
  }
  const logIndex = Number(entry.logIndex);
  const integratedTime = Number(entry.integratedTime);
  if (!Number.isFinite(logIndex) || !Number.isFinite(integratedTime)) {
    throw new VerificationError('transparency log entry has invalid logIndex/integratedTime');
  }
  const body = entry.canonicalizedBody;
  if (!isNonEmptyString(body)) throw new VerificationError('transparency log entry has no body');

  // Rekor signs the JCS-canonicalized LogEntryAnon object, not just the body.
  const canonicalEntry = JSON.stringify({
    body,
    integratedTime,
    logID: trustedLog.keyId.toString('hex'),
    logIndex,
  });
  // Rekor v1 uses an ECDSA/P-256 key and signs with SHA-256.  Rekor v2 (the
  // log2025-* instances) can use Ed25519, where Node requires a null digest.
  const keyType = trustedLog.publicKey.asymmetricKeyType;
  const algorithm = keyType === 'ed25519' || keyType === 'ed448' ? null : 'sha256';
  let ok;
  try {
    ok = cryptoVerify(
      algorithm,
      Buffer.from(canonicalEntry, 'utf8'),
      trustedLog.publicKey,
      Buffer.from(set, 'base64'),
    );
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new VerificationError(
      `signed entry timestamp from ${trustedLog.baseUrl ?? 'the transparency log'} does not verify`,
    );
  }
  return { body: Buffer.from(body, 'base64'), logIndex, integratedTime };
}

function verifyTlogEntries(entries, trustRoot, payload) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return { verified: false, reason: 'bundle has no transparency log entry' };
  }
  if (trustRoot.tlogs.length === 0) {
    throw new VerificationError('bundle contains a transparency log entry but the trust root has no log keys');
  }

  const errors = [];
  for (const entry of entries) {
    try {
      if (!isPlainObject(entry)) throw new VerificationError('transparency log entry is not an object');
      const keyId = entry.logId?.keyId;
      if (!isNonEmptyString(keyId)) throw new VerificationError('transparency log entry has no logId');
      const keyIdBytes = Buffer.from(keyId, 'base64');
      const trustedLog = trustRoot.tlogs.find(
        (candidate) => candidate.keyId.length === keyIdBytes.length && candidate.keyId.equals(keyIdBytes),
      );
      if (!trustedLog) {
        throw new VerificationError(
          `transparency log ${keyId} is not present in the configured trust root`,
        );
      }
      const { body, logIndex, integratedTime } = verifySignedEntryTimestamp(entry, trustedLog);

      let parsed;
      try {
        parsed = JSON.parse(body.toString('utf8'));
      } catch (error) {
        throw new VerificationError(`transparency log entry body is not JSON: ${error.message}`);
      }
      // Rekor's DSSE entry stores payloadHash at spec.payloadHash; some npm
      // bundles wrap it under spec.content.  Accept either spelling rather
      // than silently skipping the binding between the log entry and payload.
      const payloadHash = parsed?.spec?.payloadHash ?? parsed?.spec?.content?.payloadHash;
      if (payloadHash?.value && payloadHash?.algorithm) {
        const algorithm = String(payloadHash.algorithm).toLowerCase();
        if (!['sha256', 'sha384', 'sha512'].includes(algorithm)) {
          throw new VerificationError(`unsupported payload hash algorithm ${payloadHash.algorithm}`);
        }
        const actual = hashHex(algorithm, payload);
        if (actual !== String(payloadHash.value).toLowerCase()) {
          throw new VerificationError('transparency log entry payload hash does not match the DSSE payload');
        }
      }

      return {
        verified: true,
        body: parsed,
        logIndex,
        integratedTime,
        logUrl: trustedLog.baseUrl,
        inclusionProof: Boolean(entry.inclusionProof),
        signedEntryTimestamp: true,
      };
    } catch (error) {
      errors.push(error.message);
    }
  }

  throw new VerificationError(`transparency log verification failed: ${errors.join('; ')}`);
}

function signatureHashAlgorithm(cert) {
  const key = cert.publicKey;
  const type = key.asymmetricKeyType;
  if (type === 'ed25519' || type === 'ed448') return null;
  if (type === 'ec') {
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (curve === 'secp384r1') return 'sha384';
    if (curve === 'secp521r1') return 'sha512';
    return 'sha256';
  }
  return 'sha256';
}

function verifyDsseSignature(envelope, leaf) {
  const payload = typeof envelope.payload === 'string' ? Buffer.from(envelope.payload, 'base64') : undefined;
  if (!payload) throw new VerificationError('DSSE envelope has no payload');
  const payloadType = firstString(envelope.payloadType) ?? 'application/vnd.in-toto+json';
  const signatures = Array.isArray(envelope.signatures) ? envelope.signatures : [];
  if (signatures.length === 0) throw new VerificationError('DSSE envelope has no signatures');
  const pae = dssePae(payloadType, payload);
  const algorithm = signatureHashAlgorithm(leaf);
  let lastError;
  for (const signature of signatures) {
    if (!isNonEmptyString(signature?.sig)) continue;
    try {
      if (cryptoVerify(algorithm, pae, leaf.publicKey, Buffer.from(signature.sig, 'base64'))) {
        return { payload, payloadType };
      }
      lastError = new VerificationError('DSSE signature does not verify');
    } catch (error) {
      lastError = new VerificationError(`DSSE signature verification failed: ${error.message}`);
    }
  }
  throw lastError ?? new VerificationError('DSSE envelope has no usable signature');
}

export function verifyBundle(bundle, trustRoot, options = {}) {
  if (!isPlainObject(bundle)) throw new VerificationError('attestation bundle is missing or not an object');
  const material = bundle.verificationMaterial ?? {};
  const envelope = bundle.dsseEnvelope;
  if (!isPlainObject(envelope)) throw new VerificationError('attestation bundle has no DSSE envelope');

  const certInputs = bundleCertificateInputs(material);
  if (certInputs.length === 0) {
    throw new VerificationError(
      'attestation bundle has no X.509 certificate chain; key-based bundles cannot be verified offline against a trust root',
    );
  }
  const leaf = certificateFromInput(certInputs[0]);
  if (!leaf) throw new VerificationError('attestation bundle signing certificate is not a valid X.509 certificate');

  const tlogEntries = Array.isArray(material.tlogEntries) ? material.tlogEntries : [];
  let signingTime = options.now ?? new Date();
  const firstIntegrated = Number(tlogEntries[0]?.integratedTime);
  if (Number.isFinite(firstIntegrated) && firstIntegrated > 0) {
    signingTime = new Date(firstIntegrated * 1000);
  }

  const extra = certInputs.slice(1).map((input) => certificateFromInput(input)).filter(Boolean);
  const chain = buildCertificateChain(leaf, extra, trustRoot, signingTime);

  const { payload, payloadType } = verifyDsseSignature(envelope, leaf);
  let statement;
  try {
    statement = JSON.parse(payload.toString('utf8'));
  } catch (error) {
    throw new VerificationError(`attestation statement is not JSON: ${error.message}`);
  }
  if (!isPlainObject(statement)) throw new VerificationError('attestation statement is not a JSON object');
  if (!Array.isArray(statement.subject)) throw new VerificationError('attestation statement has no subject array');

  const tlog = verifyTlogEntries(tlogEntries, trustRoot, payload);

  return {
    statement,
    payload,
    payloadType,
    certificate: leaf,
    chain,
    signingTime,
    tlog,
    identities: certificateIdentities(leaf),
  };
}
