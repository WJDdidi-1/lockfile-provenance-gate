// Load Sigstore trust material from a trusted root JSON file, a PEM bundle, or
// the copy of the public-good root shipped with this package.  Parsing is
// intentionally tolerant of the trusted_root.json shape and plain PEM, because
// CI users commonly point --trust-root at either.

import { existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash, createPublicKey, X509Certificate } from 'node:crypto';
import path from 'node:path';
import { GateError, isPlainObject } from './util.js';

const BUILTIN_URL = new URL('./trusted-root.json', import.meta.url);

const CACHE_TRUST_NAMES = [
  'trusted-root.json',
  'trusted_root.json',
  'trust-root.json',
  'trust_root.json',
  'sigstore-trusted-root.json',
  'sigstore_trusted_root.json',
  'trustedroot.json',
  'fulcio.pem',
  'fulcio.crt',
  'ca.pem',
  'root.pem',
  'roots.pem',
];

function certificateFromInput(input) {
  try {
    if (Buffer.isBuffer(input)) return new X509Certificate(input);
    if (isPlainObject(input)) {
      if (input.rawBytes) return new X509Certificate(Buffer.from(input.rawBytes, 'base64'));
      if (input.der) return new X509Certificate(Buffer.from(input.der, 'base64'));
      if (input.pem) return new X509Certificate(input.pem);
      return undefined;
    }
    if (typeof input === 'string') return new X509Certificate(input);
  } catch {
    return undefined;
  }
  return undefined;
}

function certificateInputs(value, out = []) {
  if (value === undefined || value === null) return out;
  if (typeof value === 'string' || Buffer.isBuffer(value)) {
    out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) certificateInputs(item, out);
    return out;
  }
  if (!isPlainObject(value)) return out;
  if (value.rawBytes || value.der || value.pem) {
    out.push(value);
    return out;
  }
  if (value.certificateAuthorities) certificateInputs(value.certificateAuthorities, out);
  if (value.certificateChain) certificateInputs(value.certificateChain, out);
  if (value.certChain) certificateInputs(value.certChain, out);
  if (value.certificates) certificateInputs(value.certificates, out);
  if (value.certificate) certificateInputs(value.certificate, out);
  if (value.certs) certificateInputs(value.certs, out);
  if (value.fulcioRoots) certificateInputs(value.fulcioRoots, out);
  return out;
}

function splitPem(text) {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/gu) ?? [];
}

function dedupeCertificates(certificates) {
  const seen = new Set();
  const result = [];
  for (const cert of certificates) {
    const key = createHash('sha256').update(cert.raw).digest('hex');
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ cert, der: cert.raw, pem: cert.toString(), fingerprint: key });
  }
  return result;
}

function isSelfSigned(cert) {
  try {
    return cert.checkIssued(cert) && cert.verify(cert.publicKey);
  } catch {
    return false;
  }
}

function parseTrustedRootJson(value, source) {
  const certificates = [];
  for (const input of certificateInputs(value)) {
    if (typeof input === 'string') {
      for (const pem of splitPem(input)) {
        const cert = certificateFromInput(pem);
        if (cert) certificates.push(cert);
      }
    } else {
      const cert = certificateFromInput(input);
      if (cert) certificates.push(cert);
    }
  }

  const deduped = dedupeCertificates(certificates);
  if (deduped.length === 0) {
    throw new GateError(`trust root ${source} contains no X.509 certificates`);
  }

  const selfSigned = deduped.filter((item) => isSelfSigned(item.cert));
  const roots = selfSigned.length > 0 ? selfSigned : deduped;
  const rootFingerprints = new Set(roots.map((item) => item.fingerprint));
  const intermediates = deduped.filter((item) => !rootFingerprints.has(item.fingerprint));

  const tlogs = [];
  const rawTlogs = [
    ...(Array.isArray(value?.tlogs) ? value.tlogs : []),
    ...(Array.isArray(value?.transparencyLogs) ? value.transparencyLogs : []),
  ];
  for (const entry of rawTlogs) {
    if (!isPlainObject(entry)) continue;
    let keyBytes;
    if (isPlainObject(entry.publicKey)) {
      if (entry.publicKey.rawBytes) keyBytes = Buffer.from(entry.publicKey.rawBytes, 'base64');
      else if (typeof entry.publicKey.pem === 'string') keyBytes = Buffer.from(entry.publicKey.pem);
    } else if (typeof entry.publicKey === 'string') {
      keyBytes = entry.publicKey.includes('BEGIN PUBLIC KEY')
        ? Buffer.from(entry.publicKey)
        : Buffer.from(entry.publicKey, 'base64');
    } else if (entry.publicKeyRawBytes) {
      keyBytes = Buffer.from(entry.publicKeyRawBytes, 'base64');
    }
    if (!keyBytes) continue;

    let publicKey;
    try {
      publicKey = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
    } catch {
      try {
        publicKey = createPublicKey(keyBytes.toString('utf8'));
      } catch {
        continue;
      }
    }

    let keyId;
    if (entry.logId?.keyId) keyId = Buffer.from(entry.logId.keyId, 'base64');
    else if (entry.logID?.keyId) keyId = Buffer.from(entry.logID.keyId, 'base64');
    else if (typeof entry.logId === 'string') keyId = Buffer.from(entry.logId, 'base64');
    else keyId = createHash('sha256').update(keyBytes).digest();

    tlogs.push({
      keyId,
      keyIdHex: keyId.toString('hex'),
      publicKey,
      baseUrl: entry.baseUrl ?? entry.url,
      raw: entry,
    });
  }

  return {
    source,
    sourceType: 'json',
    roots,
    intermediates,
    tlogs,
    raw: value,
  };
}

export function parseTrustRoot(value, source = '<trust-root>') {
  if (isPlainObject(value)) return parseTrustedRootJson(value, source);
  if (Buffer.isBuffer(value)) value = value.toString('utf8');
  if (typeof value !== 'string') throw new GateError(`trust root ${source} has an unsupported format`);

  const text = value.trim();
  if (text.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      throw new GateError(`cannot parse trust root ${source}: ${error.message}`);
    }
    return parseTrustedRootJson(parsed, source);
  }

  const pemCerts = splitPem(text);
  if (pemCerts.length > 0) return parseTrustedRootJson({ certificates: pemCerts }, source);

  const cert = certificateFromInput(Buffer.from(text, 'base64'));
  if (cert) return parseTrustedRootJson({ certificates: [cert] }, source);
  throw new GateError(`trust root ${source} contains no PEM or DER certificates`);
}

function readTrustRootFile(file) {
  let info;
  try {
    info = statSync(file);
  } catch (error) {
    throw new GateError(`cannot read trust root ${file}: ${error.message}`);
  }
  if (info.isDirectory()) {
    for (const name of CACHE_TRUST_NAMES) {
      const candidate = path.join(file, name);
      if (existsSync(candidate)) return readTrustRootFile(candidate);
    }
    throw new GateError(`trust root directory ${file} contains no recognized trust root file`);
  }
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    throw new GateError(`cannot read trust root ${file}: ${error.message}`);
  }
  return parseTrustRoot(text, file);
}

function loadBuiltin() {
  return parseTrustRoot(readFileSync(BUILTIN_URL, 'utf8'), 'built-in Sigstore public-good trust root');
}

export function loadTrustRoot({ explicit, policyTrustRoot, cacheDir, env = process.env } = {}) {
  const requested = explicit ?? policyTrustRoot ?? env.PROVENANCE_GATE_TRUST_ROOT ?? env.SIGSTORE_TRUST_ROOT;
  if (requested) {
    if (isPlainObject(requested)) return parseTrustRoot(requested, 'policy trustRoot');
    if (typeof requested === 'string') {
      const inline = requested.trim();
      if (inline.startsWith('{') || inline.includes('BEGIN CERTIFICATE')) {
        return parseTrustRoot(inline, 'inline trust root');
      }
    }
    return readTrustRootFile(path.resolve(String(requested)));
  }

  if (cacheDir) {
    for (const name of CACHE_TRUST_NAMES) {
      const candidate = path.join(cacheDir, name);
      if (existsSync(candidate)) return readTrustRootFile(candidate);
    }
    for (const directory of ['trust', 'sigstore', 'trust-root']) {
      const candidate = path.join(cacheDir, directory);
      if (existsSync(candidate)) {
        try {
          return readTrustRootFile(candidate);
        } catch {
          // try the next candidate
        }
      }
    }
  }

  return loadBuiltin();
}

// Persist the trust root into the cache so a later --offline run is hermetic.
// Always overwrite: if the caller supplied a different --trust-root this run,
// the cache must describe the anchors this run actually verified against.
export function cacheTrustRoot(cacheDir, trustRoot) {
  if (!cacheDir) return undefined;
  const target = path.join(cacheDir, 'trusted-root.json');
  let payload;
  if (isPlainObject(trustRoot.raw)) {
    payload = trustRoot.raw;
  } else {
    payload = {
      certificates: trustRoot.roots.concat(trustRoot.intermediates).map((item) => item.pem),
      tlogs: trustRoot.tlogs.map((entry) => ({
        baseUrl: entry.baseUrl,
        publicKey: { rawBytes: entry.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') },
        logId: { keyId: entry.keyId.toString('base64') },
      })),
    };
  }
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(temporary, `${JSON.stringify(payload, null, 2)}\n`);
    renameSync(temporary, target);
    return target;
  } catch (error) {
    try {
      if (existsSync(temporary)) unlinkSync(temporary);
    } catch {
      // Best effort cleanup; the original write error is the useful one.
    }
    throw new GateError(`cannot write cached trust root ${target}: ${error.message}`);
  }
}
