#!/usr/bin/env node
import { readFileSync } from 'node:fs';

const VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;

const USAGE = `lockfile-provenance-gate: a small developer tool

Usage:
  lockfile-provenance-gate --help
  lockfile-provenance-gate --version

MVP features:
  - \`provenance-gate check package-lock.json --policy provenance.json\` resolves each lockfile entry to its registry attestation and verifies the Sigstore bundle offline against the npm subject digest and the lockfile integrity hash.
  - Policy file requires either all packages or a named allowlist to carry provenance, plus expected source repository, workflow path, and an explicit exemption list with reasons.
  - Emits a per-package verdict table and a \`--json\` receipt (package, version, commit, source repo, workflow, verified, reason) with exit codes 0 pass / 1 policy failure / 2 fetch or verification error.
  - \`--cache <dir>\` stores fetched bundles and the Sigstore trust root so verification can rerun hermetically in CI without re-hitting the registry; ships fixture bundles so \`node --test\` proves pass, missing-attestation, and repo-mismatch paths with no network.
  - Never installs or executes the audited packages: it reads the lockfile and registry metadata only, so it is safe to run before install.
`;

const args = process.argv.slice(2);
if (args.includes('--version') || args.includes('-v')) {
  console.log(VERSION);
} else {
  console.log(USAGE);
}
