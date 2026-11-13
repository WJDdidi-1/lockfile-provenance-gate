# lockfile-provenance-gate

Gate npm lockfiles on provenance bound to the repo you actually trust.

## Who it is for

Maintainers of devcontainers, Helm charts, and CLI wrappers who vendor someone else's npm package (e.g. hoshiori-dev verifying the opencode package it ships) and need CI to prove that the tarball came from the expected upstream repo and commit, not just from some registry uploader.

## The problem

npm now publishes Sigstore provenance for many packages, but nothing in a normal terminal workflow answers the question a consumer actually has: 'is this exact lockfile entry attested, and does its attestation name the upstream repository and workflow I trust?' Verification today means hand-reading registry JSON or trusting a green check on the npm website.

## Why not the obvious answer

npm's built-in `npm audit signatures` is the obvious answer and it does verify registry signatures and attestation bundles for installed packages, but it is all-or-nothing over the installed tree, has no notion of an expected source repository or workflow path, cannot scope the requirement to the handful of packages you actually vendor, and emits a pass/fail count rather than a machine-readable receipt. cosign/sigstore CLI can verify a bundle you already have but will not resolve a package-lock.json, match subject integrity to lockfile entries, or apply a repo allowlist. Neither gives a CI gat

## Install

```sh
npm install -g lockfile-provenance-gate
```

## Use

```sh
lockfile-provenance-gate --help
```

## What the MVP does

- `provenance-gate check package-lock.json --policy provenance.json` resolves each lockfile entry to its registry attestation and verifies the Sigstore bundle offline against the npm subject digest and the lockfile integrity hash.
- Policy file requires either all packages or a named allowlist to carry provenance, plus expected source repository, workflow path, and an explicit exemption list with reasons.
- Emits a per-package verdict table and a `--json` receipt (package, version, commit, source repo, workflow, verified, reason) with exit codes 0 pass / 1 policy failure / 2 fetch or verification error.
- `--cache <dir>` stores fetched bundles and the Sigstore trust root so verification can rerun hermetically in CI without re-hitting the registry; ships fixture bundles so `node --test` proves pass, missing-attestation, and repo-mismatch paths with no network.
- Never installs or executes the audited packages: it reads the lockfile and registry metadata only, so it is safe to run before install.

## How we know it works

`node bin/provenance-gate.js check fixtures/good/package-lock.json --policy fixtures/good/policy.json --cache fixtures/bundles` exits 0 and prints one verified line per required package; `node bin/provenance-gate.js check fixtures/bad/package-lock.json --policy fixtures/bad/policy.json --cache fixtures/bundles` exits 1 naming the package whose attestation is missing or whose source repo mismatches

## Status

Early MVP. The features above are the scope; anything not listed is not built yet.

## Licence

Apache-2.0.
