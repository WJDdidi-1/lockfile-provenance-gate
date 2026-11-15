# lockfile-provenance-gate

[![CI](https://github.com/WJDdidi-1/lockfile-provenance-gate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WJDdidi-1/lockfile-provenance-gate/actions/workflows/ci.yml)

Gate npm lockfiles on Sigstore provenance bound to the repository and workflow you actually trust.

For each dependency your policy covers, `provenance-gate` answers three questions from a plain terminal:

1. Is there a build provenance attestation for this exact version?
2. Does the signed subject digest match the tarball integrity in `package-lock.json`?
3. Was the attestation signed by the upstream repository and workflow named in the policy?

It reads the lockfile and registry metadata only. It never installs or executes the packages it audits.

## Who it is for

Maintainers of devcontainers, Helm charts, and CLI wrappers who vendor someone else's npm package and need CI to prove that the tarball came from the expected upstream repo and workflow, not just from some registry uploader. It is also useful for pinning provenance requirements to a short list of security-sensitive dependencies instead of demanding it for the whole tree.

## Why not `npm audit signatures`?

`npm audit signatures` verifies registry signatures and attestation bundles for the packages already installed. It is all-or-nothing over that installed tree, has no notion of an expected source repository or workflow path, cannot scope the requirement to the handful of packages you actually vendor, and emits a pass/fail count rather than a machine-readable receipt. The cosign/Sigstore CLI can verify a bundle you already have, but it will not resolve a `package-lock.json`, match the attestation subject to a lockfile integrity hash, or apply a repository allowlist.

This tool checks the lockfile before install and binds each verdict to the repository and workflow you name.

## Install

Requires Node.js 18 or newer. There are no runtime dependencies.

```sh
npm install --global lockfile-provenance-gate
lockfile-provenance-gate --version
```

Or run it without a global install:

```sh
npx lockfile-provenance-gate --help
```

Both `lockfile-provenance-gate` and the shorter `provenance-gate` are installed and invoke the same CLI. Examples below use `provenance-gate`.

## Runnable examples

[`examples/`](examples/) contains two self-contained, offline walkthroughs: one package that passes, and one whose validly signed *publish* attestation is not build provenance (exit 1). From a clone, with no install and no network:

```sh
npm run example
```

The runner asserts both documented exit codes, so the examples cannot silently drift. Each directory has its own lockfile, policy, and cache; see [examples/README.md](examples/README.md) for the full output and how to adapt the policy to your own lockfile. The bundles are generated test data, not real registry attestations, and the fixture trust root must not be used in production.

## Quick start: a real check session

The repository ships generated, Sigstore-style test bundles signed by a throwaway fixture PKI. They are **test data, not real registry attestations**. From a clone of this repository, this succeeds offline:

```console
$ node bin/provenance-gate.js check test/fixtures/offline/package-lock.json \
    --policy test/fixtures/offline/policy.json \
    --cache test/fixtures/bundles \
    --offline

PACKAGE       VERSION  INTEGRITY                                                                                        STATUS    REASON
------------  -------  -----------------------------------------------------------------------------------------------  --------  -------------------
@acme/widget  1.2.3    sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==  verified  provenance verified

1 required, 1 verified, 0 missing, 0 mismatch, 0 error
$ echo $?
0
```

A validly signed attestation is not enough if it is the wrong kind of attestation. npm's publish attestation has a different predicate and does not satisfy a build-provenance policy:

```console
$ node bin/provenance-gate.js check test/fixtures/publish-only/package-lock.json \
    --policy test/fixtures/publish-only/policy.json \
    --cache test/fixtures/bundles \
    --offline

PACKAGE       VERSION  INTEGRITY                                                                                        STATUS    REASON
------------  -------  -----------------------------------------------------------------------------------------------  --------  --------------------------------------------------------------------------
publish-only  1.0.0    sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==  mismatch  no verifiable Sigstore provenance attestation found for publish-only@1.0.0

1 required, 0 verified, 0 missing, 1 mismatch, 0 error
$ echo $?
1
```

For a real project, point it at your own lockfile and policy:

```sh
# First run: fetch missing bundles and the Sigstore trust root into the cache.
provenance-gate check package-lock.json --policy provenance.json --cache .provenance-cache

# Later runs, including CI: verify hermetically with no registry access.
provenance-gate check package-lock.json --policy provenance.json --cache .provenance-cache --offline
```

## Policy format

`--policy` is required. The canonical minimal allowlist policy is:

```json
{
  "mode": "allowlist",
  "sourceRepository": "https://github.com/acme/widget",
  "workflow": ".github/workflows/release.yml",
  "allowlist": [
    { "name": "@acme/widget", "version": "1.2.3" }
  ]
}
```

There are two modes:

- `"mode": "all"` requires every selected registry package in the lockfile to carry provenance matching the expected source. Use it when the whole tree comes from one trusted upstream, or pair it with `exemptions` for the remainder.
- `"mode": "allowlist"` requires provenance only for the named packages. Packages outside the allowlist are not checked. Use per-package overrides when the allowlisted packages come from different repositories.

A fuller allowlist policy, including a per-package override and an explicit exemption:

```json
{
  "mode": "allowlist",
  "sourceRepository": "https://github.com/acme/widget",
  "workflow": ".github/workflows/release.yml",
  "registry": "https://registry.npmjs.org",
  "allowlist": [
    { "name": "@acme/widget", "version": "1.2.3" },
    {
      "name": "beta",
      "version": "0.9.0",
      "sourceRepository": "https://github.com/acme/beta",
      "workflow": ".github/workflows/build.yml"
    }
  ],
  "exemptions": [
    {
      "package": "internal-tool",
      "version": "4.2.0",
      "reason": "Vendored tarball; upstream publishes no provenance as of 2026-01-15"
    }
  ]
}
```

An exemption is the only way to make a required package pass without provenance, and it must give a reason. The reason is not just documentation: a policy that exempts a package without one is rejected.

### Policy fields

| Field | Required | Meaning |
| --- | --- | --- |
| `mode` | yes | `"all"` or `"allowlist"`. |
| `sourceRepository` | strongly recommended | Expected upstream repository. Accepts normalized forms such as `https://github.com/org/repo`, `git+https://github.com/org/repo.git`, and `git@github.com:org/repo.git`. If omitted, the gate checks the subject digest and signature but cannot bind the attestation to a repository you trust. |
| `workflow` | strongly recommended | Expected workflow path, for example `.github/workflows/release.yml`. Matched against both the SLSA statement and the signing certificate's identity. |
| `ref` | no | Expected git ref, for example `refs/heads/main`. When set, the attestation and certificate identity must agree. |
| `allowlist` | in allowlist mode | Array of package names or objects. An object may set `name` (or `package`), `version`, `integrity`, and per-package `sourceRepository`, `workflow`, and `ref` overrides. |
| `exemptions` | no | Array of `{ "package": "...", "version": "...", "reason": "..." }`. `package` and `reason` are required; `version` is optional. |
| `integrity` | no | In an allowlist entry, pins the exact SRI hash. A lockfile entry whose integrity differs fails with exit 1. |
| `trustRoot` | no | Path to a Sigstore `trusted_root.json`/PEM file, or an inline trust-root object. Relative paths resolve from the policy file. Defaults to the built-in public-good trust root. |
| `registry` | no | npm registry base URL. `--registry` overrides it. |
| `includeDev` | no | Include dev dependencies. Defaults to `true`. |
| `includeOptional` | no | Include optional dependencies. Defaults to `true`. |
| `includePeer` | no | Include peer dependencies. Defaults to `true`. |

The policy is validated strictly: a malformed URL, an empty allowlist, an unknown mode, or an exemption without a reason is an error rather than a silently weaker gate. Common alternate spellings are accepted for compatibility, but the canonical form above is what the examples and tests use.

## What a run verifies

For every selected lockfile entry, the tool:

1. Parses `package-lock.json` v1, v2, or v3 and skips links, workspaces, and git/file dependencies that cannot have npm registry provenance.
2. Resolves the package's npm attestation document, from `--cache` first and otherwise from the registry's attestations endpoint (falling back to a bundle advertised in the package metadata).
3. Requires a build-provenance predicate. A validly signed npm *publish* attestation is ignored for this policy.
4. Verifies the DSSE signature over the in-toto statement.
5. Builds an X.509 chain to a configured trust root and checks certificate validity at the transparency-log integration time.
6. Verifies the Rekor signed entry timestamp (SET) and, when present, its payload hash against the DSSE payload. It does not fetch or verify a full Merkle inclusion proof.
7. Matches the signed subject name, version, and digest against the lockfile entry and its integrity hash.
8. Matches the attestation source repository and workflow against the policy, and requires the signing certificate's URI identity to agree.

A mismatch in any of these steps is a policy failure (exit 1), while malformed input, an unreadable cache, an unreachable registry, or a signature/certificate verification failure is an error (exit 2). The distinction matters in CI: exit 1 means "this package does not meet the policy"; exit 2 means "the gate could not complete its work."

## Cache and offline verification

`--cache <dir>` is a hermetic store. An online run writes each fetched attestation document to the cache, plus the exact trust root used for the run as `trusted-root.json`. A later run with the same cache and `--offline` never contacts the network:

```sh
provenance-gate check package-lock.json --policy provenance.json --cache .provenance-cache --offline
```

If a required bundle is absent from the cache while offline, the result is `missing` (exit 1), not a network fetch. A cache entry that exists but is corrupt is an error (exit 2), never a pass. Cache filenames use the safe package id: `@scope/name@1.2.3` becomes `scope_name@1.2.3.json`.

A committed cache is reproducible only if you also commit the trust root it contains. If you supply your own `--trust-root`, you are trusting that material explicitly.

## JSON receipt

Add `--json` to get a machine-readable receipt on stdout:

```json
{
  "schemaVersion": 1,
  "tool": "lockfile-provenance-gate",
  "version": "0.1.0",
  "generatedAt": "2026-01-15T12:00:00.000Z",
  "ok": true,
  "exitCode": 0,
  "offline": true,
  "summary": {
    "required": 1,
    "verified": 1,
    "missing": 0,
    "mismatch": 0,
    "error": 0,
    "exempt": 0
  },
  "packages": [
    {
      "package": "@acme/widget",
      "version": "1.2.3",
      "integrity": "sha512-...",
      "commit": "1111111111111111111111111111111111111111",
      "sourceRepository": "github.com/acme/widget",
      "workflow": ".github/workflows/release.yml",
      "verified": true,
      "status": "verified",
      "reason": "provenance verified"
    }
  ]
}
```

The receipt also carries `lockfile`, `policy`, `registry`, and `lockfileVersion`; each package row includes `status` (`verified`, `mismatch`, `missing`, or `error`), `verified`, `reason`, and the cache provenance fields when applicable.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every required package verified against the policy, or was explicitly exempted. |
| `1` | Policy failure: missing attestation, digest mismatch, integrity-pin mismatch, or source repository/workflow mismatch. |
| `2` | The check could not complete: malformed input, corrupt cache, unreachable registry, or signature/certificate verification failure. |

## Security notes

- Provenance is only as strong as the trust root and policy you supply. Set `sourceRepository` and `workflow`; without them the gate still verifies that a valid attestation covers the lockfile digest, but it cannot tell you *who* built it.
- The bundle must chain to a configured Sigstore root. The package ships the public-good root; the test fixture trust root is test-only and must never be used in production.
- The tool does not install, execute, or unpack the audited tarballs. It does read registry attestation metadata for the exact lockfile version.
- npm provenance is not universal. Required packages without it fail; exempt them deliberately with a reason if that is the right risk decision for your project.

## Development

```sh
npm test
```

The suite uses Node's built-in test runner and generated fixtures, including a local HTTP server for cache tests. It does not require network access. It also runs the checked-in examples, so their documented exit codes are part of `npm test`. CI runs on Ubuntu, macOS, and Windows with Node 18, 20, and 22, then packs the tarball and installs it in a clean directory to run both binaries with `--version` and `--help`.

## Status

Early MVP. The features above are the scope; anything not listed is not built yet.

## License

Apache-2.0. See [LICENSE](LICENSE).
