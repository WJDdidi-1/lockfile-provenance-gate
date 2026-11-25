# Measurement: git/file/link lockfile entries before and after the unverifiable verdict

Date: 2026-11-26
Change: report lockfile entries that cannot carry npm registry provenance instead of dropping them.
Baseline: `b402b20` (the source of the published `0.2.0`). After: this working tree.

The gate is run with `--json` where the receipt matters and without it to show the
human table. The three reproductions below use lockfiles produced by npm from real
dependencies. The mixed case uses the real registry attestation for
`cache-verdict@0.7.0`; the git and file/link cases need no registry access.

## 1. A lockfile whose only dependency is a git checkout

`npm install github:WJDdidi-1/loud-cron --package-lock-only` produced:

```json
"node_modules/loud-cron": {
  "version": "0.1.0",
  "resolved": "git+ssh://git@github.com/WJDdidi-1/loud-cron.git#f8c54287bfb916d083f8e814a086f1a83aee26c3",
  "license": "Apache-2.0"
}
```

Policy: `{"mode": "all"}`.

Before, the git entry was filtered out before selection:

```text
PACKAGE  VERSION  INTEGRITY  STATUS  REASON
-------  -------  ---------  ------  ------

0 required, 0 verified, 0 missing, 0 mismatch, 0 error
exit 0
```

After:

```text
PACKAGE    VERSION  INTEGRITY  STATUS        REASON
---------  -------  ---------  ------------  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
loud-cron  0.1.0    -          unverifiable  lockfile entry loud-cron@0.1.0 cannot be verified: it is a git dependency resolved from git+ssh://git@github.com/WJDdidi-1/loud-cron.git#f8c54287bfb916d083f8e814a086f1a83aee26c3 and has no registry integrity hash or provenance

1 required, 0 verified, 0 missing, 0 mismatch, 0 error, 1 unverifiable
exit 1
```

The receipt now carries the row and the count:

```json
{
  "ok": false,
  "exitCode": 1,
  "summary": {
    "required": 1,
    "verified": 0,
    "missing": 0,
    "mismatch": 0,
    "unverifiable": 1,
    "error": 0,
    "exempt": 0
  },
  "packages": [
    {
      "package": "loud-cron",
      "version": "0.1.0",
      "integrity": null,
      "status": "unverifiable",
      "verified": false,
      "resolved": "git+ssh://git@github.com/WJDdidi-1/loud-cron.git#f8c54287bfb916d083f8e814a086f1a83aee26c3",
      "sourceType": "git",
      "reason": "lockfile entry loud-cron@0.1.0 cannot be verified: it is a git dependency resolved from git+ssh://git@github.com/WJDdidi-1/loud-cron.git#f8c54287bfb916d083f8e814a086f1a83aee26c3 and has no registry integrity hash or provenance"
    }
  ]
}
```

## 2. A git checkout of a package that is also installed from the registry

`npm install` on this dependency set:

```json
{
  "cv-exact": "npm:cache-verdict@0.7.0",
  "cv-range": "npm:cache-verdict@^0.7.0",
  "gitdep": "github:WJDdidi-1/cache-verdict"
}
```

produced a registry entry under `node_modules/cv-exact`, another under
`node_modules/cv-range`, and a git checkout under `node_modules/gitdep` with the
same real name and version:

```json
"node_modules/gitdep": {
  "name": "cache-verdict",
  "version": "0.7.0",
  "resolved": "git+ssh://git@github.com/WJDdidi-1/cache-verdict.git#869ba478b697c30feeda0d8d26eb11cce51077bc",
  "license": "Apache-2.0"
}
```

Policy: `mode: all`, repository `https://github.com/WJDdidi-1/cache-verdict`,
workflow `.github/workflows/publish.yml`, with the real attestation cached.

Before, the receipt covered only the registry copy and reported a clean tree:

```json
{
  "ok": true,
  "exitCode": 0,
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
      "package": "cache-verdict",
      "version": "0.7.0",
      "status": "verified",
      "reason": "provenance verified"
    }
  ]
}
```

After, the same lockfile has two required entries; the verified registry row no
longer hides the git checkout:

```json
{
  "ok": false,
  "exitCode": 1,
  "summary": {
    "required": 2,
    "verified": 1,
    "missing": 0,
    "mismatch": 0,
    "unverifiable": 1,
    "error": 0,
    "exempt": 0
  },
  "packages": [
    {
      "package": "cache-verdict",
      "version": "0.7.0",
      "status": "unverifiable",
      "verified": false,
      "resolved": "git+ssh://git@github.com/WJDdidi-1/cache-verdict.git#869ba478b697c30feeda0d8d26eb11cce51077bc",
      "sourceType": "git",
      "reason": "lockfile entry cache-verdict@0.7.0 cannot be verified: it is a git dependency resolved from git+ssh://git@github.com/WJDdidi-1/cache-verdict.git#869ba478b697c30feeda0d8d26eb11cce51077bc and has no registry integrity hash or provenance"
    },
    {
      "package": "cache-verdict",
      "version": "0.7.0",
      "integrity": "sha512-dvziszaWS1gFLFaSdksrOp6kcsgZPJUGMIkmKWbt3bM9zLkJXuF2jGmOnNcPvP97rwvxt/TXmmFjoC3ae21VJg==",
      "status": "verified",
      "verified": true,
      "reason": "provenance verified"
    }
  ]
}
```

## 3. A `file:` dependency

`npm install` on `{"localpkg": "file:../localpkg"}` produced a link entry. The
target package entry carries the version npm actually links:

```json
"../localpkg": { "version": "1.2.3", "license": "MIT" },
"node_modules/localpkg": { "resolved": "../localpkg", "link": true }
```

Policy: `{"mode": "all"}`.

Before:

```text
PACKAGE  VERSION  INTEGRITY  STATUS  REASON
-------  -------  ---------  ------  ------

0 required, 0 verified, 0 missing, 0 mismatch, 0 error
exit 0
```

After:

```text
PACKAGE   VERSION  INTEGRITY  STATUS        REASON
--------  -------  ---------  ------------  ----------------------------------------------------------------------------------------------------------------------------------------------------
localpkg  1.2.3    -          unverifiable  lockfile entry localpkg@1.2.3 cannot be verified: it is a link dependency resolved from ../localpkg and has no registry integrity hash or provenance

1 required, 0 verified, 0 missing, 0 mismatch, 0 error, 1 unverifiable
exit 1
```

## Allowlist mode and exemptions

An allowlist entry whose name is present only as an unverifiable lockfile entry
now reports that fact instead of claiming the package is absent:

```json
{
  "mode": "allowlist",
  "allowlist": [{ "name": "loud-cron", "version": "0.1.0" }]
}
```

```text
loud-cron  ...  unverifiable  policy requires loud-cron@0.1.0, which is present in the lockfile but cannot be verified: ...
exit 1
```

Adding an exemption with a non-empty reason is still the explicit escape hatch:

```json
{
  "mode": "allowlist",
  "allowlist": [{ "name": "loud-cron" }],
  "exemptions": [{ "package": "loud-cron", "reason": "hand-reviewed git checkout" }]
}
```

This exits 0 with `summary.exempt: 1` and no verdict row, for the same reason a
registry package exemption does.

## Registry-only regression

Existing registry fixtures and examples keep their verdict rows and exit 0. Their
human summary line is unchanged because a zero unverifiable count is not printed.
Their JSON `summary` gains `"unverifiable": 0` so machine consumers can read the
new count without special-casing old receipts.

## Test coverage

`npm test` covers the three reproductions (`unverifiable-git`,
`unverifiable-mixed`, `unverifiable-link`), the allowlist "present but cannot be
verified" wording, the exemption path, v1 git/file specs, v3 link target
versions, and a v3 file tarball entry. The existing registry, alias, missing,
mismatch, error, cache, packed-tarball, and example tests still pass.
