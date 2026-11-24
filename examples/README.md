# Runnable examples

Three self-contained, offline examples of the gate. They need no install and no
network access: clone the repository, use Node.js 18 or newer, and run them
from the repository root.

> **The bundles here are generated test data, not real registry attestations.**
> They are signed by a throwaway fixture PKI whose trust root lives in each
> `cache/` directory. Use them to learn the command and the verdict format;
> never use that trust root for a production policy.

## Run all, with assertions

```sh
npm run example
```

`examples/run-example.mjs` runs the CLI three times (`--offline`), prints each
verdict and summary, and fails unless the first two exit 0 and the third exits
1. The tail of its output is:

```console
1. verified example
   ...
   @acme/widget@1.2.3: verified - provenance verified
   summary: 1 required, 1 verified, 0 missing, 0 mismatch, 0 error
   exit: 0 (expected 0)
   PASS

2. npm alias example: the policy names the real package
   ...
   @acme/widget@1.2.3: verified - provenance verified
   summary: 1 required, 1 verified, 0 missing, 0 mismatch, 0 error
   exit: 0 (expected 0)
   PASS

3. expected failure: publish attestation is not build provenance
   ...
   publish-only@1.0.0: mismatch - no verifiable Sigstore provenance attestation found for publish-only@1.0.0
   summary: 1 required, 0 verified, 0 missing, 1 mismatch, 0 error
   exit: 1 (expected 1)
   PASS

All 3 examples behaved as documented.
```

## Example 1: a package that passes

`examples/offline-check` contains a lockfile entry for `@acme/widget@1.2.3`,
an allowlist policy naming `https://github.com/acme/widget` and
`.github/workflows/release.yml`, and a cache holding both the attestation
bundle and the trust root.

```sh
node bin/provenance-gate.js check examples/offline-check/package-lock.json \
  --policy examples/offline-check/provenance.json \
  --cache examples/offline-check/cache \
  --offline
```

```console
PACKAGE       VERSION  INTEGRITY                                                                                        STATUS    REASON
------------  -------  -----------------------------------------------------------------------------------------------  --------  -------------------
@acme/widget  1.2.3    sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==  verified  provenance verified

1 required, 1 verified, 0 missing, 0 mismatch, 0 error
```

The exit code is 0. The gate verified the DSSE signature over the in-toto
statement, chained the signing certificate to the fixture trust root, checked
the Rekor signed entry timestamp, matched the signed subject digest to the
lockfile integrity, and matched the source repository and workflow to the
policy. The policy names no `trustRoot`, so the offline run reads
`cache/trusted-root.json`.

`examples/offline-check/provenance.json`:

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

## Example 2: an npm alias that passes

`examples/alias-check` is the same package installed under a local alias. The
lockfile records `"widget": "npm:@acme/widget@1.2.3"` as the dependency and
installs it at `node_modules/widget`, but the entry's `name` is still
`@acme/widget`. The policy names the real package, so the gate resolves the
alias, queries the `@acme/widget` attestation, and reports the real name:

```sh
node bin/provenance-gate.js check examples/alias-check/package-lock.json \
  --policy examples/alias-check/provenance.json \
  --cache examples/alias-check/cache \
  --offline
```

```console
PACKAGE       VERSION  INTEGRITY                                                                                        STATUS    REASON
------------  -------  -----------------------------------------------------------------------------------------------  --------  -------------------
@acme/widget  1.2.3    sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==  verified  provenance verified

1 required, 1 verified, 0 missing, 0 mismatch, 0 error
```

The exit code is 0. Prefer the real package name in the policy; naming the
local alias (`widget`) also selects this entry, but the receipt and attestation
still use `@acme/widget`. The integrity hash binds the verdict to the exact
tarball installed under the alias.

## Example 3: a signed attestation that is the wrong kind

`examples/publish-only` is the same shape, but its bundle carries npm's
*publish* attestation predicate instead of build provenance. A valid signature
does not make it satisfy a build-provenance policy.

```sh
node bin/provenance-gate.js check examples/publish-only/package-lock.json \
  --policy examples/publish-only/provenance.json \
  --cache examples/publish-only/cache \
  --offline
```

```console
PACKAGE       VERSION  INTEGRITY                                                                                        STATUS    REASON
------------  -------  -----------------------------------------------------------------------------------------------  --------  --------------------------------------------------------------------------
publish-only  1.0.0    sha512-W3ZDqfRmYOYhjOasZ3pSvK6VJJL9dhNSPAmgtAF51MTLW88dnoGyNVrO6bsw8Ju46DepNLq2admJQKeVbDcNRw==  mismatch  no verifiable Sigstore provenance attestation found for publish-only@1.0.0

1 required, 0 verified, 0 missing, 1 mismatch, 0 error
```

The exit code is 1: a policy failure, not an execution error. Exit 2 is
reserved for a run that could not complete, such as malformed input or a
corrupt cache.

## Adapt this to your own lockfile

1. Copy the shape of `examples/offline-check/provenance.json`. Set
   `sourceRepository` and `workflow` to the upstream you trust, and list the
   packages you vendor in `allowlist` (or use `"mode": "all"`). Use the
   canonical field table in the [main README](../README.md#policy-fields).
2. Run once online so the gate writes each fetched bundle and the exact
   Sigstore trust root into your own cache directory:

   ```sh
   provenance-gate check package-lock.json \
     --policy provenance.json \
     --cache .provenance-cache
   ```

3. Re-run hermetically in CI with the same cache:

   ```sh
   provenance-gate check package-lock.json \
     --policy provenance.json \
     --cache .provenance-cache \
     --offline
   ```

Do not copy the fixture `cache/` from these examples into a real project. An
online run with your policy and no custom `--trust-root` uses the built-in
Sigstore public-good root; that is the material the cache will store for later
offline runs. See the main README for the policy format, exit codes, and the
JSON receipt.

## Files

```text
examples/
├── run-example.mjs                 # runs both cases and asserts exit 0 / 1
├── offline-check/
│   ├── package-lock.json
│   ├── provenance.json
│   └── cache/
│       ├── acme_widget@1.2.3.json  # generated build-provenance bundle
│       └── trusted-root.json       # test-only fixture root
├── alias-check/
│   ├── package-lock.json           # installs @acme/widget under node_modules/widget
│   ├── provenance.json             # names the real package, @acme/widget
│   └── cache/
│       ├── acme_widget@1.2.3.json  # generated build-provenance bundle
│       └── trusted-root.json       # test-only fixture root
└── publish-only/
    ├── package-lock.json
    ├── provenance.json
    └── cache/
        ├── publish-only@1.0.0.json # generated publish attestation
        └── trusted-root.json       # test-only fixture root
```
