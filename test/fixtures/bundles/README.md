# Offline verification fixtures

These bundles are generated test data, not real Sigstore material.  They exist
so `npm test` can verify the whole offline path without touching the network:

- `trust-root.json` is a test-only Fulcio/Rekor trust root.  Its leaf
  certificates were issued by a throwaway CA and carry the source repository
  and workflow identities used by the fixtures.
- `<package>@<version>.json` is a cached npm-style attestation bundle.  The
  DSSE signature, certificate chain, and Rekor signed entry timestamp all
  verify against the test trust root.
- `broken@0.1.0.json` has a corrupted DSSE signature.
- `tlog-broken@0.1.0.json` has a corrupted transparency-log promise.
- `publish-only@1.0.0.json` is validly signed but carries npm's publish
  attestation predicate instead of build provenance, so it must not satisfy the
  policy.

The bundle filenames use the same safe package id as `--cache`
(`@scope/name` becomes `scope_name`).  The private keys used to create these
fixtures are deliberately not committed; use a fresh throwaway PKI if the
fixtures ever need to be regenerated.
