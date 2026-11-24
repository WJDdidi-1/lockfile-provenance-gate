# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Fixed

- An npm alias is now checked as the package it actually names. Projects that
  install `"cv": "npm:cache-verdict@0.7.0"` get a `cache-verdict@0.7.0` entry
  verified against that package's provenance instead of a false `missing` for
  `cv` (or for `cache-verdict`, when the policy correctly named the real
  package). `package-lock.json` v1 aliases, where the real name lives in the
  `npm:` version spec, and v2/v3 aliases, where `packages[*].name` carries it,
  are both resolved. Naming the local alias in a policy also selects the entry,
  including when npm installed the same tarball directly as well, but the real
  published name is canonical: it is what the attestation, the registry lookup,
  and the receipt use. The integrity hash still binds the verdict to the aliased
  tarball.
- `npm test` now packs the tarball, installs it in a clean directory, and has
  the installed CLI verify an aliased project (exit 0) and an integrity
  mismatch (exit 1).

## 0.1.1 - 2026-11-16

### Fixed

- A required package that is present in `package-lock.json` but filtered out by
  a policy dependency-type option (`includeDev: false`, `includeOptional: false`,
  or `includePeer: false`) is now reported as excluded by that filter. It no
  longer says the package is "not present in the lockfile", which sent users
  looking for a missing dependency that was actually a configuration choice.
  The exit code remains `1`.
