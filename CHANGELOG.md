# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Fixed

- A required package that is present in `package-lock.json` but filtered out by
  a policy dependency-type option (`includeDev: false`, `includeOptional: false`,
  or `includePeer: false`) is now reported as excluded by that filter. It no
  longer says the package is "not present in the lockfile", which sent users
  looking for a missing dependency that was actually a configuration choice.
  The exit code remains `1`.
