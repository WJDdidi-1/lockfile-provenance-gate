#!/usr/bin/env node
// Long package name; kept for the existing npm bin entry and shell history.
import { main } from '../lib/cli.js';

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(
    `lockfile-provenance-gate: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 2;
}
