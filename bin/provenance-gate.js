#!/usr/bin/env node
// Short alias matching the documented `provenance-gate` examples.
import { main } from '../lib/cli.js';

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`provenance-gate: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
