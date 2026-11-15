// Command-line surface for lockfile-provenance-gate.  Kept separate from the
// checker so the core can be tested without spawning a process.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { formatTable, runCheck } from './check.js';
import { GateError } from './util.js';

const PACKAGE = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const VERSION = PACKAGE.version;

const USAGE = `lockfile-provenance-gate ${VERSION}
Gate npm lockfiles on provenance bound to the repo you actually trust.

Usage:
  provenance-gate check <package-lock.json> --policy <provenance.json> [options]
  provenance-gate --help
  provenance-gate --version

Options:
  -p, --policy <file>     Policy JSON (required): mode all|allowlist, expected
                          source repository/workflow, exemptions with reasons.
  -c, --cache <dir>       Directory of cached attestation bundles.  A package
                          without a cached bundle is reported as missing.
      --offline           Never touch the network.  This build only reads the
                          bundle cache, so verification is always hermetic.
      --trust-root <file> Sigstore trusted_root.json, PEM, or a cache
                          directory holding one.  Defaults to the policy
                          trustRoot or the built-in public-good root.
      --json              Emit a machine-readable receipt on stdout.
  -h, --help              Show this help.
  -v, --version           Show the version.

Exit codes:
  0  every required package is verified against the policy (or exempted)
  1  policy failure: missing attestation, digest mismatch, or source
     repository/workflow mismatch
  2  malformed input, unreadable cache/trust root, or a signature/certificate
     verification error
`;

function parseValue(argv, index, flag) {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('-')) {
    throw new GateError(`option ${flag} requires a value`);
  }
  return value;
}

export function parseCheckArgs(argv) {
  const options = {
    lockfile: undefined,
    policy: undefined,
    cache: undefined,
    trustRoot: undefined,
    offline: false,
    json: false,
  };
  const positional = [];

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const equals = arg.startsWith('--') ? arg.indexOf('=') : -1;
    const flag = equals > 0 ? arg.slice(0, equals) : arg;
    const inlineValue = equals > 0 ? arg.slice(equals + 1) : undefined;

    if (arg === '--') {
      positional.push(...argv.slice(index + 1));
      break;
    }
    if (flag === '--help' || flag === '-h') {
      options.help = true;
      continue;
    }
    if (flag === '--version' || flag === '-v') {
      options.version = true;
      continue;
    }
    if (flag === '--offline') {
      options.offline = true;
      continue;
    }
    if (flag === '--json') {
      options.json = true;
      continue;
    }
    if (flag === '--policy' || flag === '-p') {
      options.policy = inlineValue ?? parseValue(argv, index, flag);
      if (inlineValue === undefined) index += 1;
      continue;
    }
    if (flag === '--cache' || flag === '-c') {
      options.cache = inlineValue ?? parseValue(argv, index, flag);
      if (inlineValue === undefined) index += 1;
      continue;
    }
    if (flag === '--trust-root' || flag === '--trusted-root' || flag === '--root') {
      options.trustRoot = inlineValue ?? parseValue(argv, index, flag);
      if (inlineValue === undefined) index += 1;
      continue;
    }
    if (arg.startsWith('-')) throw new GateError(`unknown option ${arg}`);
    positional.push(arg);
  }

  if (positional.length > 1) throw new GateError(`unexpected argument "${positional[1]}"`);
  options.lockfile = positional[0];
  return options;
}

function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

function baseReceipt(result, { offline }) {
  return {
    schemaVersion: 1,
    tool: 'lockfile-provenance-gate',
    version: VERSION,
    generatedAt: new Date().toISOString(),
    ok: result.ok,
    exitCode: result.exitCode,
    offline: Boolean(offline),
    lockfile: result.lockfile,
    policy: result.policy,
    lockfileVersion: result.lockfileVersion,
    summary: result.summary,
    packages: result.packages,
  };
}

function errorReceipt(error, exitCode, { offline }) {
  return {
    schemaVersion: 1,
    tool: 'lockfile-provenance-gate',
    version: VERSION,
    generatedAt: new Date().toISOString(),
    ok: false,
    exitCode,
    offline: Boolean(offline),
    error: error instanceof Error ? error.message : String(error),
    summary: { required: 0, verified: 0, missing: 0, mismatch: 0, error: 1, exempt: 0 },
    packages: [],
  };
}

export function main(argv, { stdout = process.stdout, stderr = process.stderr, cwd = process.cwd() } = {}) {
  const args = argv.slice();
  if (args.length === 0) {
    stdout.write(USAGE);
    return 0;
  }
  if (args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    stdout.write(USAGE);
    return 0;
  }
  if (args.includes('--version') || args.includes('-v') || args[0] === 'version') {
    stdout.write(`${VERSION}\n`);
    return 0;
  }

  let command = args[0];
  let rest = args.slice(1);
  if (command !== 'check') {
    // Accept the common shorthand where the lockfile is the first argument.
    if (!command.startsWith('-') && /\.json$/iu.test(command)) {
      rest = args;
      command = 'check';
    } else {
      stderr.write(`provenance-gate: unknown command "${command}"\n\n${USAGE}`);
      return 2;
    }
  }

  let options;
  try {
    options = parseCheckArgs(rest);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`provenance-gate: ${message}\n`);
    return error.exitCode ?? 2;
  }
  if (options.help) {
    stdout.write(USAGE);
    return 0;
  }
  if (options.version) {
    stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (!options.lockfile) {
    stderr.write('provenance-gate: check requires a lockfile path\n');
    return 2;
  }
  if (!options.policy) {
    stderr.write('provenance-gate: check requires --policy <provenance.json>\n');
    return 2;
  }

  const lockfilePath = path.resolve(cwd, options.lockfile);
  const policyPath = path.resolve(cwd, options.policy);
  const cacheDir = options.cache ? path.resolve(cwd, options.cache) : undefined;
  const trustRootPath = options.trustRoot ? path.resolve(cwd, options.trustRoot) : undefined;

  try {
    const result = runCheck({
      lockfilePath,
      policyPath,
      cacheDir,
      trustRootPath,
      offline: options.offline,
    });
    const receipt = baseReceipt(result, options);
    if (options.json) writeJson(stdout, receipt);
    else stdout.write(formatTable(receipt));
    return result.exitCode;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const exitCode = error instanceof GateError ? error.exitCode : 2;
    if (options.json) writeJson(stdout, errorReceipt(error, exitCode, options));
    else stderr.write(`provenance-gate: ${message}\n`);
    return exitCode;
  }
}
