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
  -c, --cache <dir>       Read/write cache.  Without --offline, fetched
                          attestation bundles and the Sigstore trust root are
                          stored here for later hermetic runs.
      --offline           Never touch the network.  Every bundle must already
                          be in --cache; the trust root comes from --trust-root,
                          the policy, the cache, or the built-in root.
      --registry <url>    npm registry base URL (default https://registry.npmjs.org).
      --trust-root <file> Sigstore trusted_root.json, PEM, or a cache
                          directory holding one.  Defaults to the policy
                          trustRoot or the built-in public-good root.
      --json              Emit a machine-readable receipt on stdout.
  -h, --help              Show this help.
  -v, --version           Show the version.

Exit codes:
  0  every required package is verified against the policy (or exempted)
  1  policy failure: missing attestation, an unverifiable git/file/link
     entry, digest mismatch, or source repository/workflow mismatch
  2  malformed input, unreadable/corrupt cache, unreachable registry, or a
     signature/certificate verification error
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
    registry: undefined,
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
    if (flag === '--registry') {
      options.registry = inlineValue ?? parseValue(argv, index, flag);
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
    registry: result.registry ?? null,
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
    summary: { required: 0, verified: 0, missing: 0, mismatch: 0, unverifiable: 0, error: 1, exempt: 0 },
    packages: [],
  };
}

function streamsFor(io) {
  return {
    stdout: io.stdout ?? process.stdout,
    stderr: io.stderr ?? process.stderr,
    cwd: io.cwd ?? process.cwd(),
  };
}

// Synchronous argument handling.  Returning a numeric exitCode means the
// invocation is already finished (help, version, or a usage error); otherwise
// the caller has a fully resolved check to execute.
function resolveInvocation(argv, { stdout, stderr, cwd }) {
  const args = argv.slice();
  if (args.length === 0) {
    stdout.write(USAGE);
    return { exitCode: 0 };
  }
  if (args.includes('--help') || args.includes('-h') || args[0] === 'help') {
    stdout.write(USAGE);
    return { exitCode: 0 };
  }
  if (args.includes('--version') || args.includes('-v') || args[0] === 'version') {
    stdout.write(`${VERSION}\n`);
    return { exitCode: 0 };
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
      return { exitCode: 2 };
    }
  }

  let options;
  try {
    options = parseCheckArgs(rest);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`provenance-gate: ${message}\n`);
    return { exitCode: error.exitCode ?? 2 };
  }
  if (options.help) {
    stdout.write(USAGE);
    return { exitCode: 0 };
  }
  if (options.version) {
    stdout.write(`${VERSION}\n`);
    return { exitCode: 0 };
  }
  if (!options.lockfile) {
    stderr.write('provenance-gate: check requires a lockfile path\n');
    return { exitCode: 2 };
  }
  if (!options.policy) {
    stderr.write('provenance-gate: check requires --policy <provenance.json>\n');
    return { exitCode: 2 };
  }

  return {
    options,
    lockfilePath: path.resolve(cwd, options.lockfile),
    policyPath: path.resolve(cwd, options.policy),
    cacheDir: options.cache ? path.resolve(cwd, options.cache) : undefined,
    trustRootPath: options.trustRoot ? path.resolve(cwd, options.trustRoot) : undefined,
  };
}

async function executeCheck(invocation, { stdout, stderr }) {
  const { options, lockfilePath, policyPath, cacheDir, trustRootPath } = invocation;
  try {
    const result = await runCheck({
      lockfilePath,
      policyPath,
      cacheDir,
      trustRootPath,
      registry: options.registry,
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

// Async implementation, exported for programmatic callers and tests that need
// to await the registry fetch.  `main` below is the synchronous bin contract.
export async function runMain(argv, io = {}) {
  const streams = streamsFor(io);
  const invocation = resolveInvocation(argv, streams);
  if (invocation.exitCode !== undefined) return invocation.exitCode;
  return executeCheck(invocation, streams);
}

// The bin entry points are synchronous (`process.exitCode = main(...)`), while
// registry access is asynchronous.  Help, version and usage errors still return
// synchronously; an actual check starts in a microtask so the bin's assignment
// happens first, and the final code then wins when the run finishes.  Anything
// that needs the exit code directly should await runMain.
export function main(argv, io = {}) {
  const streams = streamsFor(io);
  const invocation = resolveInvocation(argv, streams);
  if (invocation.exitCode !== undefined) return invocation.exitCode;
  queueMicrotask(() => {
    executeCheck(invocation, streams).then(
      (exitCode) => {
        process.exitCode = exitCode;
      },
      (error) => {
        const message = error instanceof Error ? error.message : String(error);
        streams.stderr.write(`provenance-gate: ${message}\n`);
        process.exitCode = 2;
      },
    );
  });
  return 0;
}
