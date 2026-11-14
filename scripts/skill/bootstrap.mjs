#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { realpath } from 'node:fs/promises';
import {
  BootstrapError,
  doctorBootstrap,
  loadPreparedBootstrap,
  parseBootstrapArguments,
  prepareBootstrap,
  runPrepared,
  validateRunArguments,
} from './bootstrap-core.mjs';

export async function main(argv = process.argv.slice(2)) {
  try {
    const options = parseBootstrapArguments(argv);
    if (options.help) {
      process.stdout.write('Usage: node scripts/skill/bootstrap.mjs doctor|prepare|run --revision FULL40 --cache-dir DIR [--allow-dirty] [--offline] [--capability core|scan] [--profile dev|release] [-- CLI arguments]\nScan preparation: prepare --capability scan --engine ID[,ID] --data-dir DIR [--managed-runtime-bundle DIR] [--release-approved-local-image-directory DIR]\n');
      return 0;
    }
    if (options.command === 'doctor') {
      const result = await doctorBootstrap(options);
      process.stdout.write(`${JSON.stringify(result)}\n`);
      return result.ready ? 0 : 4;
    }
    if (options.command === 'run') validateRunArguments(options.cliArguments);
    const result = options.command === 'run' ? await loadPreparedBootstrap(options) : await prepareBootstrap(options);
    if (options.command === 'prepare') {
      process.stdout.write(`${JSON.stringify(result)}\n`);
      return 0;
    }
    process.stderr.write(`Scanner core ${result.cache_hit ? 'reused' : 'prepared'}: ${result.cache_key}\n`);
    return await runPrepared(result, options.cliArguments);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      schema_version: 'ai-security-scanner.bootstrap-error/v1',
      error: error instanceof BootstrapError ? error.code : 'bootstrap_failed',
      message: error.message,
      ...(error instanceof BootstrapError && error.details !== undefined ? { detail: error.details } : {}),
    })}\n`);
    return error instanceof BootstrapError ? error.exitCode : 4;
  }
}

if (process.argv[1] && await realpath(resolve(process.argv[1])).catch(() => undefined) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
