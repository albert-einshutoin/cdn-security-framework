#!/usr/bin/env node
import { assertSupportedNode } from '../lib/node-engine';
assertSupportedNode(require.main === module);

/**
 * Thin wrapper around `tsc` so CI can skip redundant rebuilds when
 * CDN_SECURITY_TS_READY=1 is set after an initial successful compile.
 */
const { execSync } = require('node:child_process');
const path = require('node:path');

if (process.env.CDN_SECURITY_TS_READY === '1') {
  process.exit(0);
}

const root = path.join(__dirname, '..');
execSync('npx tsc -p tsconfig.json --incremental false', { cwd: root, stdio: 'inherit' });
execSync('node scripts/ensure-cli-executable.js', { cwd: root, stdio: 'inherit' });
