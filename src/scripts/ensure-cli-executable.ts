#!/usr/bin/env node

import fs = require('node:fs');
import path = require('node:path');

const repoRoot = path.join(__dirname, '..');
const cliPath = path.join(repoRoot, 'bin', 'cli.js');

const currentMode = fs.statSync(cliPath).mode;
const executableMode = currentMode | 0o755;

// TypeScript emit does not preserve executable bits, but npm bin entries must
// remain executable for packed installs and `node_modules/.bin` shims.
if (currentMode !== executableMode) {
  fs.chmodSync(cliPath, executableMode);
}
