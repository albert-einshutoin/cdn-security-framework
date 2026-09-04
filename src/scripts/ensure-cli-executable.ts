#!/usr/bin/env node

import fs = require('node:fs');
import path = require('node:path');

const repoRoot = path.join(__dirname, '..');
const cliPath = path.join(repoRoot, 'bin', 'cli.js');
const policyTypesPath = path.join(repoRoot, 'types', 'policy.d.ts');

const currentMode = fs.statSync(cliPath).mode;
const executableMode = currentMode | 0o755;

// TypeScript emit does not preserve executable bits, but npm bin entries must
// remain executable for packed installs and `node_modules/.bin` shims.
if (currentMode !== executableMode) {
  fs.chmodSync(cliPath, executableMode);
}

// TypeScript does not emit authored .d.ts inputs, so copy the policy contract
// to the path referenced by the generated public declarations.
fs.mkdirSync(path.dirname(policyTypesPath), { recursive: true });
fs.copyFileSync(path.join(repoRoot, 'src', 'types', 'policy.d.ts'), policyTypesPath);
