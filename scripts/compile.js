#!/usr/bin/env node
/**
 * Compile: security.yml (Source of Truth) を読み、テンプレートに注入して dist/edge/*.js に出力する。
 * Usage: node scripts/compile.js [path/to/security.yml] [--policy path] [--out-dir dir]
 * Default: policy/security.yml or policy/base.yml
 * Requires: npm install js-yaml
 */

const { main } = require('./lib/compile-core');

main(process.argv.slice(2));
