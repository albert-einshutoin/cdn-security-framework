#!/usr/bin/env node

import assert from 'node:assert/strict';
import path from 'node:path';
import { isRepositoryPath } from './check-docs-sync';

assert.equal(isRepositoryPath('/workspace/repository', '/workspace/repository/docs/ROADMAP.md', path.posix), true);
assert.equal(isRepositoryPath('/workspace/repository', '/workspace/outside.md', path.posix), false);
assert.equal(isRepositoryPath('/workspace/repository', '/workspace/repository-old/ROADMAP.md', path.posix), false);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'C:\\workspace\\repository\\docs\\ROADMAP.md', path.win32), true);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'C:\\workspace\\outside.md', path.win32), false);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'C:\\workspace\\repository-old\\ROADMAP.md', path.win32), false);
assert.equal(isRepositoryPath('C:\\workspace\\repository', 'D:\\outside.md', path.win32), false);

console.log('[docs-sync-unit] OK: repository-relative link boundary');
