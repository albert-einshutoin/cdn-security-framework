import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { transformSync } from 'esbuild';
import { vi } from 'vitest';

export function generatedWorker(policy: Record<string, unknown>, origin: typeof fetch, webCrypto = globalThis.crypto) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-generated-worker-'));
  try {
    const input = path.join(dir, 'policy.json');
    fs.writeFileSync(input, JSON.stringify({ version: 2, request: { allow_methods: ['GET', 'POST'] }, ...policy }));
    execFileSync(process.execPath, ['scripts/compile-cloudflare.js', '--policy', input, '--out-dir', dir],
      { cwd: process.cwd(), stdio: 'pipe', timeout: 10000 });
    const code = transformSync(fs.readFileSync(path.join(dir, 'edge/cloudflare/index.ts'), 'utf8'),
      { loader: 'ts', format: 'cjs', target: 'es2022' }).code;
    const module = { exports: {} as { default?: { fetch(request: Request, env: object): Promise<Response> } } };
    const logger = { log: vi.fn(), error: vi.fn() };
    Function('module', 'exports', 'fetch', 'console', 'crypto', code)(module, module.exports, origin, logger, webCrypto);
    return { handler: module.exports.default!, logger, code };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
