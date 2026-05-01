import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

const requireFromRepo = createRequire(path.join(process.cwd(), 'package.json'));

describe('bundler emitter prototype', () => {
  test('bundles a virtual config module into parseable output', async () => {
    const {
      assertBundledConfigBindings,
      buildBundlerEmitterPrototype,
    } = requireFromRepo('./scripts/lib/bundler-emitter-prototype');

    const result = await buildBundlerEmitterPrototype({
      source: [
        'import { CFG } from "cdn-security:config";',
        'function handler() { return CFG.mode; }',
        'export { handler };',
      ].join('\n'),
      configExports: {
        CFG: { mode: 'enforce', allowedMethods: ['GET'] },
      },
    });

    expect(result.code).toContain('"mode": "enforce"');
    expect(result.code).toContain('function handler');
    expect(() => assertBundledConfigBindings(result.code, ['CFG'])).not.toThrow();
  });

  test('rejects source that shadows the generated config binding', async () => {
    const { buildBundlerEmitterPrototype } = requireFromRepo('./scripts/lib/bundler-emitter-prototype');

    await expect(buildBundlerEmitterPrototype({
      source: [
        'import { CFG } from "cdn-security:config";',
        'function handler(CFG) { return CFG.mode; }',
        'export { handler };',
      ].join('\n'),
      configExports: {
        CFG: { mode: 'enforce' },
      },
    })).rejects.toThrow(/shadows config binding/);
  });

  test('rejects output with duplicated generated config bindings', () => {
    const { assertBundledConfigBindings } = requireFromRepo('./scripts/lib/bundler-emitter-prototype');

    expect(() => {
      assertBundledConfigBindings('var CFG = {};\nvar CFG = {};', ['CFG']);
    }).toThrow(/must appear exactly once/);
  });
});
