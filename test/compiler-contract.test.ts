import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

const requireFromRepo = createRequire(path.join(process.cwd(), 'package.json'));

describe('compiler public contracts', () => {
  test('phase modules expose callable contracts', () => {
    const parser = requireFromRepo('./parser');
    const validator = requireFromRepo('./validator');
    const emitter = requireFromRepo('./emitter');

    expect(parser.parsePolicyFile).toEqual(expect.any(Function));
    expect(validator.validatePolicy).toEqual(expect.any(Function));
    expect(emitter.compileArtifacts).toEqual(expect.any(Function));
  });

  test('validator accepts schema-derived policy shape without emitting artifacts', () => {
    const { validatePolicy } = requireFromRepo('./validator');
    const result = validatePolicy({
      pkgRoot: process.cwd(),
      policy: {
        version: 1,
        request: { allow_methods: ['GET'] },
        response_headers: {},
      },
    });

    expect(result).toMatchObject({
      ok: true,
      errors: [],
    });
    expect(result.warnings).toEqual(expect.any(Array));
  });

  test('template injection rejects duplicate top-level config declarations', () => {
    const { assertInjectedConstDeclarations } = requireFromRepo('./scripts/lib/template-inject');

    expect(() => {
      assertInjectedConstDeclarations('const CFG = {};\nconst CFG = {};', ['CFG']);
    }).toThrow();
  });
});
