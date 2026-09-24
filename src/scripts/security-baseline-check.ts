#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');

function read(file: string) {
  return fs.readFileSync(path.join(repoRoot, file), 'utf8');
}

function fail(msg: string) {
  console.error('Baseline check failed:', msg);
  process.exit(1);
}

function ensureIncludes(file: string, pattern: string, desc: string) {
  const content = read(file);
  if (!content.includes(pattern)) {
    fail(`${file} is missing ${desc} (${pattern})`);
  }
}

function readJson(file: string) {
  return JSON.parse(read(file));
}

function main() {
  // OWASP references should be documented.
  ensureIncludes('docs/threat-model.md', 'OWASP Top 10:2025', 'OWASP Top 10:2025 mapping');
  ensureIncludes('docs/threat-model.md', 'OWASP API Security Top 10 (2023)', 'OWASP API Top 10 mapping');
  ensureIncludes('docs/threat-model.ja.md', 'OWASP Top 10:2025', 'OWASP Top 10:2025 mapping');
  ensureIncludes('docs/threat-model.ja.md', 'OWASP API Security Top 10 (2023)', 'OWASP API Top 10 mapping');

  // CI quality gate should delegate to the single source.
  const workflow = read('.github/workflows/policy-lint.yml');
  if (!workflow.includes('npm run test:ci')) {
    fail('.github/workflows/policy-lint.yml must run npm run test:ci');
  }
  const releaseSteps = yaml.load(read('.github/workflows/release-npm.yml'))?.jobs?.publish?.steps;
  if (!Array.isArray(releaseSteps)) fail('release workflow publish steps are missing');
  if (releaseSteps.some((step: { run?: string }) => step.run?.includes('${{ inputs.tag }}'))) {
    fail('release tag input must not be interpolated into shell source');
  }
  const validateTagAt = releaseSteps.findIndex((step: { name?: string }) => step.name === 'Validate release tag');
  const checkoutTagAt = releaseSteps.findIndex((step: { name?: string }) => step.name === 'Checkout release tag for manual dispatch');
  if (validateTagAt < 0 || checkoutTagAt <= validateTagAt) {
    fail('release tag must be validated before manual checkout');
  }
  const validateTagStep = releaseSteps[validateTagAt];
  const checkoutTagStep = releaseSteps[checkoutTagAt];
  const versionTagStep = releaseSteps.find((step: { name?: string }) => step.name === 'Ensure tag matches package version');
  const validatedTagRef = '${{ steps.release_tag.outputs.tag }}';
  if (validateTagStep.id !== 'release_tag'
    || checkoutTagStep.env?.RELEASE_TAG !== validatedTagRef
    || versionTagStep?.env?.RELEASE_TAG !== validatedTagRef) {
    fail('release checkout and version gate must use the validated tag');
  }
  const tagTestDir = fs.mkdtempSync(path.join(os.tmpdir(), 'csf-release-tag-'));
  try {
    const outputPath = path.join(tagTestDir, 'tag-output');
    const checkTag = (event: string, ref: string, input: string) => {
      fs.rmSync(outputPath, { force: true });
      const result = spawnSync('bash', ['-e', '-c', validateTagStep.run], {
        env: { ...process.env, GITHUB_EVENT_NAME: event, GITHUB_REF_NAME: ref, DISPATCH_TAG: input, GITHUB_OUTPUT: outputPath },
        encoding: 'utf8',
      });
      return { status: result.status, output: fs.existsSync(outputPath) ? fs.readFileSync(outputPath, 'utf8') : '' };
    };
    const manual = checkTag('workflow_dispatch', 'main', 'v2.0.0-rc.1');
    const pushed = checkTag('push', 'v2.0.0', 'v9.9.9');
    const hostile = checkTag('workflow_dispatch', 'main', 'v2.0.0$(printf injected)');
    if (manual.status !== 0 || manual.output !== 'tag=v2.0.0-rc.1\n'
      || pushed.status !== 0 || pushed.output !== 'tag=v2.0.0\n'
      || hostile.status === 0 || hostile.output !== '') {
      fail('release tag validation must accept version tags and reject shell syntax');
    }
  } finally {
    fs.rmSync(tagTestDir, { recursive: true, force: true });
  }
  const scriptsJson = readJson('package.json');
  const packageScripts = scriptsJson.scripts || {};
  const ciScript = String(packageScripts['test:ci'] || '');
  if (!ciScript.includes('npm run test:drift')) {
    fail('package.json test:ci must run npm run test:drift');
  }
  if (!ciScript.includes('npm run test:security-baseline')) {
    fail('package.json test:ci must run npm run test:security-baseline');
  }
  if (!ciScript.includes('npm run test:coverage')) {
    fail('package.json test:ci must run npm run test:coverage');
  }

  // Schema should include fingerprint controls.
  const schema = read('policy/schema.json');
  if (!schema.includes('ja3_fingerprints') || !schema.includes('ja4_fingerprints')) {
    fail('policy/schema.json must include ja3_fingerprints and ja4_fingerprints');
  }

  // Keep the TypeScript quality gate single-sourced. The scoped strict
  // typecheck scripts duplicated tsconfig.json and made test:all run the same
  // project-wide check repeatedly.
  const packageJson = readJson('package.json');
  const scripts = packageJson.scripts || {};
  const redundantTypecheckScripts = [
    'typecheck:lib-strict',
    'typecheck:scripts-lib-strict',
    'typecheck:unit-tests-strict',
    'typecheck:cli-strict',
    'typecheck:compiler-strict',
  ];
  for (const scriptName of redundantTypecheckScripts) {
    if (Object.prototype.hasOwnProperty.call(scripts, scriptName)) {
      fail(`package.json must not define redundant ${scriptName}; use npm run typecheck`);
    }
    if (String(scripts['test:all'] || '').includes(scriptName)) {
      fail(`package.json test:all must not invoke redundant ${scriptName}`);
    }
  }
  if (!String(scripts['test:all'] || '').includes('npm run typecheck')) {
    fail('package.json test:all must invoke npm run typecheck as the single project-wide type gate');
  }

  const tsconfig = readJson('tsconfig.json');
  if (tsconfig.compilerOptions?.incremental !== true) {
    fail('tsconfig.json must enable compilerOptions.incremental for repeated build:ts prefixes');
  }
  if (tsconfig.compilerOptions?.tsBuildInfoFile !== './.tsbuildinfo') {
    fail('tsconfig.json must write incremental state to ./.tsbuildinfo');
  }
  ensureIncludes('.gitignore', '.tsbuildinfo', 'TypeScript incremental cache ignore');

  // Cloudflare WAF parity docs must exist and reference the fail flag, so the
  // dual-target transparency promise is not silently deleted. The drift test
  // (scripts/check-drift.js) separately enforces that the body matches the
  // generator output.
  const parityFiles = [
    { file: 'docs/cloudflare-waf-parity.md', heading: '# Cloudflare WAF parity' },
    { file: 'docs/cloudflare-waf-parity.ja.md', heading: '# Cloudflare WAF パリティ' },
  ];
  for (const p of parityFiles) {
    if (!fs.existsSync(path.join(repoRoot, p.file))) {
      fail(`${p.file} is missing — parity transparency (issue #68) requires this file to exist`);
    }
    ensureIncludes(p.file, p.heading, 'parity doc heading');
    ensureIncludes(p.file, '--fail-on-waf-approximation', 'reference to the CI gate flag');
  }

  // Copyable deployment recipes are a documented adoption surface. Keep both
  // language variants present and ensure the core recipe set does not regress.
  const recipeFiles = [
    { file: 'docs/recipes.md', heading: '# Policy Recipes' },
    { file: 'docs/recipes.ja.md', heading: '# ポリシーレシピ' },
  ];
  const recipeHeadings = [
    '## Cognito JWT API',
    '## Next.js or SPA Static Site',
    '## Internal Admin Panel',
    '## Signed Download URLs',
    '## Cloudflare GraphQL API',
  ];
  for (const p of recipeFiles) {
    if (!fs.existsSync(path.join(repoRoot, p.file))) {
      fail(`${p.file} is missing — policy recipes (issue #132) require EN + JA docs`);
    }
    ensureIncludes(p.file, p.heading, 'recipe doc heading');
    for (const heading of recipeHeadings) {
      ensureIncludes(p.file, heading, 'core policy recipe heading');
    }
  }

  console.log('Security baseline check passed.');
}

main();
