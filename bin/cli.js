#!/usr/bin/env node
/**
 * cdn-security-framework CLI
 * Commands: init (scaffold policy YAML), build (compile policy → dist)
 */

const path = require('path');
const fs = require('fs');
const { Command } = require('commander');
const inquirer = require('inquirer');

const pkgRoot = path.resolve(__dirname, '..');

const program = new Command();

program
  .name('cdn-security')
  .description('CDN edge security: init policy YAML and build runtime code from policy')
  .version(require(path.join(pkgRoot, 'package.json')).version);

program
  .command('init')
  .description('Scaffold policy/base.yml and a profile (interactive or --platform/--profile)')
  .option('-f, --force', 'Overwrite existing policy files')
  .option('-p, --platform <name>', 'Platform: aws | cloudflare (skip interactive)')
  .option('--profile <name>', 'Profile: strict | balanced | permissive (skip interactive)')
  .option('--archetype <name>', 'Archetype: spa-static-site | rest-api | admin-panel | microservice-origin (mutually exclusive with --profile)')
  .action(async (opts) => {
    const cwd = process.cwd();
    const policyDir = path.join(cwd, 'policy');
    const profilesDir = path.join(cwd, 'policy', 'profiles');

    let platform = opts.platform;
    let profile = opts.profile;
    let archetype = opts.archetype;
    const archetypeNames = ['spa-static-site', 'rest-api', 'admin-panel', 'microservice-origin'];
    if (profile && !['strict', 'balanced', 'permissive'].includes(profile)) {
      console.error('[ERROR] Invalid --profile. Use strict, balanced, or permissive.');
      process.exit(1);
    }
    if (archetype && !archetypeNames.includes(archetype)) {
      console.error('[ERROR] Invalid --archetype. Use one of:', archetypeNames.join(', '));
      process.exit(1);
    }
    if (archetype && profile) {
      console.error('[ERROR] Specify --profile or --archetype, not both. Archetypes extend a profile.');
      process.exit(1);
    }
    if (!platform || (!profile && !archetype)) {
      const questions = [];
      if (!platform) {
        questions.push({
          type: 'list',
          name: 'platform',
          message: 'Which platform are you using?',
          choices: [
            { name: 'AWS CloudFront', value: 'aws' },
            { name: 'Cloudflare Workers', value: 'cloudflare' },
          ],
        });
      }
      if (!profile && !archetype) {
        questions.push({
          type: 'list',
          name: 'starterKind',
          message: 'Start from a profile or an archetype?',
          choices: [
            { name: 'Profile — strict / balanced / permissive', value: 'profile' },
            { name: 'Archetype — app-shaped preset (SPA, REST API, admin, microservice)', value: 'archetype' },
          ],
        });
        questions.push({
          type: 'list',
          name: 'profile',
          message: 'Choose a security profile:',
          when: (a) => a.starterKind === 'profile',
          choices: [
            { name: 'Strict (High security, risk of breaking legacy clients)', value: 'strict' },
            { name: 'Balanced (Recommended for most sites)', value: 'balanced' },
            { name: 'Permissive (API / Legacy compatibility)', value: 'permissive' },
          ],
        });
        questions.push({
          type: 'list',
          name: 'archetype',
          message: 'Choose an archetype:',
          when: (a) => a.starterKind === 'archetype',
          choices: [
            { name: 'SPA / static site (immutable cache, CSP nonce)', value: 'spa-static-site' },
            { name: 'REST API (JWT-gated /api/*, CORS allowlist)', value: 'rest-api' },
            { name: 'Admin panel (static_token, no-store, strict CSP)', value: 'admin-panel' },
            { name: 'Microservice origin (signed origin header)', value: 'microservice-origin' },
          ],
        });
      }
      const answers = await inquirer.prompt(questions);
      platform = platform || answers.platform;
      profile = profile || answers.profile;
      archetype = archetype || answers.archetype;
    }

    const starterFile = archetype ? archetype + '.yml' : profile + '.yml';
    const starterDir = archetype ? 'archetypes' : 'profiles';
    const srcProfile = path.join(pkgRoot, 'policy', starterDir, starterFile);
    const profileFile = starterFile;
    const destSecurity = path.join(policyDir, 'security.yml');
    const destProfile = path.join(profilesDir, profileFile);

    if (!fs.existsSync(srcProfile)) {
      console.error('[ERROR] Starter policy not found in package:', srcProfile);
      process.exit(1);
    }

    const destStarterDir = path.join(cwd, 'policy', starterDir);
    const destStarter = path.join(destStarterDir, profileFile);

    if (!opts.force && (fs.existsSync(destSecurity) || fs.existsSync(destStarter))) {
      console.error('[ERROR] policy/security.yml or policy/' + starterDir + '/ already exists. Use --force to overwrite.');
      process.exit(1);
    }

    fs.mkdirSync(destStarterDir, { recursive: true });
    const content = fs.readFileSync(srcProfile, 'utf8');
    fs.writeFileSync(destSecurity, content, 'utf8');
    fs.writeFileSync(destStarter, content, 'utf8');

    console.log('[SUCCESS] Created policy/security.yml');
    console.log('[SUCCESS] Created policy/' + starterDir + '/' + profileFile);
  });

program
  .command('build')
  .description('Validate security.yml and generate Edge Runtime (dist/edge/*.js) and optionally Infra Config (dist/infra/*.tf.json)')
  .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
  .option('-o, --out-dir <dir>', 'Output directory', 'dist')
  .option('-t, --target <platform>', 'Target platform (aws | cloudflare)', 'aws')
  .option('--output-mode <mode>', 'AWS infra output mode: full | rule-group', 'full')
  .option('--rule-group-only', 'AWS only: generate WAF rule groups without aws_wafv2_web_acl output')
  .option('--fail-on-permissive', 'Exit non-zero when policy.metadata.risk_level is "permissive" (gate for production CI)')
  .action((opts) => {
    const cwd = process.cwd();
    let policyPath = opts.policy;
    if (!policyPath) {
      const security = path.join(cwd, 'policy', 'security.yml');
      const base = path.join(cwd, 'policy', 'base.yml');
      policyPath = fs.existsSync(security) ? security : base;
    } else if (!path.isAbsolute(policyPath)) {
      policyPath = path.join(cwd, policyPath);
    }
    const outDir = path.isAbsolute(opts.outDir) ? opts.outDir : path.join(cwd, opts.outDir);

    if (!fs.existsSync(policyPath)) {
      console.error('[ERROR] Policy file not found:', policyPath);
      process.exit(1);
    }

    // Lint
    const lintPath = path.join(pkgRoot, 'scripts', 'policy-lint.js');
    const { spawnSync } = require('child_process');
    const lintResult = spawnSync(process.execPath, [lintPath, policyPath], {
      stdio: 'inherit',
      cwd,
    });
    if (lintResult.status !== 0) {
      console.error('[ERROR] Policy validation failed.');
      process.exit(1);
    }
    console.log('[INFO] Validating policy... OK');

    const permissiveFlag = opts.failOnPermissive ? ['--fail-on-permissive'] : [];

    if (opts.target === 'aws') {
      console.log('[INFO] Target: AWS CloudFront Functions');
      const compilePath = path.join(pkgRoot, 'scripts', 'compile.js');
      const compileResult = spawnSync(process.execPath, [
        compilePath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...permissiveFlag,
      ], { stdio: 'inherit', cwd });
      if (compileResult.status !== 0) process.exit(1);
      console.log('[SUCCESS] Generated ' + path.join(outDir, 'edge', 'viewer-request.js'));
      console.log('[SUCCESS] Generated ' + path.join(outDir, 'edge', 'viewer-response.js'));
      console.log('[SUCCESS] Generated ' + path.join(outDir, 'edge', 'origin-request.js'));
      const compileInfraPath = path.join(pkgRoot, 'scripts', 'compile-infra.js');
      const compileInfraResult = spawnSync(process.execPath, [
        compileInfraPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        '--output-mode', opts.outputMode,
        ...(opts.ruleGroupOnly ? ['--rule-group-only'] : []),
      ], { stdio: 'inherit', cwd });
      if (compileInfraResult.status !== 0) process.exit(1);
      console.log('[SUCCESS] Generated ' + path.join(outDir, 'infra', '*.tf.json'));
    } else if (opts.target === 'cloudflare') {
      console.log('[INFO] Target: Cloudflare Workers');
      const compileCfPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare.js');
      const compileCfResult = spawnSync(process.execPath, [
        compileCfPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...permissiveFlag,
      ], { stdio: 'inherit', cwd });
      if (compileCfResult.status !== 0) process.exit(1);
      console.log('[SUCCESS] Generated ' + path.join(outDir, 'edge', 'cloudflare', 'index.ts'));
      const compileCfWafPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare-waf.js');
      const compileCfWafResult = spawnSync(process.execPath, [
        compileCfWafPath,
        '--policy', policyPath,
        '--out-dir', outDir,
      ], { stdio: 'inherit', cwd });
      if (compileCfWafResult.status !== 0) process.exit(1);
      console.log('[SUCCESS] Generated ' + path.join(outDir, 'infra', 'cloudflare-waf.tf.json'));
    } else {
      console.error('[ERROR] Unknown target:', opts.target);
      process.exit(1);
    }
  });

program
  .command('migrate')
  .description('Migrate a policy file between schema versions (stub — v1 is the only shipped version)')
  .option('-p, --policy <path>', 'Policy file path to inspect', 'policy/security.yml')
  .option('--to <version>', 'Target schema version', '1')
  .option('--write', 'Write the migrated policy back in place (no-op on v1)')
  .action((opts) => {
    const cwd = process.cwd();
    const policyPath = path.isAbsolute(opts.policy) ? opts.policy : path.join(cwd, opts.policy);
    if (!fs.existsSync(policyPath)) {
      console.error('[ERROR] Policy file not found:', policyPath);
      process.exit(1);
    }
    const yaml = require('js-yaml');
    const doc = yaml.load(fs.readFileSync(policyPath, 'utf8'));
    const fromVersion = doc && doc.version;
    const toVersion = Number(opts.to);

    if (fromVersion === undefined) {
      console.error('[ERROR] Policy has no `version` field. Add `version: 1` and retry.');
      process.exit(1);
    }
    if (Number.isNaN(toVersion)) {
      console.error('[ERROR] --to must be a number. Got:', opts.to);
      process.exit(1);
    }

    console.log('[INFO] Policy:', policyPath);
    console.log('[INFO] Current schema version:', fromVersion);
    console.log('[INFO] Target schema version: ', toVersion);

    if (fromVersion === toVersion) {
      console.log('[OK] Already at target version — no migration needed.');
      process.exit(0);
    }
    if (toVersion < fromVersion) {
      console.error('[ERROR] Downgrade migrations are not supported.');
      process.exit(1);
    }

    // Forward migrations are registered here when a new schema version ships.
    // The contract: each step is a pure function (v_n policy) -> (v_n+1 policy).
    // v1 is currently the only shipped schema, so there is nothing to run.
    console.error(`[ERROR] No migration path from v${fromVersion} to v${toVersion} is registered in this CLI version.`);
    console.error('        See docs/schema-migration.md for the migration policy and supported versions.');
    process.exit(2);
  });

program.parse();
