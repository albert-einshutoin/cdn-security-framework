#!/usr/bin/env node
// @ts-nocheck
// @ts-nocheck
// @ts-nocheck
/**
 * cdn-security-framework CLI
 * Commands: init (scaffold policy YAML), build (compile policy → dist)
 */

const path = require('path');
const fs = require('fs');
const { Command } = require('commander');
// inquirer v13+ ships as ESM-only and is exposed through a CJS interop wrapper;
// `.default` holds the real module. `|| require('inquirer')` keeps us compatible
// with any earlier CJS-native version a consumer might still have hoisted.
const inquirer = require('inquirer').default || require('inquirer');

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
  .option('--fail-on-waf-approximation', 'Cloudflare only: exit non-zero when the policy relies on approximate or unsupported Cloudflare WAF mappings (see docs/cloudflare-waf-parity.md)')
  .action((opts) => {
    const { compile } = require(path.join(pkgRoot, 'lib'));
    const cwd = process.cwd();
    let policyPath = opts.policy;
    if (!policyPath) {
      const security = path.join(cwd, 'policy', 'security.yml');
      const base = path.join(cwd, 'policy', 'base.yml');
      policyPath = fs.existsSync(security) ? security : base;
    }

    const result = compile({
      policyPath,
      outDir: opts.outDir,
      target: opts.target,
      outputMode: opts.outputMode,
      ruleGroupOnly: !!opts.ruleGroupOnly,
      failOnPermissive: !!opts.failOnPermissive,
      failOnWafApproximation: !!opts.failOnWafApproximation,
      cwd,
      pkgRoot,
    });

    result.warnings.forEach((w) => console.warn(w));

    if (!result.ok) {
      result.errors.forEach((e) => console.error('[ERROR]', e));
      process.exit(1);
    }

    console.log('[INFO] Validating policy... OK');
    console.log('[INFO] Target:', result.target === 'aws' ? 'AWS CloudFront Functions' : 'Cloudflare Workers');
    result.edgeFiles.forEach((f) => console.log('[SUCCESS] Generated ' + f));
    if (result.infraFiles.length > 0) {
      console.log('[SUCCESS] Generated ' + path.join(result.outDir, 'infra', '*.tf.json'));
    }
  });

program
  .command('doctor')
  .description('Run environment diagnostics and print pass/fail report (exit non-zero on failure)')
  .option('-p, --policy <path>', 'Policy file path to inspect', null)
  .option('--report <path>', 'Write machine-readable JSON report to this path', 'doctor-report.json')
  .option('--no-report', 'Skip writing doctor-report.json')
  .action((opts) => {
    const { runDoctor } = require(path.join(pkgRoot, 'scripts', 'cli-doctor.js'));
    const result = runDoctor({
      cwd: process.cwd(),
      pkgRoot,
      policyPath: opts.policy,
      reportPath: opts.report === false ? null : opts.report,
    });
    process.exit(result.exitCode);
  });

program
  .command('emit-waf')
  .description('Generate only the WAF/infra config (no edge code). Use when edge is already deployed and you only need to refresh firewall rules.')
  .option('-p, --policy <path>', 'Policy file path', null)
  .option('-o, --out-dir <dir>', 'Output directory', 'dist')
  .option('-t, --target <platform>', 'Target platform (aws | cloudflare)', 'aws')
  .option('--output-mode <mode>', 'AWS infra output mode: full | rule-group', 'full')
  .option('--rule-group-only', 'AWS only: generate WAF rule groups without aws_wafv2_web_acl output')
  .option('--format <format>', 'Output format: terraform | cloudformation | cdk (terraform is the only format currently generated; others return exit 2)', 'terraform')
  .option('--fail-on-waf-approximation', 'Cloudflare only: exit non-zero when the policy relies on approximate or unsupported Cloudflare WAF mappings (see docs/cloudflare-waf-parity.md)')
  .action((opts) => {
    const { emitWaf } = require(path.join(pkgRoot, 'lib'));
    const cwd = process.cwd();
    let policyPath = opts.policy;
    if (!policyPath) {
      const security = path.join(cwd, 'policy', 'security.yml');
      const base = path.join(cwd, 'policy', 'base.yml');
      policyPath = fs.existsSync(security) ? security : base;
    }

    const result = emitWaf({
      policyPath,
      outDir: opts.outDir,
      target: opts.target,
      format: opts.format,
      outputMode: opts.outputMode,
      ruleGroupOnly: !!opts.ruleGroupOnly,
      failOnWafApproximation: !!opts.failOnWafApproximation,
      cwd,
      pkgRoot,
    });

    result.warnings.forEach((w) => console.warn(w));

    if (!result.ok) {
      result.errors.forEach((e) => console.error('[ERROR]', e));
      // Reserved format = exit 2 so pipelines notice silent-fallback is not an option.
      process.exit(result.formatNotImplemented ? 2 : 1);
    }

    console.log('[INFO] Target:', result.target === 'aws' ? 'AWS WAFv2 / CloudFront infra' : 'Cloudflare WAF');
    if (result.infraFiles.length > 0) {
      console.log('[SUCCESS] Generated ' + path.join(result.outDir, 'infra', '*.tf.json'));
    }
  });

program
  .command('migrate')
  .description('Migrate a policy file between schema versions (stub — v1 is the only shipped version)')
  .option('-p, --policy <path>', 'Policy file path to inspect', 'policy/security.yml')
  .option('--to <version>', 'Target schema version', '1')
  .option('--write', 'Write the migrated policy back in place (no-op on v1)')
  .action((opts) => {
    const { migratePolicy } = require(path.join(pkgRoot, 'lib'));
    const cwd = process.cwd();
    const policyPath = path.isAbsolute(opts.policy) ? opts.policy : path.join(cwd, opts.policy);

    const result = migratePolicy({
      policyPath,
      toVersion: opts.to,
      cwd,
    });

    if (result.fromVersion !== undefined) {
      console.log('[INFO] Policy:', policyPath);
      console.log('[INFO] Current schema version:', result.fromVersion);
      console.log('[INFO] Target schema version: ', result.toVersion);
    }

    if (result.ok && result.noop) {
      console.log('[OK] Already at target version — no migration needed.');
      process.exit(0);
    }

    if (!result.ok) {
      result.errors.forEach((e) => console.error('[ERROR]', e));
      process.exit(result.reservedExit2 ? 2 : 1);
    }
  });

program.parse();
