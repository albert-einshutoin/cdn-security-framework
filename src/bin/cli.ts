#!/usr/bin/env node
/**
 * cdn-security-framework CLI
 * Commands: init (scaffold policy YAML), build (compile policy → dist)
 */

const path = require('path');
const fs = require('fs');
const { Command } = require('commander');

const pkgRoot = path.resolve(__dirname, '..');

const program = new Command();

type InitOptions = {
  force?: boolean;
  platform?: string;
  profile?: string;
  archetype?: string;
};

type BuildOptions = {
  policy?: string | null;
  outDir: string;
  target: string;
  outputMode: string;
  ruleGroupOnly?: boolean;
  failOnPermissive?: boolean;
  failOnWafApproximation?: boolean;
};

type DoctorOptions = {
  policy?: string | null;
  report?: string | false | null;
  strict?: boolean;
};

type EmitWafOptions = {
  policy?: string | null;
  outDir: string;
  target: string;
  format: string;
  outputMode: string;
  ruleGroupOnly?: boolean;
  failOnWafApproximation?: boolean;
};

type MigrateOptions = {
  policy: string;
  to: string;
  write?: boolean;
};

type ExplainOptions = {
  policy?: string | null;
};

type DiffOptions = {
  policy?: string | null;
  outDir: string;
  target: string;
};

type StarterAnswers = {
  platform?: string;
  starterKind?: 'profile' | 'archetype';
  profile?: string;
  archetype?: string;
};

async function promptQuestions(questions: any[]) {
  // inquirer v13+ is ESM-only. Keep it lazy so simple commands like
  // `cdn-security --version` and `build` do not require loading the prompt UI.
  const dynamicImport = new Function('specifier', 'return import(specifier)');
  const mod = await dynamicImport('inquirer');
  const inquirer = mod.default || mod;
  return inquirer.prompt(questions);
}

function resolvePolicyPath(cwd: string, explicitPath?: string | null): string {
  if (explicitPath) return path.isAbsolute(explicitPath) ? explicitPath : path.join(cwd, explicitPath);
  const security = path.join(cwd, 'policy', 'security.yml');
  const base = path.join(cwd, 'policy', 'base.yml');
  return fs.existsSync(security) ? security : base;
}

function loadPolicyDocument(policyPath: string) {
  const yaml = require('js-yaml');
  return yaml.load(fs.readFileSync(policyPath, 'utf8'));
}

function explainPolicy(policy: any): string[] {
  const request = policy.request || {};
  const routes = Array.isArray(policy.routes) ? policy.routes : [];
  const firewall = policy.firewall || {};
  const waf = firewall.waf || {};
  const responseHeaders = policy.response_headers || {};
  const lines = [
    `Policy: ${policy.project || 'cdn-security'} (schema v${policy.version || 'unknown'})`,
    `Mode: ${(policy.defaults && policy.defaults.mode) || 'enforce'}`,
    `Allowed methods: ${(request.allow_methods || []).join(', ') || '(none)'}`,
  ];
  const limits = request.limits || {};
  if (Object.keys(limits).length > 0) {
    lines.push(`Request limits: ${Object.entries(limits).map(([k, v]) => `${k}=${v}`).join(', ')}`);
  }
  if (Array.isArray(request.allowed_hosts) && request.allowed_hosts.length > 0) {
    lines.push(`Host allowlist: ${request.allowed_hosts.join(', ')}`);
  }
  lines.push(`Routes: ${routes.length}`);
  for (const route of routes) {
    const prefixes = (((route || {}).match || {}).path_prefixes || []).join(', ') || '(no path prefixes)';
    const gate = (route || {}).auth_gate || {};
    lines.push(`- ${route.name || 'unnamed'}: ${prefixes}; auth=${gate.type || 'none'}`);
  }
  if (waf.rate_limit || Array.isArray(waf.managed_rules) || Array.isArray(waf.rate_limit_rules)) {
    const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules.length : 0;
    const fineGrained = Array.isArray(waf.rate_limit_rules) ? waf.rate_limit_rules.length : 0;
    lines.push(`WAF: rate_limit=${waf.rate_limit || 'none'}, managed_rules=${managed}, rate_limit_rules=${fineGrained}`);
  }
  const headerKeys = ['hsts', 'csp_public', 'csp_admin', 'csp_report_only', 'cors', 'cookie_attributes']
    .filter((key) => responseHeaders[key] !== undefined);
  lines.push(`Response headers: ${headerKeys.join(', ') || '(defaults only)'}`);
  return lines;
}

function collectFiles(root: string): string[] {
  if (!fs.existsSync(root)) return [];
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) walk(full);
      else out.push(path.relative(root, full));
    }
  };
  walk(root);
  return out.sort();
}

program
  .name('cdn-security')
  .description('CDN edge security: init policy YAML and build runtime code from policy')
  .version(require(path.join(pkgRoot, 'package.json')).version);

program
  .command('init')
  .description('Scaffold policy/security.yml from a profile or archetype (interactive or --platform/--profile)')
  .option('-f, --force', 'Overwrite existing policy files')
  .option('-p, --platform <name>', 'Platform: aws | cloudflare (skip interactive)')
  .option('--profile <name>', 'Profile: strict | balanced | permissive (skip interactive)')
  .option('--archetype <name>', 'Archetype: spa-static-site | rest-api | admin-panel | microservice-origin (mutually exclusive with --profile)')
  .action(async (opts: InitOptions) => {
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
      const questions: any[] = [];
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
          when: (a: StarterAnswers) => a.starterKind === 'profile',
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
          when: (a: StarterAnswers) => a.starterKind === 'archetype',
          choices: [
            { name: 'SPA / static site (immutable cache, CSP nonce)', value: 'spa-static-site' },
            { name: 'REST API (JWT-gated /api/*, CORS allowlist)', value: 'rest-api' },
            { name: 'Admin panel (static_token, no-store, strict CSP)', value: 'admin-panel' },
            { name: 'Microservice origin (signed origin header)', value: 'microservice-origin' },
          ],
        });
      }
      const answers: StarterAnswers = await promptQuestions(questions);
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
  .action((opts: BuildOptions) => {
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

    result.warnings.forEach((w: string) => console.warn(w));

    if (!result.ok) {
      result.errors.forEach((e: string) => console.error('[ERROR]', e));
      process.exit(1);
    }

    console.log('[INFO] Validating policy... OK');
    console.log('[INFO] Target:', result.target === 'aws' ? 'AWS CloudFront Functions' : 'Cloudflare Workers');
    result.edgeFiles.forEach((f: string) => console.log('[SUCCESS] Generated ' + f));
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
  .option('--strict', 'Treat warn checks as failures for production CI gates')
  .action((opts: DoctorOptions) => {
    const { runDoctor } = require(path.join(pkgRoot, 'scripts', 'cli-doctor.js'));
    const result = runDoctor({
      cwd: process.cwd(),
      pkgRoot,
      policyPath: opts.policy,
      reportPath: opts.report === false ? null : opts.report,
      strict: opts.strict,
    });
    process.exit(result.exitCode);
  });

program
  .command('explain')
  .description('Explain the effective security posture of a policy without generating runtime files')
  .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
  .action((opts: ExplainOptions) => {
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    let policy;
    try {
      policy = loadPolicyDocument(policyPath);
    } catch (e: any) {
      console.error('[ERROR] Failed to read policy:', e.message);
      process.exit(1);
    }
    explainPolicy(policy).forEach((line) => console.log(line));
  });

program
  .command('diff')
  .description('Compare current generated output with a fresh build from policy')
  .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
  .option('-o, --out-dir <dir>', 'Existing output directory to compare', 'dist')
  .option('-t, --target <platform>', 'Target platform (aws | cloudflare)', 'aws')
  .action((opts: DiffOptions) => {
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    const existingOutDir = path.isAbsolute(opts.outDir) ? opts.outDir : path.join(cwd, opts.outDir);
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cdn-security-diff-'));
    const freshOutDir = path.join(tmpRoot, 'dist');
    try {
      const { compile } = require(path.join(pkgRoot, 'lib'));
      const result = compile({
        policyPath,
        outDir: freshOutDir,
        target: opts.target,
        cwd,
        pkgRoot,
        env: process.env,
      });
      result.warnings.forEach((w: string) => console.warn(w));
      if (!result.ok) {
        result.errors.forEach((e: string) => console.error('[ERROR]', e));
        process.exit(1);
      }
      const existingFiles = collectFiles(existingOutDir);
      const freshFiles = collectFiles(freshOutDir);
      const allFiles = Array.from(new Set(existingFiles.concat(freshFiles))).sort();
      const diffs: string[] = [];
      for (const rel of allFiles) {
        const existingPath = path.join(existingOutDir, rel);
        const freshPath = path.join(freshOutDir, rel);
        if (!fs.existsSync(existingPath)) {
          diffs.push(`MISSING ${rel}`);
          continue;
        }
        if (!fs.existsSync(freshPath)) {
          diffs.push(`EXTRA ${rel}`);
          continue;
        }
        if (fs.readFileSync(existingPath, 'utf8') !== fs.readFileSync(freshPath, 'utf8')) {
          diffs.push(`CHANGED ${rel}`);
        }
      }
      if (diffs.length === 0) {
        console.log('[OK] Generated output matches policy.');
        process.exit(0);
      }
      diffs.forEach((line) => console.log(line));
      process.exit(1);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
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
  .action((opts: EmitWafOptions) => {
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

    result.warnings.forEach((w: string) => console.warn(w));

    if (!result.ok) {
      result.errors.forEach((e: string) => console.error('[ERROR]', e));
      // Reserved format = exit 2 so pipelines notice silent-fallback is not an option.
      process.exit(result.formatNotImplemented ? 2 : 1);
    }

    console.log('[INFO] Target:', result.target === 'aws' ? 'AWS WAFv2 / CloudFront infra' : 'Cloudflare WAF');
    if (result.infraFiles.length > 0) {
      result.infraFiles.forEach((f: string) => console.log('[SUCCESS] Generated ' + f));
    }
  });

program
  .command('migrate')
  .description('Migrate a policy file between schema versions (stub — v1 is the only shipped version)')
  .option('-p, --policy <path>', 'Policy file path to inspect', 'policy/security.yml')
  .option('--to <version>', 'Target schema version', '1')
  .option('--write', 'Write the migrated policy back in place (no-op on v1)')
  .action((opts: MigrateOptions) => {
    const { migratePolicy } = require(path.join(pkgRoot, 'lib'));
    const cwd = process.cwd();
    const policyPath = path.isAbsolute(opts.policy) ? opts.policy : path.join(cwd, opts.policy);

    const result = migratePolicy({
      policyPath,
      toVersion: opts.to,
      cwd,
      write: !!opts.write,
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
      result.errors.forEach((e: string) => console.error('[ERROR]', e));
      process.exit(result.reservedExit2 ? 2 : 1);
    }
  });

program.parse();
