#!/usr/bin/env node
"use strict";
/**
 * cdn-security-framework CLI
 * Commands: init (scaffold policy YAML), build (compile policy → dist)
 */
Object.defineProperty(exports, "__esModule", { value: true });
const path = require('path');
const fs = require('fs');
const { Command } = require('commander');
const pkgRoot = path.resolve(__dirname, '..');
const program = new Command();
async function promptQuestions(questions) {
    // inquirer v13+ is ESM-only. Keep it lazy so simple commands like
    // `cdn-security --version` and `build` do not require loading the prompt UI.
    const dynamicImport = new Function('specifier', 'return import(specifier)');
    const mod = await dynamicImport('inquirer');
    const inquirer = mod.default || mod;
    return inquirer.prompt(questions);
}
function resolvePolicyPath(cwd, explicitPath) {
    if (explicitPath)
        return path.isAbsolute(explicitPath) ? explicitPath : path.join(cwd, explicitPath);
    const security = path.join(cwd, 'policy', 'security.yml');
    const base = path.join(cwd, 'policy', 'base.yml');
    return fs.existsSync(security) ? security : base;
}
function loadPolicyDocument(policyPath) {
    const yaml = require('js-yaml');
    return yaml.load(fs.readFileSync(policyPath, 'utf8'));
}
function explainPolicy(policy) {
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
function readinessFinding(severity, id, detail, recommendation) {
    return { severity, id, detail, recommendation };
}
function evaluateReadiness(policy, target, lintWarnings) {
    const findings = [];
    const metadata = (policy && policy.metadata) || {};
    const defaults = (policy && policy.defaults) || {};
    const request = (policy && policy.request) || {};
    const responseHeaders = (policy && policy.response_headers) || {};
    const firewall = (policy && policy.firewall) || {};
    const waf = firewall.waf || {};
    const riskLevel = metadata.risk_level;
    if (riskLevel === 'permissive') {
        findings.push(readinessFinding('fail', 'policy.risk_level.permissive', 'metadata.risk_level is "permissive", which is intentionally loose.', 'Use a balanced or strict policy for production, or remove the permissive tag only after tightening the policy.'));
    }
    else if (!riskLevel) {
        findings.push(readinessFinding('warn', 'policy.risk_level.missing', 'metadata.risk_level is not set.', 'Set metadata.risk_level to balanced or strict so production gates can reason about policy intent.'));
    }
    const mode = defaults.mode || 'enforce';
    if (mode !== 'enforce') {
        findings.push(readinessFinding('fail', 'policy.mode.not_enforce', `defaults.mode is "${mode}", so some controls may only observe traffic.`, 'Use defaults.mode: enforce for production release artifacts.'));
    }
    if (!Array.isArray(request.allow_methods) || request.allow_methods.length === 0) {
        findings.push(readinessFinding('fail', 'request.allow_methods.empty', 'request.allow_methods is empty or missing.', 'Declare the smallest method set required by the application.'));
    }
    if (Array.isArray(request.allow_methods) && request.allow_methods.includes('TRACE')) {
        findings.push(readinessFinding('fail', 'request.allow_methods.trace', 'TRACE is allowed.', 'Remove TRACE from request.allow_methods for production.'));
    }
    if (!responseHeaders.hsts) {
        findings.push(readinessFinding('warn', 'response_headers.hsts.missing', 'HSTS is not configured.', 'Configure response_headers.hsts for HTTPS-only production sites.'));
    }
    if (!responseHeaders.csp_public && !responseHeaders.csp_admin) {
        findings.push(readinessFinding('warn', 'response_headers.csp.missing', 'No CSP policy is configured.', 'Add csp_public and, if needed, csp_admin before production rollout.'));
    }
    if (!firewall.waf) {
        findings.push(readinessFinding('warn', 'firewall.waf.missing', 'firewall.waf is not configured.', 'Add WAF rate limits and managed rules for production traffic.'));
    }
    else {
        if (!waf.rate_limit && !Array.isArray(waf.rate_limit_rules)) {
            findings.push(readinessFinding('warn', 'firewall.waf.rate_limit.missing', 'No global or scoped WAF rate limit is configured.', 'Set firewall.waf.rate_limit or firewall.waf.rate_limit_rules for production.'));
        }
        const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
        const hasCoreSignal = managed.some((r) => r === 'AWSManagedRulesBotControlRuleSet' ||
            r === 'AWSManagedRulesATPRuleSet' ||
            r === 'AWSManagedRulesIPReputationList' ||
            r === 'AWSManagedRulesAnonymousIpList');
        if (!hasCoreSignal) {
            findings.push(readinessFinding('warn', 'firewall.waf.managed_rules.core_signal_missing', 'Managed WAF rules omit BotControl, ATP, IPReputation, and AnonymousIp.', 'Consider at least AWSManagedRulesIPReputationList and AWSManagedRulesAnonymousIpList for production enforce mode.'));
        }
        if (target === 'cloudflare') {
            const { classifyManagedRule } = require(path.join(pkgRoot, 'scripts', 'lib', 'cloudflare-waf-parity.js'));
            for (const rule of managed) {
                const entry = classifyManagedRule(rule);
                if (entry.status === 'unsupported') {
                    findings.push(readinessFinding('fail', `cloudflare.waf.managed_rule.unsupported.${rule}`, `${rule} has no Cloudflare WAF mapping and would be emitted disabled.`, 'Remove the AWS-only managed rule from Cloudflare builds or replace it with an explicit Cloudflare rule.'));
                }
                else if (entry.status === 'approximate') {
                    findings.push(readinessFinding('warn', `cloudflare.waf.managed_rule.approximate.${rule}`, `${rule} maps only approximately to Cloudflare.`, 'Review docs/cloudflare-waf-parity.md and decide whether the approximation is acceptable before production.'));
                }
            }
        }
    }
    if (target === 'aws') {
        if (request.graphql_guard) {
            findings.push(readinessFinding('fail', 'target.aws.graphql_guard.unsupported', 'request.graphql_guard is configured, but AWS edge output cannot read request bodies.', 'Use Cloudflare Workers for this guard or enforce GraphQL limits at the origin.'));
        }
        if (firewall.challenge) {
            findings.push(readinessFinding('fail', 'target.aws.challenge.unsupported', 'firewall.challenge is configured, but Edge JS challenge is Cloudflare Workers-only.', 'Disable firewall.challenge for AWS builds or use a Cloudflare target.'));
        }
        if (policy && policy.response_dlp && policy.response_dlp.enabled === true) {
            findings.push(readinessFinding('fail', 'target.aws.response_dlp.unsupported', 'response_dlp is enabled, but AWS CloudFront Functions cannot inspect response bodies.', 'Use Cloudflare Workers or enforce response DLP in Lambda/origin/application code.'));
        }
    }
    for (const warning of lintWarnings) {
        if (warning.includes('managed_rules does not include any of BotControl')) {
            continue;
        }
        findings.push(readinessFinding('warn', 'policy.lint.warning', warning, 'Review the policy lint warning before promoting this artifact.'));
    }
    return findings;
}
function printReadinessReport(report) {
    console.log(`Readiness: ${report.status.toUpperCase()} (target=${report.target}, policy=${report.policyPath})`);
    if (report.findings.length === 0) {
        console.log('[OK] No production readiness findings.');
        return;
    }
    for (const finding of report.findings) {
        const marker = finding.severity === 'fail' ? 'FAIL' : 'WARN';
        const stream = finding.severity === 'fail' ? console.error : console.warn;
        stream(`[${marker}] ${finding.id}: ${finding.detail}`);
        stream(`       ${finding.recommendation}`);
    }
}
function renderAwsDeploymentWorkflow() {
    return `name: CDN Security AWS Build

on:
  workflow_dispatch:
  push:
    branches: [main]
    paths:
      - 'policy/**'
      - 'templates/**'
      - 'package.json'
      - 'package-lock.json'
      - '.github/workflows/cdn-security-aws.yml'

permissions:
  contents: read

jobs:
  build-cdn-security:
    runs-on: ubuntu-latest
    env:
      # Configure these as repository secrets. Do not commit production values.
      EDGE_ADMIN_TOKEN: \${{ secrets.EDGE_ADMIN_TOKEN }}
      ORIGIN_SECRET: \${{ secrets.ORIGIN_SECRET }}
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20.17.0'
          cache: npm

      - name: Install dependencies
        run: npm ci

      - name: Diagnose environment
        run: npx cdn-security doctor --no-report --strict

      - name: Check production readiness
        run: npx cdn-security readiness --target aws --strict --report readiness-report.json

      - name: Build AWS edge and WAF artifacts
        run: npx cdn-security build --target aws --out-dir dist

      - name: Upload generated artifacts
        uses: actions/upload-artifact@v4
        with:
          name: cdn-security-aws-artifacts
          path: |
            dist/edge/
            dist/infra/
            readiness-report.json

      # Deployment is intentionally left explicit. Wire dist/edge/*.js and
      # dist/infra/*.tf.json into your Terraform/CDK/CloudFront release flow.
`;
}
function renderCloudflareDeploymentWorkflow() {
    return `name: CDN Security Cloudflare Deploy

on:
  workflow_dispatch:
  push:
    branches: [main]
    paths:
      - 'policy/**'
      - 'templates/**'
      - 'wrangler.toml'
      - 'package.json'
      - 'package-lock.json'
      - '.github/workflows/cdn-security-cloudflare.yml'

permissions:
  contents: read

jobs:
  deploy-cdn-security:
    runs-on: ubuntu-latest
    env:
      # Configure these as repository secrets. Do not commit production values.
      EDGE_ADMIN_TOKEN: \${{ secrets.EDGE_ADMIN_TOKEN }}
      BASIC_AUTH_CREDS: \${{ secrets.BASIC_AUTH_CREDS }}
      URL_SIGNING_SECRET: \${{ secrets.URL_SIGNING_SECRET }}
      JWT_SECRET: \${{ secrets.JWT_SECRET }}
      ORIGIN_SECRET: \${{ secrets.ORIGIN_SECRET }}
      CHALLENGE_SECRET: \${{ secrets.CHALLENGE_SECRET }}
      CLOUDFLARE_API_TOKEN: \${{ secrets.CLOUDFLARE_API_TOKEN }}
      CLOUDFLARE_ACCOUNT_ID: \${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
      CDN_SECURITY_WORKER_SECRET_NAMES: EDGE_ADMIN_TOKEN,BASIC_AUTH_CREDS,URL_SIGNING_SECRET,JWT_SECRET,ORIGIN_SECRET,CHALLENGE_SECRET
      CDN_SECURITY_WORKER_SECRETS_FILE: \${{ runner.temp }}/cdn-security-worker-secrets.json
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20.17.0'
          cache: npm

      - name: Install dependencies
        run: npm ci

      - name: Diagnose environment
        run: npx cdn-security doctor --no-report --strict

      - name: Check production readiness
        run: npx cdn-security readiness --target cloudflare --strict --report readiness-report.json

      - name: Build Cloudflare Worker and WAF artifacts
        run: npx cdn-security build --target cloudflare --out-dir dist

      - name: Prepare Worker runtime secrets
        run: |
          node <<'NODE'
          const fs = require('fs');
          const secretsFile = process.env.CDN_SECURITY_WORKER_SECRETS_FILE || '/tmp/cdn-security-worker-secrets.json';
          const names = (process.env.CDN_SECURITY_WORKER_SECRET_NAMES || '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
          const secrets = {};
          for (const name of names) {
            const value = process.env[name];
            if (value) secrets[name] = value;
          }
          if (Object.keys(secrets).length === 0) {
            console.log('[INFO] No Worker runtime secrets configured; deploying without --secrets-file.');
            process.exit(0);
          }
          fs.writeFileSync(secretsFile, JSON.stringify(secrets));
          NODE

      - name: Deploy Worker with Wrangler
        run: |
          if [ -f "$CDN_SECURITY_WORKER_SECRETS_FILE" ]; then
            trap 'rm -f "$CDN_SECURITY_WORKER_SECRETS_FILE"' EXIT
            npx wrangler deploy dist/edge/cloudflare/index.ts --secrets-file "$CDN_SECURITY_WORKER_SECRETS_FILE"
          else
            npx wrangler deploy dist/edge/cloudflare/index.ts
          fi

      - name: Upload generated artifacts
        uses: actions/upload-artifact@v4
        with:
          name: cdn-security-cloudflare-artifacts
          path: |
            dist/edge/cloudflare/
            dist/infra/
            readiness-report.json

      # Configure wrangler.toml, routes, account-specific bindings, and any
      # extra policy secret env names before enabling production deploys.
`;
}
function writeDeploymentTemplates(opts, cwd) {
    const target = opts.target || 'all';
    if (!['aws', 'cloudflare', 'all'].includes(target)) {
        throw new Error('Invalid --target. Use aws, cloudflare, or all.');
    }
    const outDir = path.isAbsolute(opts.outDir) ? opts.outDir : path.join(cwd, opts.outDir);
    fs.mkdirSync(outDir, { recursive: true });
    const templates = [];
    if (target === 'aws' || target === 'all') {
        templates.push({ file: 'cdn-security-aws.yml', content: renderAwsDeploymentWorkflow() });
    }
    if (target === 'cloudflare' || target === 'all') {
        templates.push({ file: 'cdn-security-cloudflare.yml', content: renderCloudflareDeploymentWorkflow() });
    }
    const existing = templates
        .map((template) => path.join(outDir, template.file))
        .filter((filePath) => fs.existsSync(filePath));
    if (existing.length > 0 && !opts.force) {
        throw new Error(`${existing.join(', ')} already exists. Use --force to overwrite.`);
    }
    const written = [];
    for (const template of templates) {
        const filePath = path.join(outDir, template.file);
        fs.writeFileSync(filePath, template.content, 'utf8');
        written.push(filePath);
    }
    return written;
}
function collectFiles(root) {
    if (!fs.existsSync(root))
        return [];
    const out = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir)) {
            const full = path.join(dir, entry);
            const stat = fs.statSync(full);
            if (stat.isDirectory())
                walk(full);
            else
                out.push(path.relative(root, full));
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
        const answers = await promptQuestions(questions);
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
    .option('--allow-placeholder-token', 'Allow non-production placeholder credentials for static_token/basic_auth gates when referenced env vars are unset')
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
        allowPlaceholderToken: !!opts.allowPlaceholderToken,
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
    .option('--strict', 'Treat warn checks as failures for production CI gates')
    .action((opts) => {
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
    .command('readiness')
    .description('Evaluate whether a policy is ready for production release gates')
    .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
    .option('-t, --target <platform>', 'Target platform (aws | cloudflare)', 'aws')
    .option('--report <path>', 'Write machine-readable JSON report to this path', null)
    .option('--json', 'Print machine-readable JSON instead of a human report')
    .option('--strict', 'Exit non-zero on warnings as well as failures')
    .action((opts) => {
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    const target = opts.target === 'cloudflare' ? 'cloudflare' : 'aws';
    const { lintPolicy } = require(path.join(pkgRoot, 'lib'));
    const { runDoctor } = require(path.join(pkgRoot, 'scripts', 'cli-doctor.js'));
    const doctor = runDoctor({
        cwd,
        pkgRoot,
        policyPath,
        reportPath: null,
        log: false,
        strict: false,
    });
    const findings = [];
    for (const check of doctor.report.checks) {
        if (check.status === 'fail') {
            findings.push(readinessFinding('fail', `doctor.${check.name}`, check.detail, 'Fix this environment diagnostic before building production artifacts.'));
        }
        else if (check.status === 'warn') {
            findings.push(readinessFinding('warn', `doctor.${check.name}`, check.detail, 'Review this environment diagnostic before release.'));
        }
    }
    let policy = null;
    const lint = lintPolicy({ policyPath, pkgRoot, env: process.env });
    lint.errors.forEach((error) => findings.push(readinessFinding('fail', 'policy.lint.error', error, 'Fix policy validation before production release.')));
    if (lint.policy && typeof lint.policy === 'object') {
        policy = lint.policy;
        findings.push(...evaluateReadiness(policy, target, lint.warnings));
    }
    const failCount = findings.filter((f) => f.severity === 'fail').length;
    const warnCount = findings.filter((f) => f.severity === 'warn').length;
    const strict = Boolean(opts.strict);
    const exitCode = failCount > 0 || (strict && warnCount > 0) ? 1 : 0;
    const status = failCount > 0 ? 'fail' : warnCount > 0 ? 'warn' : 'pass';
    const report = {
        generatedAt: new Date().toISOString(),
        policyPath,
        target,
        strict,
        status,
        exitCode,
        summary: { fail: failCount, warn: warnCount },
        findings,
    };
    if (opts.report) {
        const reportPath = path.isAbsolute(opts.report) ? opts.report : path.join(cwd, opts.report);
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
    }
    if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
    }
    else {
        printReadinessReport(report);
    }
    process.exit(exitCode);
});
program
    .command('deploy-template')
    .description('Generate GitHub Actions deployment workflow templates for generated CDN security artifacts')
    .option('-o, --out-dir <dir>', 'Workflow output directory', '.github/workflows')
    .option('-t, --target <platform>', 'Target platform: aws | cloudflare | all', 'all')
    .option('-f, --force', 'Overwrite existing generated workflow templates')
    .action((opts) => {
    try {
        const files = writeDeploymentTemplates(opts, process.cwd());
        files.forEach((filePath) => console.log('[SUCCESS] Generated ' + filePath));
    }
    catch (e) {
        console.error('[ERROR]', e.message);
        process.exit(1);
    }
});
program
    .command('explain')
    .description('Explain the effective security posture of a policy without generating runtime files')
    .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
    .action((opts) => {
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    let policy;
    try {
        policy = loadPolicyDocument(policyPath);
    }
    catch (e) {
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
    .action((opts) => {
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
        result.warnings.forEach((w) => console.warn(w));
        if (!result.ok) {
            result.errors.forEach((e) => console.error('[ERROR]', e));
            process.exit(1);
        }
        const existingFiles = collectFiles(existingOutDir);
        const freshFiles = collectFiles(freshOutDir);
        const allFiles = Array.from(new Set(existingFiles.concat(freshFiles))).sort();
        const diffs = [];
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
    }
    finally {
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
        result.infraFiles.forEach((f) => console.log('[SUCCESS] Generated ' + f));
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
        result.errors.forEach((e) => console.error('[ERROR]', e));
        process.exit(result.reservedExit2 ? 2 : 1);
    }
});
program.parse();
