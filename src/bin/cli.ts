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
  guided?: boolean;
  appShape?: string;
  auth?: string;
  adminPaths?: string;
  corsOrigins?: string;
  waf?: string;
  geoBlock?: string;
  ipAllowlist?: string;
  deployment?: string;
  project?: string;
};

type BuildOptions = {
  policy?: string | null;
  outDir: string;
  target: string;
  outputMode: string;
  ruleGroupOnly?: boolean;
  failOnPermissive?: boolean;
  failOnWafApproximation?: boolean;
  allowPlaceholderToken?: boolean;
};

type DoctorOptions = {
  policy?: string | null;
  report?: string | false | null;
  strict?: boolean;
};

type ReadinessOptions = {
  policy?: string | null;
  target: string;
  report?: string | null;
  json?: boolean;
  strict?: boolean;
};

type DeployTemplateOptions = {
  outDir: string;
  target: string;
  force?: boolean;
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
  starterKind?: 'profile' | 'archetype' | 'guided';
  profile?: string;
  archetype?: string;
  appShape?: string;
  auth?: string;
  adminPaths?: string;
  corsOrigins?: string;
  waf?: string;
  geoBlock?: string;
  ipAllowlist?: string;
  deployment?: string;
  project?: string;
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

function csvList(value?: string | null): string[] {
  if (!value) return [];
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

function yamlString(value: string): string {
  return JSON.stringify(value);
}

function yamlInlineArray(values: string[]): string {
  return '[' + values.map(yamlString).join(', ') + ']';
}

function appendYamlList(lines: string[], indent: string, key: string, values: string[]): void {
  if (values.length === 0) return;
  lines.push(`${indent}${key}:`);
  values.forEach((value) => lines.push(`${indent}  - ${yamlString(value)}`));
}

function defaultAuthForShape(appShape: string): string {
  if (appShape === 'rest-api') return 'jwt';
  if (appShape === 'admin-panel') return 'static_token';
  if (appShape === 'microservice-origin') return 'signed_url';
  return 'none';
}

function defaultProtectedPaths(appShape: string, auth: string): string[] {
  if (auth === 'none') return [];
  if (appShape === 'rest-api') return ['/api/'];
  if (appShape === 'admin-panel') return ['/'];
  if (appShape === 'microservice-origin') return ['/internal/'];
  return ['/admin', '/docs', '/swagger'];
}

function defaultCorsOrigins(appShape: string): string[] {
  return appShape === 'rest-api' ? ['https://app.example.com'] : [];
}

function guidedAllowMethods(appShape: string): string[] {
  if (appShape === 'spa-static-site') return ['GET', 'HEAD'];
  if (appShape === 'admin-panel') return ['GET', 'HEAD', 'POST'];
  return ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
}

function guidedRateLimit(waf: string): number {
  if (waf === 'strict') return 500;
  if (waf === 'basic') return 5000;
  return 2000;
}

function guidedManagedRules(waf: string, platform: string): string[] {
  if (platform === 'cloudflare') {
    return ['AWSManagedRulesCommonRuleSet'];
  }

  const rules = [
    'AWSManagedRulesCommonRuleSet',
    'AWSManagedRulesKnownBadInputsRuleSet',
    'AWSManagedRulesIPReputationList',
  ];
  if (waf === 'balanced' || waf === 'strict') {
    rules.push('AWSManagedRulesSQLiRuleSet');
    rules.push('AWSManagedRulesAnonymousIpList');
  }
  if (waf === 'strict') {
    rules.push('AWSManagedRulesBotControlRuleSet');
  }
  return rules;
}

function hasGuidedInitOptions(opts: InitOptions): boolean {
  return Boolean(
    opts.appShape || opts.auth || opts.adminPaths || opts.corsOrigins ||
    opts.waf || opts.geoBlock || opts.ipAllowlist || opts.deployment || opts.project
  );
}

function validateGuidedChoice(name: string, value: string, allowed: string[]): void {
  if (!allowed.includes(value)) {
    throw new Error(`Invalid --${name}. Use one of: ${allowed.join(', ')}.`);
  }
}

function renderGuidedPolicy(opts: {
  platform: string;
  appShape: string;
  auth: string;
  protectedPaths: string[];
  corsOrigins: string[];
  waf: string;
  geoBlock: string[];
  ipAllowlist: string[];
  deployment: string;
  project: string;
}): string {
  const allowMethods = guidedAllowMethods(opts.appShape);
  const riskLevel = opts.waf === 'strict' ? 'strict' : opts.waf === 'basic' ? 'balanced' : 'balanced';
  const wafScope = opts.platform === 'aws' ? 'CLOUDFRONT' : 'REGIONAL';
  const csp = opts.appShape === 'rest-api'
    ? "default-src 'none'; frame-ancestors 'none';"
    : "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
  const lines: string[] = [
    '# Generated by `cdn-security init --guided`.',
    '# Secrets are referenced by environment variable name only. Store values in',
    '# CI/CD secrets or Cloudflare Worker secrets; never commit secret values.',
    '# Docs: docs/cli.md#init, docs/auth.md, docs/runbooks/secret-rotation.md',
    '',
    'version: 1',
    `project: ${yamlString(opts.project)}`,
    '',
    'metadata:',
    `  risk_level: ${riskLevel}`,
    `  description: ${yamlString(`Guided setup: ${opts.appShape} on ${opts.platform}, auth=${opts.auth}, deployment=${opts.deployment}.`)}`,
    '',
    'defaults:',
    '  mode: "enforce"',
    '  response:',
    '    add_security_headers: true',
    '',
    'request:',
    `  allow_methods: ${yamlInlineArray(allowMethods)}`,
    '  limits:',
    opts.waf === 'strict' ? '    max_query_length: 512' : '    max_query_length: 1024',
    opts.waf === 'strict' ? '    max_query_params: 20' : '    max_query_params: 30',
    opts.waf === 'strict' ? '    max_uri_length: 1024' : '    max_uri_length: 2048',
    opts.waf === 'strict' ? '    max_header_count: 48' : '    max_header_count: 64',
    '  block:',
    '    path_patterns:',
    '      contains:',
    '        - "/../"',
    '        - "%2e%2e"',
    '        - ".git/"',
    '        - ".env"',
    '    ua_contains:',
    '      - "sqlmap"',
    '      - "nikto"',
    '      - "acunetix"',
    '      - "masscan"',
    '    header_missing:',
    '      - "user-agent"',
    '  normalize:',
    '    drop_query_keys:',
    '      - "utm_source"',
    '      - "utm_medium"',
    '      - "utm_campaign"',
    '      - "utm_term"',
    '      - "utm_content"',
    '      - "gclid"',
    '      - "fbclid"',
  ];

  if (opts.auth !== 'none') {
    lines.push(
      '',
      'routes:',
      '  - name: protected',
      '    match:',
      `      path_prefixes: ${yamlInlineArray(opts.protectedPaths)}`,
      '    auth_gate:'
    );
    if (opts.auth === 'static_token') {
      lines.push(
        '      type: "static_token"',
        '      header: "x-edge-token"',
        '      # Set EDGE_ADMIN_TOKEN in CI/CD secrets. For Cloudflare, also expose it as a Worker secret.',
        '      token_env: "EDGE_ADMIN_TOKEN"'
      );
    } else if (opts.auth === 'basic_auth') {
      lines.push(
        '      type: "basic_auth"',
        '      # BASIC_AUTH_CREDS format: username:password. Store the value only in secret management.',
        '      credentials_env: "BASIC_AUTH_CREDS"'
      );
    } else if (opts.auth === 'jwt') {
      lines.push(
        '      type: "jwt"',
        '      algorithm: "RS256"',
        '      jwks_url: "https://auth.example.com/.well-known/jwks.json"',
        '      issuer: "https://auth.example.com/"',
        '      audience: "api.example.com"',
        '      clock_skew_sec: 30'
      );
    } else if (opts.auth === 'signed_url') {
      lines.push(
        '      type: "signed_url"',
        '      algorithm: "HMAC-SHA256"',
        '      # Set URL_SIGNING_SECRET in CI/CD secrets. For Cloudflare, also expose it as a Worker secret.',
        '      secret_env: "URL_SIGNING_SECRET"',
        '      expires_param: "exp"',
        '      signature_param: "sig"',
        '      exact_path: true',
        '      nonce_param: "nonce"'
      );
    }
    lines.push(
      '    response:',
      '      cache_control: "no-store"',
      '    request:',
      `      allow_methods: ${yamlInlineArray(allowMethods)}`
    );
  }

  lines.push(
    '',
    'observability:',
    '  log_format: "json"',
    '  correlation_id_header: "traceparent"',
    '  audit_log_auth: true',
    '  audit_hash_sub: true',
    '',
    'response_headers:',
    '  hsts: "max-age=31536000; includeSubDomains; preload"',
    '  x_content_type_options: "nosniff"',
    '  referrer_policy: "strict-origin-when-cross-origin"',
    '  permissions_policy: "camera=(), microphone=(), geolocation=()"',
    `  csp_public: ${yamlString(csp)}`
  );
  if (opts.auth !== 'none') {
    lines.push('  csp_admin: "default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';"');
  }
  if (opts.corsOrigins.length > 0) {
    lines.push('  cors:');
    appendYamlList(lines, '    ', 'allow_origins', opts.corsOrigins);
    lines.push(`    allow_methods: ${yamlInlineArray(allowMethods.includes('OPTIONS') ? allowMethods : allowMethods.concat(['OPTIONS']))}`);
    lines.push('    allow_headers: ["authorization", "content-type", "x-request-id", "x-edge-token"]');
    lines.push(`    allow_credentials: ${opts.corsOrigins.includes('*') ? 'false' : 'true'}`);
    lines.push('    max_age: 600');
  }

  lines.push(
    '',
    'firewall:',
    '  waf:',
    `    rate_limit: ${guidedRateLimit(opts.waf)}`,
    `    scope: ${wafScope}`,
    '    managed_rules:'
  );
  guidedManagedRules(opts.waf, opts.platform).forEach((rule) => lines.push(`      - ${yamlString(rule)}`));
  if (opts.platform === 'aws') {
    lines.push(
      '    logging:',
      '      enabled: true',
      '      destination_arn_env: "WAF_LOG_DESTINATION_ARN"',
      '      redacted_fields:',
      '        - "authorization"',
      '        - "cookie"',
      '        - "x-api-key"'
    );
  }
  if (opts.geoBlock.length > 0) {
    lines.push('  geo:');
    appendYamlList(lines, '    ', 'block_countries', opts.geoBlock.map((c) => c.toUpperCase()));
  }
  if (opts.ipAllowlist.length > 0) {
    lines.push('  ip:');
    appendYamlList(lines, '    ', 'allowlist', opts.ipAllowlist);
  }
  if (opts.auth === 'jwt') {
    lines.push(
      '  jwks:',
      '    stale_if_error_sec: 120',
      '    negative_cache_sec: 30',
      '    allowed_hosts:',
      '      - "auth.example.com"'
    );
  }
  return lines.join('\n') + '\n';
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

type ReadinessSeverity = 'fail' | 'warn';
type ReadinessFinding = {
  id: string;
  severity: ReadinessSeverity;
  detail: string;
  recommendation: string;
};

function readinessFinding(
  severity: ReadinessSeverity,
  id: string,
  detail: string,
  recommendation: string
): ReadinessFinding {
  return { severity, id, detail, recommendation };
}

function evaluateReadiness(policy: any, target: string, lintWarnings: string[]): ReadinessFinding[] {
  const findings: ReadinessFinding[] = [];
  const metadata = (policy && policy.metadata) || {};
  const defaults = (policy && policy.defaults) || {};
  const request = (policy && policy.request) || {};
  const responseHeaders = (policy && policy.response_headers) || {};
  const firewall = (policy && policy.firewall) || {};
  const waf = firewall.waf || {};

  const riskLevel = metadata.risk_level;
  if (riskLevel === 'permissive') {
    findings.push(readinessFinding(
      'fail',
      'policy.risk_level.permissive',
      'metadata.risk_level is "permissive", which is intentionally loose.',
      'Use a balanced or strict policy for production, or remove the permissive tag only after tightening the policy.'
    ));
  } else if (!riskLevel) {
    findings.push(readinessFinding(
      'warn',
      'policy.risk_level.missing',
      'metadata.risk_level is not set.',
      'Set metadata.risk_level to balanced or strict so production gates can reason about policy intent.'
    ));
  }

  const mode = defaults.mode || 'enforce';
  if (mode !== 'enforce') {
    findings.push(readinessFinding(
      'fail',
      'policy.mode.not_enforce',
      `defaults.mode is "${mode}", so some controls may only observe traffic.`,
      'Use defaults.mode: enforce for production release artifacts.'
    ));
  }

  if (!Array.isArray(request.allow_methods) || request.allow_methods.length === 0) {
    findings.push(readinessFinding(
      'fail',
      'request.allow_methods.empty',
      'request.allow_methods is empty or missing.',
      'Declare the smallest method set required by the application.'
    ));
  }
  if (Array.isArray(request.allow_methods) && request.allow_methods.includes('TRACE')) {
    findings.push(readinessFinding(
      'fail',
      'request.allow_methods.trace',
      'TRACE is allowed.',
      'Remove TRACE from request.allow_methods for production.'
    ));
  }

  if (!responseHeaders.hsts) {
    findings.push(readinessFinding(
      'warn',
      'response_headers.hsts.missing',
      'HSTS is not configured.',
      'Configure response_headers.hsts for HTTPS-only production sites.'
    ));
  }
  if (!responseHeaders.csp_public && !responseHeaders.csp_admin) {
    findings.push(readinessFinding(
      'warn',
      'response_headers.csp.missing',
      'No CSP policy is configured.',
      'Add csp_public and, if needed, csp_admin before production rollout.'
    ));
  }

  if (!firewall.waf) {
    findings.push(readinessFinding(
      'warn',
      'firewall.waf.missing',
      'firewall.waf is not configured.',
      'Add WAF rate limits and managed rules for production traffic.'
    ));
  } else {
    if (!waf.rate_limit && !Array.isArray(waf.rate_limit_rules)) {
      findings.push(readinessFinding(
        'warn',
        'firewall.waf.rate_limit.missing',
        'No global or scoped WAF rate limit is configured.',
        'Set firewall.waf.rate_limit or firewall.waf.rate_limit_rules for production.'
      ));
    }
    const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
    const hasCoreSignal = managed.some((r: string) =>
      r === 'AWSManagedRulesBotControlRuleSet' ||
      r === 'AWSManagedRulesATPRuleSet' ||
      r === 'AWSManagedRulesIPReputationList' ||
      r === 'AWSManagedRulesAnonymousIpList'
    );
    if (target === 'aws' && !hasCoreSignal) {
      findings.push(readinessFinding(
        'warn',
        'firewall.waf.managed_rules.core_signal_missing',
        'Managed WAF rules omit BotControl, ATP, IPReputation, and AnonymousIp.',
        'Consider at least AWSManagedRulesIPReputationList and AWSManagedRulesAnonymousIpList for production enforce mode.'
      ));
    }
    if (target === 'cloudflare') {
      const { classifyManagedRule } = require(path.join(pkgRoot, 'scripts', 'lib', 'cloudflare-waf-parity.js'));
      for (const rule of managed) {
        const entry = classifyManagedRule(rule);
        if (entry.status === 'unsupported') {
          findings.push(readinessFinding(
            'fail',
            `cloudflare.waf.managed_rule.unsupported.${rule}`,
            `${rule} has no Cloudflare WAF mapping and would be emitted disabled.`,
            'Remove the AWS-only managed rule from Cloudflare builds or replace it with an explicit Cloudflare rule.'
          ));
        } else if (entry.status === 'approximate') {
          findings.push(readinessFinding(
            'warn',
            `cloudflare.waf.managed_rule.approximate.${rule}`,
            `${rule} maps only approximately to Cloudflare.`,
            'Review docs/cloudflare-waf-parity.md and decide whether the approximation is acceptable before production.'
          ));
        }
      }
    }
  }

  if (target === 'aws') {
    if (request.graphql_guard) {
      findings.push(readinessFinding(
        'fail',
        'target.aws.graphql_guard.unsupported',
        'request.graphql_guard is configured, but AWS edge output cannot read request bodies.',
        'Use Cloudflare Workers for this guard or enforce GraphQL limits at the origin.'
      ));
    }
    if (firewall.challenge) {
      findings.push(readinessFinding(
        'fail',
        'target.aws.challenge.unsupported',
        'firewall.challenge is configured, but Edge JS challenge is Cloudflare Workers-only.',
        'Disable firewall.challenge for AWS builds or use a Cloudflare target.'
      ));
    }
    if (policy && policy.response_dlp && policy.response_dlp.enabled === true) {
      findings.push(readinessFinding(
        'fail',
        'target.aws.response_dlp.unsupported',
        'response_dlp is enabled, but AWS CloudFront Functions cannot inspect response bodies.',
        'Use Cloudflare Workers or enforce response DLP in Lambda/origin/application code.'
      ));
    }
  }

  for (const warning of lintWarnings) {
    if (warning.includes('managed_rules does not include any of BotControl')) {
      continue;
    }
    findings.push(readinessFinding(
      'warn',
      'policy.lint.warning',
      warning,
      'Review the policy lint warning before promoting this artifact.'
    ));
  }

  return findings;
}

function printReadinessReport(report: any): void {
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

function renderAwsDeploymentWorkflow(): string {
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

function renderCloudflareDeploymentWorkflow(): string {
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

function writeDeploymentTemplates(opts: DeployTemplateOptions, cwd: string): string[] {
  const target = opts.target || 'all';
  if (!['aws', 'cloudflare', 'all'].includes(target)) {
    throw new Error('Invalid --target. Use aws, cloudflare, or all.');
  }
  const outDir = path.isAbsolute(opts.outDir) ? opts.outDir : path.join(cwd, opts.outDir);
  fs.mkdirSync(outDir, { recursive: true });

  const templates: Array<{ file: string; content: string }> = [];
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

  const written: string[] = [];
  for (const template of templates) {
    const filePath = path.join(outDir, template.file);
    fs.writeFileSync(filePath, template.content, 'utf8');
    written.push(filePath);
  }
  return written;
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
  .description('Scaffold policy/security.yml from a profile, archetype, or guided setup')
  .option('-f, --force', 'Overwrite existing policy files')
  .option('-p, --platform <name>', 'Platform: aws | cloudflare (skip interactive)')
  .option('--profile <name>', 'Profile: strict | balanced | permissive (skip interactive)')
  .option('--archetype <name>', 'Archetype: spa-static-site | rest-api | admin-panel | microservice-origin (mutually exclusive with --profile)')
  .option('--guided', 'Run guided policy setup instead of copying a starter profile/archetype')
  .option('--app-shape <shape>', 'Guided: spa-static-site | rest-api | admin-panel | microservice-origin')
  .option('--auth <mode>', 'Guided: none | static_token | basic_auth | jwt | signed_url')
  .option('--admin-paths <paths>', 'Guided: comma-separated protected path prefixes')
  .option('--cors-origins <origins>', 'Guided: comma-separated CORS origins')
  .option('--waf <posture>', 'Guided: basic | balanced | strict')
  .option('--geo-block <countries>', 'Guided: comma-separated country codes to block')
  .option('--ip-allowlist <cidrs>', 'Guided: comma-separated CIDR allowlist')
  .option('--deployment <intent>', 'Guided: build-only | github-actions | terraform | wrangler')
  .option('--project <name>', 'Guided: policy project name')
  .action(async (opts: InitOptions) => {
    const cwd = process.cwd();
    const policyDir = path.join(cwd, 'policy');
    const profilesDir = path.join(cwd, 'policy', 'profiles');
    const canPrompt = Boolean(process.stdin.isTTY && process.stdout.isTTY);

    let platform = opts.platform;
    let profile = opts.profile;
    let archetype = opts.archetype;
    let guided = Boolean(opts.guided || hasGuidedInitOptions(opts));
    const archetypeNames = ['spa-static-site', 'rest-api', 'admin-panel', 'microservice-origin'];
    const authModes = ['none', 'static_token', 'basic_auth', 'jwt', 'signed_url'];
    const wafPostures = ['basic', 'balanced', 'strict'];
    const deploymentIntents = ['build-only', 'github-actions', 'terraform', 'wrangler'];
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
    if (guided && (profile || archetype)) {
      console.error('[ERROR] Specify --guided, --profile, or --archetype, not more than one starter mode.');
      process.exit(1);
    }
    if (guided && !platform && !canPrompt) {
      platform = 'aws';
    }
    try {
      if (opts.appShape) validateGuidedChoice('app-shape', opts.appShape, archetypeNames);
      if (opts.auth) validateGuidedChoice('auth', opts.auth, authModes);
      if (opts.waf) validateGuidedChoice('waf', opts.waf, wafPostures);
      if (opts.deployment) validateGuidedChoice('deployment', opts.deployment, deploymentIntents);
    } catch (e: any) {
      console.error('[ERROR]', e.message);
      process.exit(1);
    }

    if ((!platform || (!profile && !archetype && !guided)) && !canPrompt) {
      console.error('[ERROR] Interactive init requires a TTY. Use --guided, --profile, or --archetype with --platform for non-interactive setup.');
      process.exit(1);
    }
    if (!platform || (!profile && !archetype && !guided)) {
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
          message: 'Start from a profile, archetype, or guided setup?',
          choices: [
            { name: 'Guided setup — answer app/CDN/auth questions', value: 'guided' },
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
      guided = guided || answers.starterKind === 'guided';
      profile = profile || answers.profile;
      archetype = archetype || answers.archetype;
    }

    if (guided) {
      if (platform && !['aws', 'cloudflare'].includes(platform)) {
        console.error('[ERROR] Invalid --platform. Use aws or cloudflare.');
        process.exit(1);
      }
      const guidedQuestions: any[] = [];
      if (canPrompt && !opts.appShape) {
        guidedQuestions.push({
          type: 'list',
          name: 'appShape',
          message: 'What app shape are you protecting?',
          choices: [
            { name: 'SPA / static site', value: 'spa-static-site' },
            { name: 'REST API', value: 'rest-api' },
            { name: 'Admin panel', value: 'admin-panel' },
            { name: 'Microservice origin', value: 'microservice-origin' },
          ],
        });
      }
      if (canPrompt && !opts.auth) {
        guidedQuestions.push({
          type: 'list',
          name: 'auth',
          message: 'Which edge auth mode should protect sensitive paths?',
          default: (a: StarterAnswers) => defaultAuthForShape(a.appShape || opts.appShape || 'spa-static-site'),
          choices: [
            { name: 'None', value: 'none' },
            { name: 'Static token header', value: 'static_token' },
            { name: 'Basic auth', value: 'basic_auth' },
            { name: 'JWT via JWKS', value: 'jwt' },
            { name: 'HMAC signed URL', value: 'signed_url' },
          ],
        });
      }
      if (canPrompt && !opts.adminPaths) {
        guidedQuestions.push({
          type: 'input',
          name: 'adminPaths',
          message: 'Protected path prefixes (comma-separated):',
          default: (a: StarterAnswers) => defaultProtectedPaths(
            a.appShape || opts.appShape || 'spa-static-site',
            a.auth || opts.auth || defaultAuthForShape(a.appShape || opts.appShape || 'spa-static-site')
          ).join(','),
          when: (a: StarterAnswers) => (a.auth || opts.auth || 'none') !== 'none',
        });
      }
      if (canPrompt && !opts.corsOrigins) {
        guidedQuestions.push({
          type: 'input',
          name: 'corsOrigins',
          message: 'CORS allow origins (comma-separated, blank for none):',
          default: (a: StarterAnswers) => defaultCorsOrigins(a.appShape || opts.appShape || 'spa-static-site').join(','),
        });
      }
      if (canPrompt && !opts.waf) {
        guidedQuestions.push({
          type: 'list',
          name: 'waf',
          message: 'WAF posture:',
          choices: [
            { name: 'Balanced', value: 'balanced' },
            { name: 'Strict', value: 'strict' },
            { name: 'Basic', value: 'basic' },
          ],
        });
      }
      if (canPrompt && !opts.geoBlock) {
        guidedQuestions.push({
          type: 'input',
          name: 'geoBlock',
          message: 'Country codes to block (comma-separated, blank for none):',
          default: '',
        });
      }
      if (canPrompt && !opts.ipAllowlist) {
        guidedQuestions.push({
          type: 'input',
          name: 'ipAllowlist',
          message: 'IP allowlist CIDRs (comma-separated, blank for none):',
          default: '',
        });
      }
      if (canPrompt && !opts.deployment) {
        guidedQuestions.push({
          type: 'list',
          name: 'deployment',
          message: 'Deployment intent:',
          choices: [
            { name: 'Build artifacts only', value: 'build-only' },
            { name: 'Generate GitHub Actions later', value: 'github-actions' },
            { name: 'Terraform / CDK handoff', value: 'terraform' },
            { name: 'Cloudflare Wrangler', value: 'wrangler' },
          ],
        });
      }
      if (canPrompt && !opts.project) {
        guidedQuestions.push({
          type: 'input',
          name: 'project',
          message: 'Policy project name:',
          default: (a: StarterAnswers) => `guided-${a.appShape || opts.appShape || 'cdn-security'}`,
        });
      }
      const answers: StarterAnswers = guidedQuestions.length > 0 ? await promptQuestions(guidedQuestions) : {};
      const appShape = opts.appShape || answers.appShape || 'spa-static-site';
      const auth = opts.auth || answers.auth || defaultAuthForShape(appShape);
      const protectedPaths = csvList(opts.adminPaths || answers.adminPaths).length > 0
        ? csvList(opts.adminPaths || answers.adminPaths)
        : defaultProtectedPaths(appShape, auth);
      const corsOriginsInput = opts.corsOrigins ?? answers.corsOrigins;
      const content = renderGuidedPolicy({
        platform: platform || 'aws',
        appShape,
        auth,
        protectedPaths,
        corsOrigins: corsOriginsInput === undefined ? defaultCorsOrigins(appShape) : csvList(corsOriginsInput),
        waf: opts.waf || answers.waf || 'balanced',
        geoBlock: csvList(opts.geoBlock || answers.geoBlock),
        ipAllowlist: csvList(opts.ipAllowlist || answers.ipAllowlist),
        deployment: opts.deployment || answers.deployment || 'build-only',
        project: opts.project || answers.project || `guided-${appShape}`,
      });
      const destSecurity = path.join(policyDir, 'security.yml');
      if (!opts.force && fs.existsSync(destSecurity)) {
        console.error('[ERROR] policy/security.yml already exists. Use --force to overwrite.');
        process.exit(1);
      }
      fs.mkdirSync(policyDir, { recursive: true });
      fs.writeFileSync(destSecurity, content, 'utf8');
      console.log('[SUCCESS] Created policy/security.yml from guided setup');
      console.log('[INFO] Review secret env names and docs/runbooks/secret-rotation.md before production deploy.');
      return;
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
      allowPlaceholderToken: !!opts.allowPlaceholderToken,
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
  .command('readiness')
  .description('Evaluate whether a policy is ready for production release gates')
  .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
  .option('-t, --target <platform>', 'Target platform (aws | cloudflare)', 'aws')
  .option('--report <path>', 'Write machine-readable JSON report to this path', null)
  .option('--json', 'Print machine-readable JSON instead of a human report')
  .option('--strict', 'Exit non-zero on warnings as well as failures')
  .action((opts: ReadinessOptions) => {
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
    const findings: ReadinessFinding[] = [];
    for (const check of doctor.report.checks) {
      if (check.status === 'fail') {
        findings.push(readinessFinding(
          'fail',
          `doctor.${check.name}`,
          check.detail,
          'Fix this environment diagnostic before building production artifacts.'
        ));
      } else if (check.status === 'warn') {
        findings.push(readinessFinding(
          'warn',
          `doctor.${check.name}`,
          check.detail,
          'Review this environment diagnostic before release.'
        ));
      }
    }

    let policy = null;
    const lint = lintPolicy({ policyPath, pkgRoot, env: process.env });
    lint.errors.forEach((error: string) => findings.push(readinessFinding(
      'fail',
      'policy.lint.error',
      error,
      'Fix policy validation before production release.'
    )));
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
    } else {
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
  .action((opts: DeployTemplateOptions) => {
    try {
      const files = writeDeploymentTemplates(opts, process.cwd());
      files.forEach((filePath) => console.log('[SUCCESS] Generated ' + filePath));
    } catch (e: any) {
      console.error('[ERROR]', e.message);
      process.exit(1);
    }
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
