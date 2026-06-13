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
function isBlockedStatus(status) {
    const numericStatus = Number(status);
    return Number.isFinite(numericStatus) && numericStatus >= 400;
}
async function withMutedOutput(fn, condition) {
    if (!condition) {
        return await fn();
    }
    const stdoutWrite = process.stdout.write.bind(process.stdout);
    const stderrWrite = process.stderr.write.bind(process.stderr);
    const consoleLog = console.log;
    const consoleWarn = console.warn;
    const consoleError = console.error;
    const mutedWrite = () => true;
    const mutedConsole = () => undefined;
    process.stdout.write = mutedWrite;
    process.stderr.write = mutedWrite;
    console.log = mutedConsole;
    console.warn = mutedConsole;
    console.error = mutedConsole;
    try {
        return await fn();
    }
    finally {
        process.stdout.write = stdoutWrite;
        process.stderr.write = stderrWrite;
        console.log = consoleLog;
        console.warn = consoleWarn;
        console.error = consoleError;
    }
}
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
function csvList(value) {
    if (!value)
        return [];
    return value.split(',').map((s) => s.trim()).filter(Boolean);
}
function yamlString(value) {
    return JSON.stringify(value);
}
function yamlInlineArray(values) {
    return '[' + values.map(yamlString).join(', ') + ']';
}
function withYamlLanguageServerHint(content, schemaPath) {
    const schemaDirectivePrefix = '# yaml-language-server: $schema=';
    const normalizedContent = content.replace(/^\uFEFF/, '');
    const contentWithoutDirective = normalizedContent.replace(/^# yaml-language-server: \$schema=.*\r?\n(?:\r?\n)?/, '');
    return `${schemaDirectivePrefix}${schemaPath}\n\n${contentWithoutDirective}`;
}
function appendYamlList(lines, indent, key, values) {
    if (values.length === 0)
        return;
    lines.push(`${indent}${key}:`);
    values.forEach((value) => lines.push(`${indent}  - ${yamlString(value)}`));
}
function escapeMermaidLabel(value) {
    return value
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .trim();
}
function escapeHtml(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
function visualStatusFromTargets(targets, statusByTarget) {
    const selectedStatuses = targets.map((target) => statusByTarget[target]);
    const unique = new Set(selectedStatuses);
    if (targets.length > 1 && unique.size > 1)
        return 'target_specific';
    if (selectedStatuses[0] === 'unsupported')
        return 'unsupported';
    if (selectedStatuses[0] === 'partial' || selectedStatuses[0] === 'warning-only' || selectedStatuses.includes('partial') || selectedStatuses.includes('warning-only'))
        return 'monitor';
    return 'enforce';
}
function summaryForTargets(targets, statusByTarget) {
    return targets.map((target) => `${target}:${statusByTarget[target]}`).join(', ');
}
function collectVisualizedCapabilities(policy, target) {
    const configured = CAPABILITY_MATRIX.filter((entry) => {
        if (entry.configured)
            return entry.configured(policy);
        return anyPolicyPath(policy, entry.policyPaths);
    });
    if (configured.length === 0)
        return [];
    const targets = target === 'all' ? ['aws', 'cloudflare'] : [target];
    const ordered = configured
        .map((entry) => {
        const statusByTarget = {
            aws: entry.deploySupport.aws,
            cloudflare: entry.deploySupport.cloudflare,
        };
        return {
            category: entry.category,
            label: entry.label,
            id: entry.id,
            notes: entry.notes,
            statusByTarget,
            summary: summaryForTargets(targets, statusByTarget),
            visualStatus: visualStatusFromTargets(targets, statusByTarget),
        };
    })
        .sort((a, b) => `${a.category}\0${a.label}`.localeCompare(`${b.category}\0${b.label}`));
    return ordered;
}
function routePrefixSummary(route) {
    const match = route && route.match ? route.match : {};
    return Array.isArray(match.path_prefixes) ? match.path_prefixes : ['/'];
}
function routeMethodsSummary(route) {
    const request = route && route.request ? route.request : {};
    if (Array.isArray(request.allow_methods) && request.allow_methods.length > 0)
        return request.allow_methods;
    return [];
}
function routeAuthSummary(route) {
    const authGate = route && route.auth_gate ? route.auth_gate : {};
    return authGate && authGate.type ? authGate.type : 'none';
}
function renderPolicyVisualization(policyPath, target, options) {
    const policy = loadPolicyDocument(policyPath);
    const policyName = policy && policy.project ? String(policy.project) : 'unnamed-policy';
    const version = policy && Number(policy.version) ? String(policy.version) : '1';
    const routes = Array.isArray(policy && policy.routes) ? policy.routes : [];
    const controls = collectVisualizedCapabilities(policy, target);
    const requestedTargets = target === 'all' ? ['aws', 'cloudflare'] : [target];
    const lines = [];
    lines.push('flowchart LR');
    lines.push(`  policy["Policy: ${escapeMermaidLabel(`${policyName} (v${version})`)}"]`);
    lines.push('  edge["Edge / Request Intake"]');
    lines.push('  waf["WAF and Edge Control Coverage"]');
    lines.push('  origin["Origin / Upstream"]');
    lines.push('  response["Response / Output"]');
    lines.push('  policy --> edge');
    lines.push('  policy --> waf');
    lines.push('  waf --> origin');
    lines.push('  origin --> response');
    if (routes.length > 0) {
        lines.push('');
        lines.push('  subgraph Routes');
        routes.forEach((route, index) => {
            const idx = String(index + 1).padStart(2, '0');
            const routeNode = `route_${idx}`;
            const routeName = route && route.name ? route.name : `route-${idx}`;
            const prefixes = routePrefixSummary(route).map((value) => `"${escapeMermaidLabel(String(value))}"`).join(', ');
            const methods = routeMethodsSummary(route).map((value) => `"${escapeMermaidLabel(String(value))}"`).join(', ');
            const authType = routeAuthSummary(route);
            const methodSuffix = methods ? ` methods=${methods}` : '';
            lines.push(`    ${routeNode}[\"${escapeMermaidLabel(`${routeName}${methodSuffix} | auth=${authType} | paths=${prefixes}`)}\"]`);
            lines.push(`    edge --> ${routeNode}`);
        });
        lines.push('  end');
    }
    if (controls.length === 0) {
        lines.push('  note_no_controls["No configured control blocks were detected"]');
        lines.push('  waf --> note_no_controls');
        lines.push('  class note_no_controls monitor');
    }
    else {
        lines.push('');
        lines.push('  subgraph Controls');
        const groupedByCategory = {};
        controls.forEach((control) => {
            if (!groupedByCategory[control.category])
                groupedByCategory[control.category] = [];
            groupedByCategory[control.category].push(control);
        });
        for (const category of Object.keys(groupedByCategory).sort()) {
            lines.push(`    subgraph ${category.replace(/[^a-z0-9_]/gi, '_')}`);
            for (const control of groupedByCategory[category]) {
                const nodeId = `control_${escapeMermaidLabel(control.id).replace(/[^a-z0-9_]/gi, '_')}`;
                const targetSuffix = requestedTargets.length > 1 ? `targets=${control.summary}` : control.summary;
                const title = `${control.id} (${control.visualStatus})`;
                const detail = `${title}\\n${targetSuffix}\\n${control.notes}`;
                lines.push(`      ${nodeId}["${escapeMermaidLabel(detail)}"]`);
                lines.push(`      waf --> ${nodeId}`);
                lines.push(`      class ${nodeId} ${control.visualStatus}`);
            }
            lines.push('    end');
        }
        lines.push('  end');
    }
    lines.push('');
    lines.push('  classDef enforce fill:#dcfce7,stroke:#16a34a,color:#052e16');
    lines.push('  classDef monitor fill:#fff7ed,stroke:#ea580c,color:#7c2d12');
    lines.push('  classDef unsupported fill:#fee2e2,stroke:#dc2626,color:#7f1d1d');
    lines.push('  classDef target_specific fill:#fef9c3,stroke:#ca8a04,color:#713f12');
    lines.push(`  class policy,edge,waf,origin,response enforce`);
    lines.push(`  %% target: ${requestedTargets.join(', ')}`);
    const mermaid = lines.join('\n') + '\n';
    if (options?.format === 'html') {
        const htmlTitle = escapeHtml(policyName);
        const htmlMermaid = escapeHtml(mermaid);
        return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Policy visualization - ${htmlTitle}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 24px; }
  </style>
</head>
<body>
<pre class="mermaid">
${htmlMermaid}</pre>
<script>mermaid.initialize({ startOnLoad: true });</script>
</body>
</html>`;
    }
    return mermaid;
}
function defaultAuthForShape(appShape) {
    if (appShape === 'rest-api')
        return 'jwt';
    if (appShape === 'admin-panel')
        return 'static_token';
    if (appShape === 'microservice-origin')
        return 'signed_url';
    return 'none';
}
function defaultProtectedPaths(appShape, auth) {
    if (auth === 'none')
        return [];
    if (appShape === 'rest-api')
        return ['/api/'];
    if (appShape === 'admin-panel')
        return ['/'];
    if (appShape === 'microservice-origin')
        return ['/internal/'];
    return ['/admin', '/docs', '/swagger'];
}
function defaultCorsOrigins(appShape) {
    return appShape === 'rest-api' ? ['https://app.example.com'] : [];
}
function guidedAllowMethods(appShape) {
    if (appShape === 'spa-static-site')
        return ['GET', 'HEAD'];
    if (appShape === 'admin-panel')
        return ['GET', 'HEAD', 'POST'];
    return ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
}
function guidedRateLimit(waf) {
    if (waf === 'strict')
        return 500;
    if (waf === 'basic')
        return 5000;
    return 2000;
}
function guidedManagedRules(waf, platform) {
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
function hasGuidedInitOptions(opts) {
    return Boolean(opts.appShape || opts.auth || opts.adminPaths || opts.corsOrigins ||
        opts.waf || opts.geoBlock || opts.ipAllowlist || opts.deployment || opts.project);
}
function validateGuidedChoice(name, value, allowed) {
    if (!allowed.includes(value)) {
        throw new Error(`Invalid --${name}. Use one of: ${allowed.join(', ')}.`);
    }
}
function renderGuidedPolicy(opts) {
    const allowMethods = guidedAllowMethods(opts.appShape);
    const riskLevel = opts.waf === 'strict' ? 'strict' : opts.waf === 'basic' ? 'balanced' : 'balanced';
    const wafScope = opts.platform === 'aws' ? 'CLOUDFRONT' : 'REGIONAL';
    const csp = opts.appShape === 'rest-api'
        ? "default-src 'none'; frame-ancestors 'none';"
        : "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
    const lines = [
        '# yaml-language-server: $schema=./schema.json',
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
        lines.push('', 'routes:', '  - name: protected', '    match:', `      path_prefixes: ${yamlInlineArray(opts.protectedPaths)}`, '    auth_gate:');
        if (opts.auth === 'static_token') {
            lines.push('      type: "static_token"', '      header: "x-edge-token"', '      # Set EDGE_ADMIN_TOKEN in CI/CD secrets. For Cloudflare, also expose it as a Worker secret.', '      token_env: "EDGE_ADMIN_TOKEN"');
        }
        else if (opts.auth === 'basic_auth') {
            lines.push('      type: "basic_auth"', '      # BASIC_AUTH_CREDS format: username:password. Store the value only in secret management.', '      credentials_env: "BASIC_AUTH_CREDS"');
        }
        else if (opts.auth === 'jwt') {
            lines.push('      type: "jwt"', '      algorithm: "RS256"', '      jwks_url: "https://auth.example.com/.well-known/jwks.json"', '      issuer: "https://auth.example.com/"', '      audience: "api.example.com"', '      clock_skew_sec: 30');
        }
        else if (opts.auth === 'signed_url') {
            lines.push('      type: "signed_url"', '      algorithm: "HMAC-SHA256"', '      # Set URL_SIGNING_SECRET in CI/CD secrets. For Cloudflare, also expose it as a Worker secret.', '      secret_env: "URL_SIGNING_SECRET"', '      expires_param: "exp"', '      signature_param: "sig"', '      exact_path: true', '      nonce_param: "nonce"');
        }
        lines.push('    response:', '      cache_control: "no-store"', '    request:', `      allow_methods: ${yamlInlineArray(allowMethods)}`);
    }
    lines.push('', 'observability:', '  log_format: "json"', '  correlation_id_header: "traceparent"', '  audit_log_auth: true', '  audit_hash_sub: true', '', 'response_headers:', '  hsts: "max-age=31536000; includeSubDomains; preload"', '  x_content_type_options: "nosniff"', '  referrer_policy: "strict-origin-when-cross-origin"', '  permissions_policy: "camera=(), microphone=(), geolocation=()"', `  csp_public: ${yamlString(csp)}`);
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
    lines.push('', 'firewall:', '  waf:', `    rate_limit: ${guidedRateLimit(opts.waf)}`, `    scope: ${wafScope}`, '    managed_rules:');
    guidedManagedRules(opts.waf, opts.platform).forEach((rule) => lines.push(`      - ${yamlString(rule)}`));
    if (opts.platform === 'aws') {
        lines.push('    logging:', '      enabled: true', '      destination_arn_env: "WAF_LOG_DESTINATION_ARN"', '      redacted_fields:', '        - "authorization"', '        - "cookie"', '        - "x-api-key"');
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
        lines.push('  jwks:', '    stale_if_error_sec: 120', '    negative_cache_sec: 30', '    allowed_hosts:', '      - "auth.example.com"');
    }
    return lines.join('\n') + '\n';
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
function asStringArray(value) {
    if (!Array.isArray(value))
        return [];
    return value
        .map((item) => String(item))
        .map((item) => item.trim())
        .filter(Boolean)
        .sort();
}
function asPolicyObject(policy) {
    return (policy && typeof policy === 'object') ? policy : {};
}
function getPolicyPathValue(policy, path) {
    let current = asPolicyObject(policy);
    for (const part of path.split('.')) {
        if (!current || typeof current !== 'object' || !Object.prototype.hasOwnProperty.call(current, part)) {
            return undefined;
        }
        current = current[part];
    }
    return current;
}
function toSortedString(value) {
    if (value === undefined || value === null)
        return 'unset';
    if (Array.isArray(value))
        return value.map((item) => String(item)).sort().join(', ');
    if (typeof value === 'object')
        return JSON.stringify(value);
    return String(value);
}
function buildPolicyFinding(findings, params) {
    findings.push({
        id: params.id,
        category: params.category,
        severity: params.severity,
        summary: params.summary,
        before: toSortedString(params.before),
        after: toSortedString(params.after),
        impact: params.impact,
    });
}
function cspRiskScore(csp) {
    const normalized = csp.toLowerCase();
    let score = 0;
    if (normalized.includes("'unsafe-inline'"))
        score += 3;
    if (normalized.includes("'unsafe-eval'"))
        score += 3;
    if (/(^|[;\s])(?:default-src|script-src|connect-src|img-src)[^;]*\*/.test(normalized))
        score += 2;
    if (!/default-src/.test(normalized))
        score += 1;
    return score;
}
function routeSignature(route, index) {
    const routeName = typeof route?.name === 'string' ? route.name : `route-${index}`;
    const prefixes = asStringArray(route?.match?.path_prefixes).join('|') || '<no-path-prefixes>';
    const methods = asStringArray(route?.request?.allow_methods).join('|') || '<all-methods>';
    return `${routeName}|${prefixes}|${methods}`;
}
function collectAuthGates(policy) {
    const routes = Array.isArray(policy?.routes) ? policy.routes : [];
    const map = new Map();
    for (let i = 0; i < routes.length; i += 1) {
        const route = routes[i];
        const gate = route && route.auth_gate;
        map.set(routeSignature(route, i), gate && typeof gate.type === 'string' ? gate.type : 'none');
    }
    return map;
}
function compareCapabilitySupportFindings(baseline, candidate, baselinePolicyPath, candidatePolicyPath, targetList, findings) {
    const statusRank = {
        supported: 3,
        partial: 2,
        'warning-only': 1,
        unsupported: 0,
    };
    for (const deployTarget of targetList) {
        const baselineEvaluation = evaluatePolicyCapabilities(baseline, baselinePolicyPath, deployTarget);
        const candidateEvaluation = evaluatePolicyCapabilities(candidate, candidatePolicyPath, deployTarget);
        const baselineMap = new Map();
        const candidateMap = new Map();
        const policyIds = new Set();
        for (const control of baselineEvaluation.configuredControls) {
            baselineMap.set(control.id, control.targetSupport[deployTarget]);
            policyIds.add(control.id);
        }
        for (const control of candidateEvaluation.configuredControls) {
            candidateMap.set(control.id, control.targetSupport[deployTarget]);
            policyIds.add(control.id);
        }
        for (const id of policyIds) {
            const before = baselineMap.get(id);
            const after = candidateMap.get(id);
            if (!before && !after)
                continue;
            if (!before && after) {
                buildPolicyFinding(findings, {
                    id: `capability.${deployTarget}.${id}.added`,
                    category: 'Capability support',
                    severity: after === 'supported' ? 'low' : 'medium',
                    summary: `Configured control ${id} was added with ${after} support on ${deployTarget}.`,
                    before: '(not configured)',
                    after,
                    impact: after === 'supported'
                        ? 'Added target-supported control can improve enforcement posture.'
                        : 'Added control may not fully enforce on this deploy target.',
                });
                continue;
            }
            if (before && !after) {
                buildPolicyFinding(findings, {
                    id: `capability.${deployTarget}.${id}.removed`,
                    category: 'Capability support',
                    severity: before === 'supported' ? 'medium' : 'low',
                    summary: `Configured control ${id} was removed from ${deployTarget} evaluation.`,
                    before,
                    after: '(not configured)',
                    impact: before === 'supported'
                        ? 'Removing a target-supported control can weaken deploy-time enforcement.'
                        : 'Removing a non-fully-supported control may reduce target-specific surprises.',
                });
                continue;
            }
            if (!before || !after)
                continue;
            if (before === after)
                continue;
            const beforeScore = statusRank[before];
            const afterScore = statusRank[after];
            buildPolicyFinding(findings, {
                id: `capability.${deployTarget}.${id}`,
                category: 'Capability support',
                severity: afterScore < beforeScore ? 'medium' : 'low',
                summary: `Target support for ${id} changed from ${before} to ${after} on ${deployTarget}.`,
                before,
                after,
                impact: afterScore < beforeScore
                    ? 'Target-specific behavior may become non-enforcing or unsupported.'
                    : 'Target support improvement reduces operational surprises.',
            });
        }
    }
}
function compareSecurityPostureFindings(baselinePolicy, candidatePolicy, baselinePolicyPath, candidatePolicyPath, target) {
    const findings = [];
    const baseline = asPolicyObject(baselinePolicy);
    const candidate = asPolicyObject(candidatePolicy);
    const baselineMethods = asStringArray(getPolicyPathValue(baseline, 'request.allow_methods'));
    const candidateMethods = asStringArray(getPolicyPathValue(candidate, 'request.allow_methods'));
    const baselineMethodSet = new Set(baselineMethods);
    const candidateMethodSet = new Set(candidateMethods);
    for (const method of baselineMethods) {
        if (!candidateMethodSet.has(method)) {
            buildPolicyFinding(findings, {
                id: `request.allow_methods.removed.${method}`,
                category: 'Request posture',
                severity: 'low',
                summary: `Method ${method} was removed from allowlist.`,
                before: baselineMethods,
                after: candidateMethods,
                impact: 'Stricter method allowlist reduces exposed surface.',
            });
        }
    }
    for (const method of candidateMethods) {
        if (!baselineMethodSet.has(method)) {
            buildPolicyFinding(findings, {
                id: `request.allow_methods.added.${method}`,
                category: 'Request posture',
                severity: method === 'TRACE' ? 'high' : 'medium',
                summary: `Method ${method} was added to allowlist.`,
                before: baselineMethods,
                after: candidateMethods,
                impact: method === 'TRACE'
                    ? 'TRACE expands attack surface and should usually be blocked in production.'
                    : 'Broader allowed methods can increase risk of unauthorized state changes.',
            });
        }
    }
    const baselineLimits = asPolicyObject(getPolicyPathValue(baseline, 'request.limits'));
    const candidateLimits = asPolicyObject(getPolicyPathValue(candidate, 'request.limits'));
    const limitKeys = new Set([
        ...Object.keys(baselineLimits),
        ...Object.keys(candidateLimits),
    ]);
    for (const key of limitKeys) {
        const baselineValue = baselineLimits[key];
        const candidateValue = candidateLimits[key];
        const hasBaseline = typeof baselineValue === 'number';
        const hasCandidate = typeof candidateValue === 'number';
        if (!hasBaseline && hasCandidate) {
            buildPolicyFinding(findings, {
                id: `request.limits.added.${key}`,
                category: 'Request posture',
                severity: 'low',
                summary: `New request limit ${key} was added.`,
                before: undefined,
                after: candidateValue,
                impact: 'Added request limit usually improves enforcement posture.',
            });
            continue;
        }
        if (hasBaseline && !hasCandidate) {
            buildPolicyFinding(findings, {
                id: `request.limits.removed.${key}`,
                category: 'Request posture',
                severity: 'medium',
                summary: `Request limit ${key} was removed.`,
                before: baselineValue,
                after: undefined,
                impact: 'Removing request limits can increase DoS/abuse exposure.',
            });
            continue;
        }
        if (hasBaseline && hasCandidate && candidateValue !== baselineValue) {
            const isRelaxed = candidateValue > baselineValue;
            buildPolicyFinding(findings, {
                id: `request.limits.changed.${key}`,
                category: 'Request posture',
                severity: isRelaxed ? 'medium' : 'low',
                summary: `Request limit ${key} changed from ${baselineValue} to ${candidateValue}.`,
                before: baselineValue,
                after: candidateValue,
                impact: isRelaxed
                    ? 'Higher limits may allow heavier requests and slower filtering at edge.'
                    : 'Lower limits usually tighten request validation.',
            });
        }
    }
    const baselineMode = String(getPolicyPathValue(baseline, 'defaults.mode') || 'enforce');
    const candidateMode = String(getPolicyPathValue(candidate, 'defaults.mode') || 'enforce');
    if (baselineMode !== candidateMode) {
        const severity = candidateMode === 'enforce' ? 'low' : 'medium';
        buildPolicyFinding(findings, {
            id: 'defaults.mode',
            category: 'Operations',
            severity,
            summary: `defaults.mode changed from ${baselineMode} to ${candidateMode}.`,
            before: baselineMode,
            after: candidateMode,
            impact: candidateMode === 'enforce'
                ? 'Switching to enforce tightens production behavior.'
                : 'Switching away from enforce introduces report/monitor behavior and less blocking.',
        });
    }
    const riskRank = { permissive: 1, balanced: 2, strict: 3 };
    const baselineRisk = String(getPolicyPathValue(baseline, 'metadata.risk_level') || 'unset');
    const candidateRisk = String(getPolicyPathValue(candidate, 'metadata.risk_level') || 'unset');
    if (baselineRisk !== candidateRisk) {
        const baselineWeight = riskRank[baselineRisk] || 2;
        const candidateWeight = riskRank[candidateRisk] || 2;
        const isLoosened = candidateWeight < baselineWeight;
        buildPolicyFinding(findings, {
            id: 'metadata.risk_level',
            category: 'Policy posture',
            severity: isLoosened ? 'medium' : 'low',
            summary: `metadata.risk_level changed from ${baselineRisk} to ${candidateRisk}.`,
            before: baselineRisk,
            after: candidateRisk,
            impact: isLoosened
                ? 'Lowering risk level typically relaxes policy intent and may increase permissiveness.'
                : 'Raising risk level usually indicates stricter posture.',
        });
    }
    const cspHeaders = ['csp_public', 'csp_admin', 'csp_report_only'];
    for (const header of cspHeaders) {
        const before = String(getPolicyPathValue(baseline, `response_headers.${header}`) || '');
        const after = String(getPolicyPathValue(candidate, `response_headers.${header}`) || '');
        if (before === after)
            continue;
        if (!before) {
            buildPolicyFinding(findings, {
                id: `response_headers.${header}.added`,
                category: 'Response security',
                severity: 'low',
                summary: `${header} was added to response policy.`,
                before: '(missing)',
                after,
                impact: 'Adding CSP reduces browser-side attack surface.',
            });
            continue;
        }
        if (!after) {
            buildPolicyFinding(findings, {
                id: `response_headers.${header}.removed`,
                category: 'Response security',
                severity: 'medium',
                summary: `${header} was removed from response policy.`,
                before,
                after: '(missing)',
                impact: 'Removing CSP can broaden script/iframe and injection risk.',
            });
            continue;
        }
        const beforeRisk = cspRiskScore(before);
        const afterRisk = cspRiskScore(after);
        if (afterRisk > beforeRisk) {
            buildPolicyFinding(findings, {
                id: `response_headers.${header}.weakened`,
                category: 'Response security',
                severity: 'medium',
                summary: `${header} became more permissive.`,
                before,
                after,
                impact: 'Relaxed CSP directives can increase CSP bypass opportunities.',
            });
        }
        else if (afterRisk < beforeRisk) {
            buildPolicyFinding(findings, {
                id: `response_headers.${header}.tightened`,
                category: 'Response security',
                severity: 'low',
                summary: `${header} became stricter.`,
                before,
                after,
                impact: 'Stronger CSP directives reduce XSS/preload risk.',
            });
        }
    }
    const baselineManagedRules = new Set(asStringArray(getPolicyPathValue(baseline, 'firewall.waf.managed_rules')).map((rule) => rule.toLowerCase()));
    const candidateManagedRules = new Set(asStringArray(getPolicyPathValue(candidate, 'firewall.waf.managed_rules')).map((rule) => rule.toLowerCase()));
    for (const rule of baselineManagedRules) {
        if (!candidateManagedRules.has(rule)) {
            buildPolicyFinding(findings, {
                id: `firewall.waf.managed_rules.removed.${rule}`,
                category: 'WAF',
                severity: 'high',
                summary: `Managed rule ${rule} was removed.`,
                before: [...baselineManagedRules].sort().join(','),
                after: [...candidateManagedRules].sort().join(','),
                impact: 'Removing managed WAF rules can weaken managed protections.',
            });
        }
    }
    for (const rule of candidateManagedRules) {
        if (!baselineManagedRules.has(rule)) {
            buildPolicyFinding(findings, {
                id: `firewall.waf.managed_rules.added.${rule}`,
                category: 'WAF',
                severity: 'low',
                summary: `Managed rule ${rule} was added.`,
                before: [...baselineManagedRules].sort().join(','),
                after: [...candidateManagedRules].sort().join(','),
                impact: 'Adding managed rules generally improves attack coverage.',
            });
        }
    }
    const baseAuthBySignature = collectAuthGates(baseline);
    const candidateAuthBySignature = collectAuthGates(candidate);
    for (const [signature, baseType] of baseAuthBySignature.entries()) {
        const candidateType = candidateAuthBySignature.get(signature);
        if (candidateType === undefined)
            continue;
        if (baseType === candidateType)
            continue;
        const isRegression = baseType !== 'none' && candidateType === 'none';
        buildPolicyFinding(findings, {
            id: `routes.auth_gate.changed.${signature}`,
            category: 'Authentication',
            severity: isRegression ? 'high' : 'low',
            summary: `Route ${signature} auth gate changed from ${baseType} to ${candidateType}.`,
            before: baseType,
            after: candidateType,
            impact: isRegression
                ? 'Authentication gate removal can expose protected routes to unauthorized traffic.'
                : 'Auth gate strengthening can reduce unauthenticated access.',
        });
    }
    const gqlKeys = new Set([
        ...Object.keys(asPolicyObject(getPolicyPathValue(baseline, 'request.graphql_guard') || {})),
        ...Object.keys(asPolicyObject(getPolicyPathValue(candidate, 'request.graphql_guard') || {})),
    ]);
    const baseGraphql = asPolicyObject(getPolicyPathValue(baseline, 'request.graphql_guard') || {});
    const candidateGraphql = asPolicyObject(getPolicyPathValue(candidate, 'request.graphql_guard') || {});
    if (gqlKeys.size > 0) {
        const baseEnabled = Boolean(baseGraphql.enabled);
        const candidateEnabled = Boolean(candidateGraphql.enabled);
        if (baseEnabled !== candidateEnabled) {
            buildPolicyFinding(findings, {
                id: 'request.graphql_guard.enabled',
                category: 'Edge controls',
                severity: !candidateEnabled ? 'medium' : 'low',
                summary: `GraphQL guard ${candidateEnabled ? 'enabled' : 'disabled'}.`,
                before: baseEnabled,
                after: candidateEnabled,
                impact: candidateEnabled
                    ? 'GraphQL guard adds request-body-aware abuse protection.'
                    : 'Disabling GraphQL guard removes a body-based abuse control.',
            });
        }
        for (const key of gqlKeys) {
            const baselineValue = baseGraphql[key];
            const candidateValue = candidateGraphql[key];
            if (baselineValue === candidateValue)
                continue;
            if (typeof baselineValue === 'number' && typeof candidateValue === 'number' && key.includes('limit')) {
                const isRelaxed = candidateValue > baselineValue;
                buildPolicyFinding(findings, {
                    id: `request.graphql_guard.${key}`,
                    category: 'Edge controls',
                    severity: isRelaxed ? 'medium' : 'low',
                    summary: `GraphQL guard ${key} changed from ${baselineValue} to ${candidateValue}.`,
                    before: baselineValue,
                    after: candidateValue,
                    impact: isRelaxed
                        ? 'Higher GraphQL guard thresholds increase body complexity and runtime cost.'
                        : 'Lower limits can reduce exploitability from expensive queries.',
                });
            }
        }
    }
    if (target === 'all' || target === 'aws' || target === 'cloudflare') {
        const targetList = target === 'all'
            ? ['aws', 'cloudflare']
            : [target];
        compareCapabilitySupportFindings(baseline, candidate, baselinePolicyPath, candidatePolicyPath, targetList, findings);
    }
    const dedupedFindings = [];
    const seen = new Set();
    for (const finding of findings) {
        const key = `${finding.category}:${finding.id}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        dedupedFindings.push(finding);
    }
    return {
        generatedAt: new Date().toISOString(),
        mode: 'semantic',
        baselinePolicyPath,
        candidatePolicyPath,
        target,
        findings: dedupedFindings,
        summary: {
            total: dedupedFindings.length,
            high: dedupedFindings.filter((finding) => finding.severity === 'high').length,
            medium: dedupedFindings.filter((finding) => finding.severity === 'medium').length,
            low: dedupedFindings.filter((finding) => finding.severity === 'low').length,
            info: dedupedFindings.filter((finding) => finding.severity === 'info').length,
            regressions: dedupedFindings.filter((finding) => finding.severity === 'high' || finding.severity === 'medium').length,
            improvements: dedupedFindings.filter((finding) => finding.severity === 'low' || finding.severity === 'info').length,
        },
    };
}
function printPolicyDiffReport(mode, jsonOutput) {
    if (jsonOutput) {
        console.log(JSON.stringify(mode, null, 2));
        return mode.summary.regressions > 0 ? 1 : 0;
    }
    console.log(`Semantic policy diff: ${mode.baselinePolicyPath} -> ${mode.candidatePolicyPath} (target=${mode.target})`);
    if (mode.findings.length === 0) {
        console.log('[OK] No semantic posture regressions detected.');
        return 0;
    }
    console.log(`Summary: regressions=${mode.summary.regressions}, improvements=${mode.summary.improvements}, total=${mode.summary.total}`);
    for (const finding of mode.findings) {
        console.log(`[${finding.severity.toUpperCase()}] ${finding.id} (${finding.category})`);
        console.log(`  summary: ${finding.summary}`);
        console.log(`  before: ${finding.before}`);
        console.log(`  after: ${finding.after}`);
        console.log(`  impact: ${finding.impact}`);
    }
    return mode.summary.regressions > 0 ? 1 : 0;
}
const CAPABILITY_TARGETS = [
    { key: 'cloudfront_functions', label: 'AWS CloudFront Functions' },
    { key: 'lambda_edge', label: 'AWS Lambda@Edge' },
    { key: 'cloudflare_workers', label: 'Cloudflare Workers' },
    { key: 'terraform_waf', label: 'Terraform-backed WAF' },
];
const CAPABILITY_STATUSES = ['supported', 'partial', 'unsupported', 'warning-only'];
const PLAYGROUND_PLACEHOLDER_TOKEN = 'INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN';
function normalizeFixtureHeader(raw) {
    const headers = {};
    if (!raw)
        return headers;
    for (const [key, value] of Object.entries(raw)) {
        if (value === undefined || value === null)
            continue;
        if (typeof value === 'object')
            continue;
        headers[key] = String(value);
    }
    return headers;
}
function normalizeFixtureQuery(raw) {
    if (raw == null)
        return '';
    if (typeof raw === 'string')
        return raw;
    if (typeof raw !== 'object' || Array.isArray(raw))
        return '';
    const pairs = [];
    for (const [key, value] of Object.entries(raw)) {
        if (value === null || value === undefined)
            continue;
        if (typeof value === 'object') {
            const obj = value;
            if (obj.value !== undefined && obj.value !== null) {
                pairs.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(obj.value))}`);
            }
            if (Array.isArray(obj.multiValue)) {
                for (const item of obj.multiValue) {
                    if (item && item.value !== undefined && item.value !== null) {
                        pairs.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(item.value))}`);
                    }
                }
            }
            continue;
        }
        if (Array.isArray(value)) {
            for (const item of value) {
                if (item === undefined || item === null)
                    continue;
                pairs.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(item))}`);
            }
            continue;
        }
        pairs.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
    }
    return pairs.join('&');
}
function buildDefaultPlaygroundFixtures() {
    return [
        {
            name: 'GET / with explicit user-agent',
            request: {
                method: 'GET',
                path: '/',
                query: '',
                headers: {
                    'user-agent': 'cdn-security-framework-playground',
                    accept: 'text/plain',
                },
                body: null,
            },
        },
        {
            name: 'PATCH / is blocked by method rule',
            request: {
                method: 'PATCH',
                path: '/',
                query: '',
                headers: {
                    'user-agent': 'cdn-security-framework-playground',
                },
                body: null,
            },
        },
        {
            name: 'Path traversal is blocked',
            request: {
                method: 'GET',
                path: '/foo/../bar',
                query: '',
                headers: {
                    'user-agent': 'cdn-security-framework-playground',
                },
                body: null,
            },
        },
        {
            name: 'Query string strip example',
            request: {
                method: 'GET',
                path: '/search',
                query: 'utm_source=google&q=abc',
                headers: {
                    'user-agent': 'cdn-security-framework-playground',
                },
                body: null,
            },
        },
        {
            name: 'Auth missing on admin route',
            request: {
                method: 'GET',
                path: '/admin',
                query: '',
                headers: {
                    'user-agent': 'cdn-security-framework-playground',
                },
                body: null,
            },
        },
        {
            name: 'Auth with placeholder token on admin route',
            request: {
                method: 'GET',
                path: '/admin',
                query: '',
                headers: {
                    'user-agent': 'cdn-security-framework-playground',
                    'x-edge-token': PLAYGROUND_PLACEHOLDER_TOKEN,
                },
                body: null,
            },
        },
    ];
}
function loadPlaygroundFixtures(fixturePath) {
    if (!fixturePath) {
        return buildDefaultPlaygroundFixtures();
    }
    const raw = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
    let list = [];
    if (Array.isArray(raw)) {
        list = raw;
    }
    else if (raw && Array.isArray(raw.fixtures)) {
        list = raw.fixtures;
    }
    else if (raw && raw.request) {
        list = [raw];
    }
    else {
        throw new Error('Invalid fixture format. Use array, {fixtures: [...]}, or {request: {...}}.');
    }
    return list.map((entry, index) => {
        const payload = (entry && entry.request && typeof entry.request === 'object') ? entry.request : entry;
        if (!payload || typeof payload !== 'object') {
            throw new Error(`Fixture entry #${index + 1} is invalid.`);
        }
        const req = payload;
        return {
            name: String(entry.name || `request-${index + 1}`),
            request: {
                method: String(req.method || 'GET').toUpperCase(),
                path: String(req.path || req.uri || '/'),
                query: normalizeFixtureQuery(req.query),
                headers: normalizeFixtureHeader(req.headers),
                body: req.body,
                raw: req.body,
            },
        };
    });
}
function buildAwsEvent(fixture) {
    const headers = {};
    for (const [name, value] of Object.entries(fixture.headers)) {
        headers[name.toLowerCase()] = { value: String(value) };
    }
    return {
        request: {
            method: fixture.method,
            uri: fixture.path,
            headers,
            querystring: fixture.query,
        },
    };
}
function buildCloudflareRequest(fixture) {
    const basePath = fixture.path || '/';
    const [pathOnly, rawQuery] = basePath.split('?');
    const normalizedQuery = fixture.query || (rawQuery || '');
    const queryString = normalizedQuery ? (normalizedQuery.startsWith('?') ? normalizedQuery.slice(1) : normalizedQuery) : '';
    const url = new URL(pathOnly + (queryString ? `?${queryString}` : ''), 'https://edge.example.com');
    const headers = new Headers();
    for (const [name, value] of Object.entries(fixture.headers)) {
        headers.set(name, value);
    }
    const body = (fixture.body === undefined || fixture.body === null)
        ? undefined
        : typeof fixture.body === 'string' ? fixture.body : JSON.stringify(fixture.body);
    return new Request(url.toString(), {
        method: fixture.method,
        headers,
        body: ['GET', 'HEAD'].includes(fixture.method) ? undefined : body,
    });
}
function runAwsPlayground(outDir, fixtures) {
    const viewerRequestPath = path.join(outDir, 'edge', 'viewer-request.js');
    const code = fs.readFileSync(viewerRequestPath, 'utf8');
    const handler = Function(`${code}\nreturn handler;`)();
    if (typeof handler !== 'function') {
        throw new Error('AWS compiled artifact is malformed: handler missing.');
    }
    const result = { target: 'aws', fixtures: [] };
    for (const fixture of fixtures) {
        const response = handler(buildAwsEvent(fixture.request));
        const status = response && response.statusCode != null ? Number(response.statusCode) : 200;
        const blocked = isBlockedStatus(response && response.statusCode);
        result.fixtures.push({
            name: fixture.name,
            decision: blocked ? 'block' : 'pass',
            status,
            block_reason: blocked ? String(response.body || 'blocked') : '',
            path: fixture.request.path,
            method: fixture.request.method,
            query: fixture.request.query,
        });
    }
    return result;
}
async function runCloudflarePlayground(outDir, fixtures) {
    const esbuild = require('esbuild');
    const workerSourcePath = path.join(outDir, 'edge', 'cloudflare', 'index.ts');
    const generated = fs.readFileSync(workerSourcePath, 'utf8');
    const compiled = esbuild.transformSync(generated, {
        loader: 'ts',
        format: 'cjs',
        target: 'es2022',
    }).code;
    const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cdn-security-playground-cf-'));
    const modPath = path.join(tmpDir, 'worker.cjs');
    const env = {
        EDGE_ADMIN_TOKEN: PLAYGROUND_PLACEHOLDER_TOKEN,
        BASIC_AUTH_CREDS: 'basic:cred',
        URL_SIGNING_SECRET: 'url-signing-secret',
        JWT_SECRET: 'jwt-secret',
        ORIGIN_SECRET: 'origin-secret',
        CHALLENGE_SECRET: 'challenge-secret',
    };
    const previousFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response('origin-ok', { status: 200, headers: {} });
    const result = { target: 'cloudflare', fixtures: [] };
    try {
        fs.writeFileSync(modPath, compiled, 'utf8');
        delete require.cache[modPath];
        const mod = require(modPath);
        const fetchHandler = mod && mod.default && typeof mod.default.fetch === 'function'
            ? mod.default.fetch
            : null;
        if (typeof fetchHandler !== 'function') {
            throw new Error('Cloudflare compiled artifact is malformed: default.fetch missing.');
        }
        for (const fixture of fixtures) {
            const request = buildCloudflareRequest(fixture.request);
            const response = await fetchHandler(request, env, {});
            const status = Number(response.status) || 0;
            const blocked = isBlockedStatus(status);
            const body = blocked ? await response.text() : '';
            result.fixtures.push({
                name: fixture.name,
                decision: blocked ? 'block' : 'pass',
                status,
                block_reason: blocked ? body : '',
                path: fixture.request.path,
                method: fixture.request.method,
                query: fixture.request.query,
            });
        }
        return result;
    }
    finally {
        globalThis.fetch = previousFetch;
        if (fs.existsSync(tmpDir))
            fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}
async function runPlayground(opts) {
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    const fixtures = loadPlaygroundFixtures(opts.fixture ? path.isAbsolute(opts.fixture)
        ? opts.fixture
        : path.join(cwd, opts.fixture) : null);
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cdn-security-playground-'));
    const allowPlaceholderToken = opts.allowPlaceholderToken !== false;
    const target = opts.target || 'all';
    const { compile } = require(path.join(pkgRoot, 'lib'));
    const results = [];
    const isAws = target === 'aws' || target === 'all';
    const isCloudflare = target === 'cloudflare' || target === 'all';
    try {
        if (isAws) {
            const outDir = path.join(tmpRoot, 'aws');
            const compileResult = compile({
                policyPath,
                outDir,
                target: 'aws',
                allowPlaceholderToken,
                cwd,
                pkgRoot,
            });
            if (!compileResult.ok) {
                throw new Error(`playground: aws compile failed: ${compileResult.errors.join(' | ')}`);
            }
            results.push(runAwsPlayground(outDir, fixtures));
        }
        if (isCloudflare) {
            const outDir = path.join(tmpRoot, 'cloudflare');
            const compileResult = compile({
                policyPath,
                outDir,
                target: 'cloudflare',
                allowPlaceholderToken,
                cwd,
                pkgRoot,
            });
            if (!compileResult.ok) {
                throw new Error(`playground: cloudflare compile failed: ${compileResult.errors.join(' | ')}`);
            }
            results.push(await runCloudflarePlayground(outDir, fixtures));
        }
        return { policyPath, targets: results };
    }
    finally {
        if (fs.existsSync(tmpRoot))
            fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
}
function asString(value) {
    if (typeof value === 'string') {
        const trimmed = value.trim();
        return trimmed.length > 0 ? trimmed : null;
    }
    return null;
}
function asNumber(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
    }
    if (typeof value === 'string') {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
    }
    return null;
}
function normalizePolicyRoute(value) {
    if (!value) {
        return 'unknown';
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return 'unknown';
    }
    return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}
function normalizeEvent(value) {
    const raw = asString(value);
    if (!raw) {
        return 'other';
    }
    const lower = raw.toLowerCase();
    if (lower === 'allow' || lower === 'pass' || lower === 'passed') {
        return 'pass';
    }
    if (lower === 'block' || lower === 'blocked') {
        return 'block';
    }
    if (lower === 'monitor' || lower === 'monitoring' || lower === 'logged') {
        return 'monitor';
    }
    return lower;
}
function parseAnalyzeRecord(row) {
    if (!row || typeof row !== 'object') {
        return null;
    }
    const record = row;
    const method = asString(record.method)
        || asString(record.httpRequest?.method)
        || asString(record.request?.method)
        || 'UNKNOWN';
    const rawEvent = asString(record.event) !== null
        ? record.event
        : asString(record.eventName) !== null
            ? record.eventName
            : record.outcome;
    const event = normalizeEvent(rawEvent);
    const blockReason = asString(record.block_reason)
        || asString(record.blockReason)
        || asString(record.reason)
        || 'unclassified';
    const uri = normalizePolicyRoute(asString(record.uri)
        || asString(record.path)
        || asString(record.request?.uri)
        || asString(record.request?.path)
        || asString(record.httpRequest?.uri)
        || asString(record.httpRequest?.path));
    const policyRoute = normalizePolicyRoute(asString(record.policy_route)
        || asString(record.policyRoute)
        || asString(record.route)
        || asString(record.request?.route)
        || uri);
    const target = asString(record.target)
        || asString(record.platform)
        || asString(record.provider)
        || asString(record.runtime)
        || 'unknown';
    const status = asNumber(record.status) || asNumber(record.statusCode) || 0;
    if (status < 0 || status > 999999) {
        return null;
    }
    return {
        target,
        policyRoute,
        method,
        uri,
        status,
        event: event === 'other' && isBlockedStatus(status) ? 'block' : event,
        blockReason,
    };
}
function buildEmptyAnalyzeReport(input, minCount, top) {
    return {
        summary: {
            input,
            totalLines: 0,
            parsedLines: 0,
            unparseableLines: 0,
            analyzedEvents: 0,
            blockEvents: 0,
            monitorEvents: 0,
            lowFrequencyThreshold: minCount,
            top,
        },
        byBlockReason: {},
        byPolicyRoute: {},
        candidates: [],
    };
}
function incrementCounter(map, key) {
    map[key] = (map[key] || 0) + 1;
}
function parseAnalyzeLine(line) {
    if (!line.trim()) {
        return null;
    }
    let row;
    try {
        row = JSON.parse(line);
    }
    catch (_e) {
        return null;
    }
    if (!row || typeof row !== 'object') {
        return null;
    }
    const nested = row.message;
    if (asString(nested) && typeof nested === 'string') {
        try {
            const parsed = JSON.parse(nested);
            return parseAnalyzeRecord(parsed);
        }
        catch (_e) {
            // fall through
        }
    }
    return parseAnalyzeRecord(row);
}
function runAnalyze(opts) {
    const cwd = process.cwd();
    const inputPath = opts.input
        ? path.isAbsolute(opts.input) ? opts.input : path.join(cwd, opts.input)
        : '';
    if (!inputPath) {
        throw new Error('analyze: --input is required');
    }
    if (!fs.existsSync(inputPath)) {
        throw new Error(`analyze: input file not found: ${inputPath}`);
    }
    const minCount = Number(opts.minCount);
    const top = Number(opts.top);
    if (!Number.isFinite(minCount) || minCount < 1) {
        throw new Error('analyze: --min-count must be a positive integer');
    }
    if (!Number.isFinite(top) || top < 1) {
        throw new Error('analyze: --top must be a positive integer');
    }
    const report = buildEmptyAnalyzeReport(inputPath, Math.floor(minCount), Math.floor(top));
    const text = fs.readFileSync(inputPath, 'utf8');
    const lines = text.split(/\r?\n/);
    const candidateMap = {};
    for (const rawLine of lines) {
        if (!rawLine.trim()) {
            continue;
        }
        report.summary.totalLines += 1;
        const event = parseAnalyzeLine(rawLine);
        if (!event) {
            report.summary.unparseableLines += 1;
            continue;
        }
        report.summary.parsedLines += 1;
        report.summary.analyzedEvents += 1;
        const byReason = report.byBlockReason[event.blockReason] || {
            count: 0,
            targets: {},
            policyRoutes: {},
        };
        incrementCounter(byReason.targets, event.target);
        incrementCounter(byReason.policyRoutes, event.policyRoute);
        byReason.count += 1;
        report.byBlockReason[event.blockReason] = byReason;
        const byRoute = report.byPolicyRoute[event.policyRoute] || {
            count: 0,
            blockReasons: {},
            targets: {},
        };
        byRoute.count += 1;
        incrementCounter(byRoute.blockReasons, event.blockReason);
        incrementCounter(byRoute.targets, event.target);
        report.byPolicyRoute[event.policyRoute] = byRoute;
        const evt = event.event || 'other';
        if (evt === 'block') {
            report.summary.blockEvents += 1;
            const key = `${event.blockReason}|${event.policyRoute}`;
            const bucket = candidateMap[key] || {
                policyRoute: event.policyRoute,
                blockReason: event.blockReason,
                count: 0,
                targets: {},
                events: [],
            };
            bucket.count += 1;
            bucket.targets[event.target] = true;
            if (bucket.events.length < report.summary.top) {
                bucket.events.push({
                    method: event.method,
                    status: event.status,
                    uri: event.uri,
                    target: event.target,
                });
            }
            candidateMap[key] = bucket;
        }
        if (evt === 'monitor') {
            report.summary.monitorEvents += 1;
        }
    }
    const candidateKeys = Object.keys(candidateMap);
    report.candidates = candidateKeys
        .map((key) => {
        const bucket = candidateMap[key];
        return {
            policyRoute: bucket.policyRoute,
            blockReason: bucket.blockReason,
            count: bucket.count,
            targets: Object.keys(bucket.targets),
            events: bucket.events
                .slice(0, report.summary.top)
                .map((event) => ({
                method: event.method,
                status: event.status,
                uri: event.uri,
                target: event.target,
            })),
        };
    })
        .filter((entry) => entry.count <= report.summary.lowFrequencyThreshold)
        .sort((a, b) => a.count - b.count || a.policyRoute.localeCompare(b.policyRoute))
        .slice(0, report.summary.top);
    return report;
}
function printAnalyzeReport(report) {
    console.log(`[analyze] input=${report.summary.input}`);
    console.log(`[analyze] total_lines=${report.summary.totalLines} parsed_lines=${report.summary.parsedLines} unparseable=${report.summary.unparseableLines}`);
    console.log(`[analyze] analyzed_events=${report.summary.analyzedEvents} block=${report.summary.blockEvents} monitor=${report.summary.monitorEvents}`);
    console.log('');
    const reasonEntries = Object.entries(report.byBlockReason)
        .map(([reason, value]) => ({ reason, count: value.count, routes: Object.entries(value.policyRoutes).length }))
        .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason));
    const routeEntries = Object.entries(report.byPolicyRoute)
        .map(([policyRoute, value]) => ({ policyRoute, count: value.count, reasons: Object.entries(value.blockReasons).length }))
        .sort((a, b) => b.count - a.count || a.policyRoute.localeCompare(b.policyRoute));
    console.log('[analyze] Block reasons:');
    for (const item of reasonEntries) {
        console.log(`- ${item.reason}: ${item.count} events across ${item.routes} policy route(s)`);
    }
    if (reasonEntries.length === 0) {
        console.log('- none');
    }
    console.log('');
    console.log('[analyze] Top policy routes:');
    for (const item of routeEntries.slice(0, 20)) {
        console.log(`- ${item.policyRoute}: ${item.count} events (${item.reasons} block reason(s))`);
    }
    if (routeEntries.length === 0) {
        console.log('- none');
    }
    console.log('');
    if (report.candidates.length > 0) {
        console.log('[analyze] Low-frequency candidates:');
        for (const candidate of report.candidates) {
            console.log(`- route=${candidate.policyRoute} reason=${candidate.blockReason} count=${candidate.count} targets=${candidate.targets.join(',')}`);
            for (const evt of candidate.events) {
                console.log(`  sample: ${evt.method} ${evt.uri} status=${evt.status} target=${evt.target}`);
            }
        }
    }
    else {
        console.log('[analyze] Low-frequency candidates: none');
    }
}
function routeAuthConfigured(policy, types) {
    const routes = Array.isArray(policy && policy.routes) ? policy.routes : [];
    return routes.some((route) => types.includes(route && route.auth_gate && route.auth_gate.type));
}
function firewallChallengeEnabled(policy) {
    return Boolean(policy && policy.firewall && policy.firewall.challenge && policy.firewall.challenge.enabled === true);
}
function hasPolicyPath(policy, dottedPath) {
    const parts = dottedPath.split('.');
    let current = policy;
    for (const part of parts) {
        if (!current || typeof current !== 'object' || !Object.prototype.hasOwnProperty.call(current, part)) {
            return false;
        }
        current = current[part];
    }
    return current !== undefined && current !== null;
}
function anyPolicyPath(policy, dottedPaths) {
    return dottedPaths.some((p) => hasPolicyPath(policy, p));
}
const CAPABILITY_MATRIX = [
    {
        id: 'request.allow_methods',
        category: 'Request hygiene',
        label: 'HTTP method allowlist',
        policyPaths: ['request.allow_methods'],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Viewer-request and Worker runtimes reject methods outside request.allow_methods.',
    },
    {
        id: 'request.uri_query_limits',
        category: 'Request hygiene',
        label: 'URI and query limits',
        policyPaths: [
            'request.limits.max_uri_length',
            'request.limits.max_query_length',
            'request.limits.max_query_params',
        ],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'URI length, query length, and query parameter count are enforced before origin fetch.',
    },
    {
        id: 'request.header_limits',
        category: 'Request hygiene',
        label: 'Header size and count limits',
        policyPaths: ['request.limits.max_header_size', 'request.limits.max_header_count'],
        support: {
            cloudfront_functions: 'partial',
            lambda_edge: 'partial',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'partial', cloudflare: 'supported' },
        notes: 'Header count is available at viewer-request; full header byte inspection depends on body/header-readable runtimes.',
    },
    {
        id: 'request.path_normalization',
        category: 'Request hygiene',
        label: 'Path and query normalization',
        policyPaths: [
            'request.normalize.path',
            'request.normalize.drop_query_keys',
        ],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Dot-segment and slash normalization plus tracking-query stripping run at request entry.',
    },
    {
        id: 'request.required_headers',
        category: 'Request hygiene',
        label: 'Required headers and scanner UA blocklist',
        policyPaths: ['request.block.header_missing', 'request.block.ua_contains'],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'General required-header checks and User-Agent substring blocking are request-entry controls.',
    },
    {
        id: 'request.graphql_guard',
        category: 'Request hygiene',
        label: 'GraphQL body depth and complexity guard',
        policyPaths: ['request.graphql_guard'],
        support: {
            cloudfront_functions: 'warning-only',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'warning-only', cloudflare: 'supported' },
        notes: 'Cloudflare Workers can inspect bounded request bodies; AWS edge output warns and does not enforce this guard.',
    },
    {
        id: 'response.security_headers',
        category: 'Response security',
        label: 'Security headers and CSP',
        policyPaths: [
            'response_headers.hsts',
            'response_headers.x_content_type_options',
            'response_headers.referrer_policy',
            'response_headers.permissions_policy',
            'response_headers.csp_public',
            'response_headers.csp_admin',
            'response_headers.csp_report_only',
        ],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Viewer-response and Worker output inject browser security headers from response_headers.',
    },
    {
        id: 'response.cors',
        category: 'Response security',
        label: 'CORS response headers and preflight',
        policyPaths: ['response_headers.cors'],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Dynamic allowlist echo is supported and appends Vary: Origin.',
    },
    {
        id: 'response.cookie_attributes',
        category: 'Response security',
        label: 'Cookie attribute hardening',
        policyPaths: ['response_headers.cookie_attributes'],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Set-Cookie attributes can be hardened on response-capable targets.',
    },
    {
        id: 'response.response_dlp',
        category: 'Response security',
        label: 'Response DLP masking/blocking',
        policyPaths: ['response_dlp'],
        support: {
            cloudfront_functions: 'warning-only',
            lambda_edge: 'partial',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'warning-only', cloudflare: 'supported' },
        notes: 'Cloudflare Workers enforce header/body DLP; AWS output emits an unsupported warning because generated CFF cannot inspect response bodies.',
        configured: (policy) => Boolean(policy && policy.response_dlp && policy.response_dlp.enabled === true),
    },
    {
        id: 'auth.static_basic',
        category: 'Authentication',
        label: 'Static token and Basic auth gates',
        policyPaths: ['routes[].auth_gate.type=static_token|basic_auth'],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Header token and Basic credentials are enforced before origin fetch.',
        configured: (policy) => routeAuthConfigured(policy, ['static_token', 'basic_auth']),
    },
    {
        id: 'auth.jwt',
        category: 'Authentication',
        label: 'JWT validation',
        policyPaths: ['routes[].auth_gate.type=jwt'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'supported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'HS256/RS256 JWT gates run in Lambda@Edge for AWS and in Workers for Cloudflare.',
        configured: (policy) => routeAuthConfigured(policy, ['jwt']),
    },
    {
        id: 'auth.signed_url',
        category: 'Authentication',
        label: 'Signed URL validation',
        policyPaths: ['routes[].auth_gate.type=signed_url'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'supported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Signed URL gates run where HMAC verification and origin request mutation are available.',
        configured: (policy) => routeAuthConfigured(policy, ['signed_url']),
    },
    {
        id: 'origin.auth',
        category: 'Origin security',
        label: 'Origin authentication',
        policyPaths: ['origin.auth'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'supported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Custom-header and HMAC origin auth are injected before origin fetch.',
    },
    {
        id: 'origin.timeout',
        category: 'Origin security',
        label: 'Origin timeout settings',
        policyPaths: ['origin.timeout'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'unsupported',
            terraform_waf: 'supported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'unsupported' },
        notes: 'CloudFront origin timeout config is emitted as Terraform-backed infrastructure.',
    },
    {
        id: 'transport.tls_http',
        category: 'Transport',
        label: 'TLS and HTTP version policy',
        policyPaths: ['transport.tls', 'transport.http'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'unsupported',
            terraform_waf: 'supported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'unsupported' },
        notes: 'CloudFront viewer protocol and security policy settings are emitted as Terraform-backed infrastructure.',
    },
    {
        id: 'waf.rate_limit',
        category: 'Firewall / WAF',
        label: 'WAF rate limiting',
        policyPaths: ['firewall.waf.rate_limit', 'firewall.waf.rate_limit_rules'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'unsupported',
            terraform_waf: 'supported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Rate limits are emitted as AWS WAFv2 or Cloudflare WAF Terraform resources.',
    },
    {
        id: 'waf.managed_rules',
        category: 'Firewall / WAF',
        label: 'WAF managed rules',
        policyPaths: ['firewall.waf.managed_rules'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'unsupported',
            terraform_waf: 'partial',
        },
        deploySupport: { aws: 'supported', cloudflare: 'partial' },
        notes: 'AWS managed rules are direct. Cloudflare mappings may be equivalent, approximate, or unsupported depending on the rule.',
    },
    {
        id: 'waf.geo_ip',
        category: 'Firewall / WAF',
        label: 'Geo and IP allow/block lists',
        policyPaths: ['firewall.geo', 'firewall.ip'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'unsupported',
            terraform_waf: 'supported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Geo and IP controls are infrastructure/WAF controls rather than edge JavaScript controls.',
    },
    {
        id: 'waf.fingerprints',
        category: 'Firewall / WAF',
        label: 'JA3/JA4 TLS fingerprint rules',
        policyPaths: ['firewall.waf.ja3_fingerprints', 'firewall.waf.ja4_fingerprints'],
        support: {
            cloudfront_functions: 'unsupported',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'unsupported',
            terraform_waf: 'supported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Fingerprint rules are emitted into the target WAF/IaC layer.',
    },
    {
        id: 'firewall.challenge',
        category: 'Firewall / WAF',
        label: 'Edge JS challenge / lightweight PoW',
        policyPaths: ['firewall.challenge'],
        support: {
            cloudfront_functions: 'warning-only',
            lambda_edge: 'unsupported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'warning-only', cloudflare: 'supported' },
        notes: 'Challenge enforcement is Cloudflare Workers-only; AWS builds warn when configured.',
        configured: firewallChallengeEnabled,
    },
    {
        id: 'defaults.monitor_mode',
        category: 'Operations',
        label: 'Monitor/report-only mode',
        policyPaths: ['defaults.mode'],
        support: {
            cloudfront_functions: 'supported',
            lambda_edge: 'supported',
            cloudflare_workers: 'supported',
            terraform_waf: 'unsupported',
        },
        deploySupport: { aws: 'supported', cloudflare: 'supported' },
        notes: 'Edge runtimes log would-block events while forwarding where the control can safely monitor.',
        configured: (policy) => Boolean(policy && policy.defaults && policy.defaults.mode === 'monitor'),
    },
];
function serializeCapability(entry) {
    return {
        id: entry.id,
        category: entry.category,
        label: entry.label,
        policyPaths: entry.policyPaths,
        support: entry.support,
        deploySupport: entry.deploySupport,
        notes: entry.notes,
    };
}
function normalizeCapabilityTarget(raw) {
    if (raw === 'aws' || raw === 'cloudflare' || raw === 'all')
        return raw;
    throw new Error('Invalid --target. Use aws, cloudflare, or all.');
}
function normalizeVisualFormat(raw) {
    if (raw === 'mermaid' || raw === 'html')
        return raw;
    throw new Error('Invalid --format. Use mermaid or html.');
}
function capabilityFinding(entry, target, status) {
    const severity = status === 'unsupported' ? 'fail' : 'warn';
    const recommendations = {
        supported: 'No action required.',
        partial: 'Review the matrix notes and target documentation before relying on full enforcement.',
        unsupported: 'Remove this policy setting for the selected target or enforce it in another layer.',
        'warning-only': 'Treat the compiler/readiness warning as non-enforcement and use a supported target or origin-side control.',
    };
    return {
        severity,
        id: `capability.${target}.${entry.id}.${status}`,
        capabilityId: entry.id,
        target,
        status,
        detail: `${entry.label} is ${status} for target ${target}.`,
        recommendation: recommendations[status],
    };
}
function evaluatePolicyCapabilities(policy, policyPath, target) {
    const configured = CAPABILITY_MATRIX.filter((entry) => {
        if (entry.configured)
            return entry.configured(policy);
        return anyPolicyPath(policy, entry.policyPaths);
    });
    const deployTargets = target === 'all' ? ['aws', 'cloudflare'] : [target];
    const findings = [];
    const controls = configured.map((entry) => {
        const targetSupport = {};
        for (const deployTarget of deployTargets) {
            const status = entry.deploySupport[deployTarget];
            targetSupport[deployTarget] = status;
            if (status !== 'supported')
                findings.push(capabilityFinding(entry, deployTarget, status));
        }
        return Object.assign(serializeCapability(entry), { targetSupport });
    });
    return {
        policyPath,
        target,
        configuredControls: controls,
        findings,
        summary: {
            configured: controls.length,
            fail: findings.filter((f) => f.severity === 'fail').length,
            warn: findings.filter((f) => f.severity === 'warn').length,
        },
    };
}
function buildCapabilitiesReport(opts) {
    const report = {
        generatedAt: new Date().toISOString(),
        target: opts.target,
        statuses: CAPABILITY_STATUSES,
        targets: CAPABILITY_TARGETS,
        capabilities: CAPABILITY_MATRIX.map(serializeCapability),
    };
    if (opts.policyPath) {
        const policy = loadPolicyDocument(opts.policyPath);
        report.policyEvaluation = evaluatePolicyCapabilities(policy, opts.policyPath, opts.target);
    }
    return report;
}
function printCapabilitiesReport(report) {
    console.log(`Target Capabilities Matrix (target=${report.target})`);
    console.log(`Statuses: ${CAPABILITY_STATUSES.join(', ')}`);
    const categories = Array.from(new Set(report.capabilities.map((entry) => entry.category)));
    for (const category of categories) {
        console.log('');
        console.log(String(category));
        for (const entry of report.capabilities.filter((cap) => cap.category === category)) {
            const support = CAPABILITY_TARGETS
                .map((target) => `${target.label}: ${entry.support[target.key]}`)
                .join('; ');
            console.log(`- ${entry.id}: ${entry.label}`);
            console.log(`  ${support}`);
            console.log(`  Policy: ${entry.policyPaths.join(', ') || '(none)'}`);
            console.log(`  Notes: ${entry.notes}`);
        }
    }
    if (!report.policyEvaluation)
        return;
    const evaluation = report.policyEvaluation;
    console.log('');
    console.log(`Policy evaluation: ${evaluation.policyPath}`);
    console.log(`Configured controls: ${evaluation.summary.configured}`);
    if (evaluation.findings.length === 0) {
        console.log('Findings: none');
        return;
    }
    console.log(`Findings: ${evaluation.summary.fail} fail, ${evaluation.summary.warn} warn`);
    for (const finding of evaluation.findings) {
        console.log(`- [${finding.severity}] ${finding.id}: ${finding.detail}`);
        console.log(`  Recommendation: ${finding.recommendation}`);
    }
}
function readinessFinding(severity, id, detail, recommendation) {
    return { severity, id, detail, recommendation };
}
const WAF_RECOMMENDATION_TEMPLATES = {
    'spa-static-site': {
        id: 'waf.recommendation.spa_static_site',
        appShape: 'spa-static-site',
        title: 'SPA/static site managed-rule baseline',
        rules: [
            'AWSManagedRulesCommonRuleSet',
            'AWSManagedRulesKnownBadInputsRuleSet',
            'AWSManagedRulesIPReputationList',
        ],
        settings: [
            'Keep request.allow_methods to GET/HEAD for static assets.',
            'Use a global WAF rate limit around 2000 requests per 5 minutes per IP, then tune from logs.',
            'Enable WAF logging when scope=CLOUDFRONT before production release.',
        ],
        rationale: 'Static sites mostly need traversal, scanner, XSS/cache-poisoning, and known-bad source coverage without heavy auth-specific managed rules.',
        cost: 'Standard AWS WAF request/WCU costs; no BotControl or ATP paid add-on in this baseline.',
        falsePositiveRisk: 'Low to medium. KnownBadInputs/OWASP-style rules can catch unusual asset paths, so monitor before enforcing on legacy static content.',
    },
    'rest-api': {
        id: 'waf.recommendation.rest_api',
        appShape: 'rest-api',
        title: 'REST API managed-rule baseline',
        rules: [
            'AWSManagedRulesCommonRuleSet',
            'AWSManagedRulesKnownBadInputsRuleSet',
            'AWSManagedRulesSQLiRuleSet',
            'AWSManagedRulesIPReputationList',
        ],
        settings: [
            'Add scoped rate_limit_rules for auth, write-heavy, or expensive API paths.',
            'Keep CORS origins explicit; do not rely on WAF rules to compensate for wildcard credentials.',
            'Enable WAF logging for CloudFront-scoped APIs before production release.',
        ],
        rationale: 'JSON APIs need injection and scanner coverage plus SQLi signatures and reputation filtering, especially on write/query endpoints.',
        cost: 'Standard AWS WAF request/WCU costs; SQLi adds WCU pressure but avoids BotControl/ATP paid add-ons.',
        falsePositiveRisk: 'Medium. SQLi signatures can flag unusual query DSLs or search syntax; start in count/monitor mode for affected routes.',
    },
    'admin-panel': {
        id: 'waf.recommendation.admin_panel',
        appShape: 'admin-panel',
        title: 'Admin panel managed-rule baseline',
        rules: [
            'AWSManagedRulesCommonRuleSet',
            'AWSManagedRulesKnownBadInputsRuleSet',
            'AWSManagedRulesIPReputationList',
            'AWSManagedRulesAnonymousIpList',
            'AWSManagedRulesBotControlRuleSet',
            'AWSManagedRulesATPRuleSet',
        ],
        settings: [
            'Use a low global WAF rate limit and a stricter scoped login/admin rate_limit_rule.',
            'Require WAF logging and redaction for authorization, cookie, and x-api-key fields.',
            'Combine managed rules with route auth, IP allowlists, VPN, or SSO where possible.',
        ],
        rationale: 'Admin panels are high-value targets for credential stuffing, bot traffic, anonymizers, and exploit probes, so stronger managed signals are justified.',
        cost: 'Higher. BotControl and ATP are paid AWS managed protections and add operational tuning cost.',
        falsePositiveRisk: 'Medium to high. Bot and ATP controls can challenge or block automation; allowlist known internal tooling before enforce mode.',
    },
    'microservice-origin': {
        id: 'waf.recommendation.microservice_origin',
        appShape: 'microservice-origin',
        title: 'Microservice origin managed-rule baseline',
        rules: [
            'AWSManagedRulesCommonRuleSet',
            'AWSManagedRulesKnownBadInputsRuleSet',
            'AWSManagedRulesIPReputationList',
        ],
        settings: [
            'Prefer signed origin authentication or an IP allowlist so direct-origin bypasses fail closed.',
            'Add scoped rate_limit_rules for expensive service endpoints instead of only a global limit.',
            'Enable WAF logging for CloudFront-scoped origins and correlate logs with origin auth failures.',
        ],
        rationale: 'Service origins need exploit-probe and reputation coverage, but broad bot or ATP controls may interfere with legitimate service clients.',
        cost: 'Standard AWS WAF request/WCU costs; avoids paid bot/account-takeover add-ons by default.',
        falsePositiveRisk: 'Low to medium. Reputation lists can block shared egress ranges used by partners; validate known service clients before enforce mode.',
    },
};
function includesAny(text, tokens) {
    return tokens.some((token) => text.includes(token));
}
function inferWafAppShape(policy) {
    const metadata = (policy && policy.metadata) || {};
    const text = [
        policy && policy.project,
        metadata.description,
        metadata.app_shape,
        metadata.appShape,
    ].filter(Boolean).join(' ').toLowerCase();
    if (includesAny(text, ['spa-static-site', 'spa / static', 'static site', 'single-page', 'spa'])) {
        return 'spa-static-site';
    }
    if (includesAny(text, ['rest-api', 'rest api', 'json api'])) {
        return 'rest-api';
    }
    if (includesAny(text, ['admin-panel', 'admin panel', 'back-office', 'ops dashboard'])) {
        return 'admin-panel';
    }
    if (includesAny(text, ['microservice-origin', 'microservice origin', 'service-to-service'])) {
        return 'microservice-origin';
    }
    const routes = Array.isArray(policy && policy.routes) ? policy.routes : [];
    const originAuth = policy && policy.origin && policy.origin.auth;
    if (originAuth)
        return 'microservice-origin';
    if (routes.some((route) => route && route.auth_gate && route.auth_gate.type === 'jwt')) {
        return 'rest-api';
    }
    if (routes.some((route) => {
        const gateType = route && route.auth_gate && route.auth_gate.type;
        const prefixes = route && route.match && Array.isArray(route.match.path_prefixes)
            ? route.match.path_prefixes
            : [];
        return (gateType === 'static_token' || gateType === 'basic_auth') &&
            prefixes.some((prefix) => typeof prefix === 'string' && (prefix === '/' || prefix.includes('admin')));
    })) {
        return 'admin-panel';
    }
    const methods = Array.isArray(policy && policy.request && policy.request.allow_methods)
        ? policy.request.allow_methods.map((m) => String(m).toUpperCase()).sort()
        : [];
    if (methods.length > 0 && methods.every((method) => method === 'GET' || method === 'HEAD')) {
        return 'spa-static-site';
    }
    if (methods.includes('OPTIONS') || (policy && policy.response_headers && policy.response_headers.cors)) {
        return 'rest-api';
    }
    return 'unknown';
}
function cloudflareSupportForRules(rules) {
    const { classifyManagedRule } = require(path.join(pkgRoot, 'scripts', 'lib', 'cloudflare-waf-parity.js'));
    const notes = [];
    let support = 'supported';
    for (const rule of rules) {
        const entry = classifyManagedRule(rule);
        if (entry.status === 'unsupported') {
            support = 'unsupported';
        }
        else if (entry.status === 'approximate' && support !== 'unsupported') {
            support = 'partial';
        }
        if (entry.status !== 'equivalent') {
            const target = entry.cloudflare && entry.cloudflare.rulesetName
                ? entry.cloudflare.rulesetName
                : 'no direct Cloudflare ruleset target';
            notes.push(`${rule}: ${entry.status} on Cloudflare (${target}).`);
        }
    }
    return { support, notes };
}
function buildWafRecommendation(template, policy) {
    const managed = policy && policy.firewall && policy.firewall.waf && Array.isArray(policy.firewall.waf.managed_rules)
        ? policy.firewall.waf.managed_rules
        : [];
    const configuredRules = template.rules.filter((rule) => managed.includes(rule));
    const missingRules = template.rules.filter((rule) => !managed.includes(rule));
    const cloudflare = cloudflareSupportForRules(template.rules);
    return Object.assign({}, template, {
        targetSupport: {
            aws: 'supported',
            cloudflare: cloudflare.support,
        },
        configuredRules,
        missingRules,
        alreadySatisfied: missingRules.length === 0,
        notes: cloudflare.notes,
    });
}
function buildWafRecommendations(policy, policyPath, target) {
    const inferredAppShape = inferWafAppShape(policy);
    const templates = inferredAppShape === 'unknown'
        ? Object.values(WAF_RECOMMENDATION_TEMPLATES)
        : [WAF_RECOMMENDATION_TEMPLATES[inferredAppShape]];
    const recommendations = templates.map((template) => buildWafRecommendation(template, policy));
    return {
        policyPath,
        target,
        inferredAppShape,
        readOnly: true,
        recommendations,
    };
}
function weakWafSeverity(options) {
    return options.failOnWeakWafBaseline ? 'fail' : 'warn';
}
function evaluateReadiness(policy, target, lintWarnings, options = {}) {
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
        findings.push(readinessFinding(weakWafSeverity(options), 'firewall.waf.missing', 'firewall.waf is not configured.', 'Add WAF rate limits and managed rules for production traffic.'));
    }
    else {
        if (!waf.rate_limit && !Array.isArray(waf.rate_limit_rules)) {
            findings.push(readinessFinding(weakWafSeverity(options), 'firewall.waf.rate_limit.missing', 'No global or scoped WAF rate limit is configured.', 'Set firewall.waf.rate_limit or firewall.waf.rate_limit_rules for production.'));
        }
        const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
        const hasCoreSignal = managed.some((r) => r === 'AWSManagedRulesBotControlRuleSet' ||
            r === 'AWSManagedRulesATPRuleSet' ||
            r === 'AWSManagedRulesIPReputationList' ||
            r === 'AWSManagedRulesAnonymousIpList');
        if (target === 'aws' && !hasCoreSignal) {
            findings.push(readinessFinding(weakWafSeverity(options), 'firewall.waf.managed_rules.core_signal_missing', 'Managed WAF rules omit BotControl, ATP, IPReputation, and AnonymousIp.', 'Consider at least AWSManagedRulesIPReputationList and AWSManagedRulesAnonymousIpList for production enforce mode.'));
        }
        const loggingEnabled = waf.logging && waf.logging.enabled === true;
        if (target === 'aws' && waf.scope === 'CLOUDFRONT' && !loggingEnabled) {
            findings.push(readinessFinding(weakWafSeverity(options), 'firewall.waf.logging.missing', 'WAF logging is not enabled while scope=CLOUDFRONT.', 'Set firewall.waf.logging.enabled: true and supply destination_arn_env for production WAF log retention.'));
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
        if (firewallChallengeEnabled(policy)) {
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
        if (target === 'aws' && warning.includes('firewall.waf.logging is not enabled while scope=CLOUDFRONT')) {
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
    }
    else {
        for (const finding of report.findings) {
            const marker = finding.severity === 'fail' ? 'FAIL' : 'WARN';
            const stream = finding.severity === 'fail' ? console.error : console.warn;
            stream(`[${marker}] ${finding.id}: ${finding.detail}`);
            stream(`       ${finding.recommendation}`);
        }
    }
    const waf = report.wafRecommendations;
    if (waf && Array.isArray(waf.recommendations) && waf.recommendations.length > 0) {
        console.log('');
        console.log(`WAF recommendations: inferred_app_shape=${waf.inferredAppShape}, read_only=${waf.readOnly}`);
        for (const rec of waf.recommendations) {
            console.log(`- ${rec.id}: ${rec.title}`);
            console.log(`  Target support: aws=${rec.targetSupport.aws}, cloudflare=${rec.targetSupport.cloudflare}`);
            console.log(`  Recommended managed rules: ${rec.rules.join(', ')}`);
            console.log(`  Missing managed rules: ${rec.missingRules.length > 0 ? rec.missingRules.join(', ') : 'none'}`);
            console.log(`  Related settings: ${rec.settings.join('; ')}`);
            console.log(`  Rationale: ${rec.rationale}`);
            console.log(`  Cost: ${rec.cost}`);
            console.log(`  False-positive risk: ${rec.falsePositiveRisk}`);
            if (rec.notes.length > 0)
                console.log(`  Target notes: ${rec.notes.join(' ')}`);
        }
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
    .action(async (opts) => {
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
        if (opts.appShape)
            validateGuidedChoice('app-shape', opts.appShape, archetypeNames);
        if (opts.auth)
            validateGuidedChoice('auth', opts.auth, authModes);
        if (opts.waf)
            validateGuidedChoice('waf', opts.waf, wafPostures);
        if (opts.deployment)
            validateGuidedChoice('deployment', opts.deployment, deploymentIntents);
    }
    catch (e) {
        console.error('[ERROR]', e.message);
        process.exit(1);
    }
    if ((!platform || (!profile && !archetype && !guided)) && !canPrompt) {
        console.error('[ERROR] Interactive init requires a TTY. Use --guided, --profile, or --archetype with --platform for non-interactive setup.');
        process.exit(1);
    }
    if (!platform || (!profile && !archetype && !guided)) {
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
        guided = guided || answers.starterKind === 'guided';
        profile = profile || answers.profile;
        archetype = archetype || answers.archetype;
    }
    if (guided) {
        if (platform && !['aws', 'cloudflare'].includes(platform)) {
            console.error('[ERROR] Invalid --platform. Use aws or cloudflare.');
            process.exit(1);
        }
        const guidedQuestions = [];
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
                default: (a) => defaultAuthForShape(a.appShape || opts.appShape || 'spa-static-site'),
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
                default: (a) => defaultProtectedPaths(a.appShape || opts.appShape || 'spa-static-site', a.auth || opts.auth || defaultAuthForShape(a.appShape || opts.appShape || 'spa-static-site')).join(','),
                when: (a) => (a.auth || opts.auth || 'none') !== 'none',
            });
        }
        if (canPrompt && !opts.corsOrigins) {
            guidedQuestions.push({
                type: 'input',
                name: 'corsOrigins',
                message: 'CORS allow origins (comma-separated, blank for none):',
                default: (a) => defaultCorsOrigins(a.appShape || opts.appShape || 'spa-static-site').join(','),
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
                default: (a) => `guided-${a.appShape || opts.appShape || 'cdn-security'}`,
            });
        }
        const answers = guidedQuestions.length > 0 ? await promptQuestions(guidedQuestions) : {};
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
        fs.writeFileSync(destSecurity, withYamlLanguageServerHint(content, './schema.json'), 'utf8');
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
    fs.writeFileSync(destSecurity, withYamlLanguageServerHint(content, './schema.json'), 'utf8');
    fs.writeFileSync(destStarter, withYamlLanguageServerHint(content, '../schema.json'), 'utf8');
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
    .option('--fail-on-weak-waf-baseline', 'Promote weak WAF baseline findings to failures for production CI')
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
    let wafRecommendations = null;
    const lint = lintPolicy({ policyPath, pkgRoot, env: process.env });
    lint.errors.forEach((error) => findings.push(readinessFinding('fail', 'policy.lint.error', error, 'Fix policy validation before production release.')));
    if (lint.policy && typeof lint.policy === 'object') {
        policy = lint.policy;
        findings.push(...evaluateReadiness(policy, target, lint.warnings, {
            failOnWeakWafBaseline: Boolean(opts.failOnWeakWafBaseline),
        }));
        wafRecommendations = buildWafRecommendations(policy, policyPath, target);
    }
    const failCount = findings.filter((f) => f.severity === 'fail').length;
    const warnCount = findings.filter((f) => f.severity === 'warn').length;
    const strict = Boolean(opts.strict);
    const failOnWeakWafBaseline = Boolean(opts.failOnWeakWafBaseline);
    const exitCode = failCount > 0 || (strict && warnCount > 0) ? 1 : 0;
    const status = failCount > 0 ? 'fail' : warnCount > 0 ? 'warn' : 'pass';
    const report = {
        generatedAt: new Date().toISOString(),
        policyPath,
        target,
        strict,
        failOnWeakWafBaseline,
        status,
        exitCode,
        summary: { fail: failCount, warn: warnCount },
        findings,
        wafRecommendations,
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
    .command('capabilities')
    .description('Print target capability support matrix and optionally evaluate configured policy controls')
    .option('-p, --policy <path>', 'Optional policy file path to evaluate against the selected target', null)
    .option('-t, --target <platform>', 'Target platform for policy evaluation: aws | cloudflare | all', 'all')
    .option('--json', 'Print machine-readable JSON instead of a human report')
    .action((opts) => {
    let target;
    try {
        target = normalizeCapabilityTarget(opts.target || 'all');
    }
    catch (e) {
        console.error('[ERROR]', e.message);
        process.exit(1);
    }
    let policyPath = null;
    if (opts.policy) {
        policyPath = path.isAbsolute(opts.policy) ? opts.policy : path.join(process.cwd(), opts.policy);
        if (!fs.existsSync(policyPath)) {
            console.error('[ERROR] Policy file not found:', policyPath);
            process.exit(1);
        }
    }
    try {
        const report = buildCapabilitiesReport({ target, policyPath });
        if (opts.json) {
            console.log(JSON.stringify(report, null, 2));
        }
        else {
            printCapabilitiesReport(report);
        }
    }
    catch (e) {
        console.error('[ERROR] Failed to inspect capabilities:', e.message);
        process.exit(1);
    }
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
    .command('visualize')
    .description('Render a deterministic policy control visualizer as Mermaid or static HTML')
    .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
    .option('-t, --target <platform>', 'Target platform for control behavior: aws | cloudflare | all', 'all')
    .option('--format <mode>', 'Artifact format: mermaid | html', 'mermaid')
    .option('-o, --out <path>', 'Write rendered output to file')
    .action((opts) => {
    let target;
    let format;
    try {
        target = normalizeCapabilityTarget(opts.target || 'all');
        format = normalizeVisualFormat(opts.format || 'mermaid');
    }
    catch (e) {
        console.error('[ERROR]', e.message);
        process.exit(1);
    }
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    if (!fs.existsSync(policyPath)) {
        console.error('[ERROR] Policy file not found:', policyPath);
        process.exit(1);
    }
    let artifact;
    try {
        artifact = renderPolicyVisualization(policyPath, target, { format });
    }
    catch (e) {
        console.error('[ERROR] Failed to render policy visualization:', e.message);
        process.exit(1);
        return;
    }
    const resolvedOut = opts.out ? (path.isAbsolute(opts.out) ? opts.out : path.join(cwd, opts.out)) : null;
    if (resolvedOut) {
        fs.writeFileSync(resolvedOut, artifact, 'utf8');
        console.log('[SUCCESS] Wrote visualization to', resolvedOut);
        return;
    }
    console.log(artifact);
});
program
    .command('diff')
    .description('Compare generated output or policy posture changes between two policies')
    .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
    .option('-o, --out-dir <dir>', 'Existing output directory to compare', 'dist')
    .option('-t, --target <platform>', 'Target platform (aws | cloudflare | all)', 'aws')
    .option('--baseline <path>', 'Baseline policy file path for semantic diff', null)
    .option('--semantic', 'Show security posture findings instead of file artifact diff')
    .option('--json', 'Output semantic policy diff as JSON')
    .action((opts) => {
    const cwd = process.cwd();
    const policyPath = resolvePolicyPath(cwd, opts.policy);
    let target;
    try {
        target = normalizeCapabilityTarget(opts.target);
    }
    catch (e) {
        console.error('[ERROR]', e.message || String(e));
        process.exit(1);
    }
    if (opts.semantic) {
        const baselinePolicyPath = opts.baseline
            ? (path.isAbsolute(opts.baseline) ? opts.baseline : path.join(cwd, opts.baseline))
            : path.join(cwd, 'policy', 'base.yml');
        if (!fs.existsSync(baselinePolicyPath)) {
            console.error('[ERROR] Baseline policy file not found:', baselinePolicyPath);
            process.exit(1);
        }
        if (!fs.existsSync(policyPath)) {
            console.error('[ERROR] Candidate policy file not found:', policyPath);
            process.exit(1);
        }
        try {
            const baselinePolicy = loadPolicyDocument(baselinePolicyPath);
            const candidatePolicy = loadPolicyDocument(policyPath);
            const report = compareSecurityPostureFindings(baselinePolicy, candidatePolicy, baselinePolicyPath, policyPath, target);
            const exitCode = printPolicyDiffReport(report, !!opts.json);
            process.exit(exitCode);
        }
        catch (e) {
            console.error('[ERROR] Failed to evaluate policy diff:', e.message);
            process.exit(1);
        }
        return;
    }
    const existingOutDir = path.isAbsolute(opts.outDir) ? opts.outDir : path.join(cwd, opts.outDir);
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cdn-security-diff-'));
    const freshOutDir = path.join(tmpRoot, 'dist');
    try {
        const { compile } = require(path.join(pkgRoot, 'lib'));
        const result = compile({
            policyPath,
            outDir: freshOutDir,
            target,
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
    .command('playground')
    .description('Run sample requests against locally compiled AWS/Cloudflare runtime artifacts')
    .option('-p, --policy <path>', 'Policy file path (default: policy/security.yml or policy/base.yml)', null)
    .option('-t, --target <platform>', 'Target platform: aws | cloudflare | all', 'all')
    .option('-f, --fixture <path>', 'JSON fixture with request cases (array, {fixtures: [...]}, or {request: {...}})')
    .option('--json', 'Emit machine-readable output')
    .option('--allow-placeholder-token', 'Allow non-production placeholder credentials for local policy checks')
    .action(async (opts) => {
    if (opts.target !== 'aws' && opts.target !== 'cloudflare' && opts.target !== 'all') {
        console.error('[ERROR] --target must be aws, cloudflare, or all.');
        process.exit(1);
    }
    try {
        const report = await withMutedOutput(() => runPlayground(opts), !!opts.json);
        if (opts.json) {
            console.log(JSON.stringify(report, null, 2));
            return;
        }
        for (const targetResult of report.targets) {
            console.log(`[${targetResult.target}]`);
            for (const item of targetResult.fixtures) {
                const querySuffix = item.query ? `?${item.query}` : '';
                const reason = item.block_reason ? ` reason=${item.block_reason}` : '';
                console.log(`- ${item.name}: ${item.method} ${item.path}${querySuffix} => ${item.decision.toUpperCase()} (status=${item.status})${reason}`);
            }
        }
    }
    catch (e) {
        console.error('[ERROR]', e.message || String(e));
        process.exit(1);
    }
});
program
    .command('analyze')
    .description('Aggregate monitor-mode JSON logs and flag low-frequency blocking candidates')
    .requiredOption('-i, --input <path>', 'Path to JSONL log input')
    .option('--min-count <n>', 'Candidate threshold for suspicious low-frequency blocks', '5')
    .option('--top <n>', 'Maximum route candidates to print/export', '20')
    .option('--json', 'Emit machine-readable output')
    .action((opts) => {
    try {
        const minCount = Number(opts.minCount);
        const top = Number(opts.top);
        const report = runAnalyze({
            input: opts.input,
            minCount,
            top,
        });
        if (opts.json) {
            console.log(JSON.stringify(report, null, 2));
        }
        else {
            printAnalyzeReport(report);
        }
    }
    catch (e) {
        console.error('[ERROR]', e.message || String(e));
        process.exit(1);
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
