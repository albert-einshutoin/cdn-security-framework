import type { CDNSecurityFrameworkPolicy } from '../../types/policy';
import type { ValidateFunction } from 'ajv';
import fs from 'node:fs';
import path from 'node:path';

let validators: { policy: ValidateFunction; methods: ValidateFunction } | undefined;
function validateStaticPolicy(policy: CDNSecurityFrameworkPolicy): void {
  if (!validators) {
    // The public validator imports compile-core, which uses this module's target
    // guard. Compile the same canonical Schema here without that dependency cycle.
    const schema = JSON.parse(fs.readFileSync(path.join(__dirname, '../../policy/schema.json'), 'utf8'));
    const Ajv = require('ajv');
    const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true });
    validators = { policy: ajv.compile(schema), methods: ajv.compile(schema.properties.firewall.properties.waf.properties.cloudflare_static_site.properties.method_exceptions.items.properties.methods) };
  }
  if (!validators.policy(policy)) fail('POLICY_SCHEMA');
  if (!validators.methods(policy.request.allow_methods)) fail('METHODS');
}

function fail(reason: string, unsupported = false): never {
  throw new Error('CLOUDFLARE_STATIC_' + (unsupported ? 'UNKNOWN: ' : 'INVALID: ') + reason);
}

export function isStaticWafPolicy(policy: CDNSecurityFrameworkPolicy): boolean {
  return policy?.firewall?.waf?.cloudflare_static_site !== undefined;
}

// A WAF-only profile must not silently create an unprotected Worker/AWS artifact.
export function rejectStaticWafPolicy(policy: CDNSecurityFrameworkPolicy): void {
  if (isStaticWafPolicy(policy)) fail('WAF_ONLY_PROFILE');
}

export function buildCloudflareStaticConditions(policy: CDNSecurityFrameworkPolicy): Array<{ description: string; expression: string }> {
  const config = policy.firewall?.waf?.cloudflare_static_site;
  if (config === undefined) return [];
  validateStaticPolicy(policy);
  const { exact, prefix } = config.block_paths;
  const exceptions = config.block_paths.exceptions ?? [];
  const ports = config.allow_ports;

  // This profile declares only WAF conditions. Refuse Worker requirements rather
  // than producing a successful artifact that cannot enforce those requirements.
  if (Object.keys(policy).some(k => !['version', 'project', 'metadata', 'defaults', 'request', 'response_headers', 'firewall', 'extends'].includes(k))
    || Object.keys(policy.request).some(k => !['allow_methods', 'block'].includes(k))
    || Object.keys(policy.request.block ?? {}).some(k => k !== 'ua_contains')
    || Object.keys(policy.response_headers).length
    || policy.defaults?.response !== undefined
    || Object.keys(policy.firewall || {}).some(k => !['waf', 'geo', 'ip'].includes(k))) fail('WORKER_REQUIREMENTS', true);
  if (policy.defaults?.mode !== undefined && policy.defaults.mode !== 'enforce') fail('MONITOR_MODE', true);
  if (policy.firewall?.waf?.scope !== undefined) fail('AWS_SCOPE', true);
  const methods = policy.request.allow_methods;
  const methodExceptions = config.method_exceptions ?? [];
  const seen = new Set<string>();
  const field = 'lower(http.request.uri.path)';
  const set = (values: string[]) => '{' + values.map(v => JSON.stringify(v)).join(' ') + '}';
  const pathTerms = [
    ...(exact.length ? [field + ' in ' + set(exact)] : []),
    ...prefix.map(p => 'starts_with(' + field + ', ' + JSON.stringify(p) + ')'),
  ];
  const matchedPath = '(' + pathTerms.join(' or ') + ')';
  const pathExpression = exceptions.length ? '(' + matchedPath + ' and not (' + field + ' in ' + set(exceptions) + '))' : matchedPath;
  const methodTerms = ['http.request.method in ' + set(methods)];
  for (const entry of methodExceptions) {
    const p = entry.path;
    if (seen.has(p)) fail('METHOD_EXCEPTION_DUPLICATE_PATH');
    seen.add(p);
    const allowed = entry.methods;
    methodTerms.push('(http.request.method in ' + set(allowed) + ' and ' + field + ' eq ' + JSON.stringify(p) + ')');
  }
  const conditions = [
    { description: 'Static site path block', expression: pathExpression },
    { description: 'Static site method allowlist', expression: 'not (' + methodTerms.join(' or ') + ')' },
    { description: 'Static site edge port allowlist', expression: 'not (cf.edge.server_port in {' + ports.join(' ') + '})' },
  ];
  if (conditions.some(c => Buffer.byteLength(c.expression) > 4096)) fail('EXPRESSION_LIMIT');
  return conditions;
}

// Recognize only these emitted shapes after the shared Free validator has
// checked and removed canonical JSON literals. This does not evaluate a WAF.
export function isCloudflareStaticExpressionShape(stripped: string): boolean {
  const literalSet = String.raw`\{""(?: ""){0,31}\}`;
  const uri = String.raw`lower\(http\.request\.uri\.path\)`;
  const pathTerm = '(?:' + uri + ' in ' + literalSet + '|starts_with\\(' + uri + ', ""\\))';
  const paths = '\\(' + pathTerm + '(?: or ' + pathTerm + '){0,32}\\)';
  const pathExpression = '^(?:' + paths + '|\\(' + paths + ' and not \\(' + uri + ' in ' + literalSet + '\\)\\))$';
  if (new RegExp(pathExpression).test(stripped)) return true;
  const methods = 'http\\.request\\.method in ' + literalSet;
  const methodException = '\\(' + methods + ' and ' + uri + ' eq ""\\)';
  if (new RegExp('^not \\(' + methods + '(?: or ' + methodException + '){0,32}\\)$').test(stripped)) return true;
  const port = /^not \(cf\.edge\.server_port in \{([1-9]\d{0,4}(?: [1-9]\d{0,4})*)\}\)$/.exec(stripped);
  return Boolean(port && port[1].split(' ').length <= 32 && port[1].split(' ').every(p => Number(p) <= 65535));
}
