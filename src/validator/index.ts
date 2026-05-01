const fs = require('fs');
const path = require('path');
const Ajv = require('ajv');

import type { ErrorObject } from 'ajv';
import type { CDNSecurityFrameworkPolicy } from '../types/policy';

const {
  validateAuthGates,
  parsePathPatterns,
} = require('../scripts/lib/compile-core');

const DEFAULT_PKG_ROOT = path.join(__dirname, '..');
export type PolicyDraft = Partial<CDNSecurityFrameworkPolicy>;
type StringRecord = Record<string, unknown>;

export type ValidatePolicyOptions = {
  policy: PolicyDraft | null;
  pkgRoot?: string;
  env?: NodeJS.ProcessEnv;
};

export type ValidatePolicyResult = {
  ok: boolean;
  errors: string[];
  warnings: string[];
};

export function formatAjvErrors(errors: ErrorObject[] = []): string[] {
  return errors.map((err) => {
    const loc = err.instancePath || '(root)';
    const key =
      err.params && err.params.additionalProperty
        ? ` (property "${err.params.additionalProperty}")`
        : '';
    return `  - ${loc} ${err.message}${key}`;
  });
}

export function validateCorsCredentials(policy: PolicyDraft | null): string[] {
  const cors = policy && policy.response_headers && policy.response_headers.cors;
  if (!cors || cors.allow_credentials !== true || !Array.isArray(cors.allow_origins)) {
    return [];
  }
  if (!cors.allow_origins.includes('*')) {
    return [];
  }
  return [
    '  - response_headers.cors: allow_origins cannot include "*" when allow_credentials is true',
  ];
}

function getStringProp(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const entry = (value as StringRecord)[key];
  return typeof entry === 'string' ? entry : undefined;
}

export function validatePolicy(opts: ValidatePolicyOptions): ValidatePolicyResult {
  const pkgRoot = (opts && opts.pkgRoot) || DEFAULT_PKG_ROOT;
  const policy = opts ? opts.policy : null;
  const env = (opts && opts.env) || process.env;
  const errors: string[] = [];
  const warnings: string[] = [];

  let schema: unknown;
  try {
    schema = JSON.parse(
      fs.readFileSync(path.join(pkgRoot, 'policy', 'schema.json'), 'utf8'),
    );
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    return {
      ok: false,
      errors: [`failed to load schema: ${message}`],
      warnings,
    };
  }

  const ajv = new Ajv({
    allErrors: true,
    strict: true,
    strictRequired: false,
    allowUnionTypes: true,
  });
  const validate = ajv.compile(schema);
  if (!validate(policy)) {
    errors.push('Schema validation failed:');
    errors.push(...formatAjvErrors(validate.errors || []));
  }

  errors.push(...validateCorsCredentials(policy));

  try {
    const block = (policy && policy.request && policy.request.block) || {};
    if (block.path_patterns !== undefined) {
      parsePathPatterns(block.path_patterns);
    }
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    errors.push(`  - request.block.path_patterns: ${message}`);
  }

  try {
    validateAuthGates(policy, {
      exitOnError: false,
      allowPlaceholderToken: true,
    });
  } catch (e: unknown) {
    if (
      e &&
      typeof e === 'object' &&
      'validationErrors' in e &&
      Array.isArray(e.validationErrors)
    ) {
      errors.push('Auth gate validation failed:');
      e.validationErrors.forEach((msg: string) => errors.push('  - ' + msg));
    } else {
      const message = e instanceof Error ? e.message : String(e);
      errors.push('Auth gate validation error: ' + message);
    }
  }

  const waf = (policy && policy.firewall && policy.firewall.waf) || {};
  if (
    waf.fingerprint_action &&
    !['block', 'count'].includes(waf.fingerprint_action)
  ) {
    errors.push(
      '  - firewall.waf.fingerprint_action must be "block" or "count"',
    );
  }

  const mode = (policy && policy.defaults && policy.defaults.mode) || null;
  const isEnforce = mode === 'enforce';
  const hasWaf = policy && policy.firewall && policy.firewall.waf;
  if (isEnforce && hasWaf) {
    const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
    const hasCoreSignal = managed.some(
      (r: string) =>
        r === 'AWSManagedRulesBotControlRuleSet' ||
        r === 'AWSManagedRulesATPRuleSet' ||
        r === 'AWSManagedRulesIPReputationList' ||
        r === 'AWSManagedRulesAnonymousIpList',
    );
    if (!hasCoreSignal) {
      warnings.push(
        'firewall.waf.managed_rules does not include any of BotControl / ATP / IPReputation / AnonymousIp. Consider adding at least IPReputation + AnonymousIp for production enforce mode.',
      );
    }
    const loggingEnabled = waf.logging && waf.logging.enabled === true;
    if (waf.scope === 'CLOUDFRONT' && !loggingEnabled) {
      warnings.push(
        'firewall.waf.logging is not enabled while scope=CLOUDFRONT. PCI-DSS / SOC2 require WAF log retention — set logging.enabled: true and supply destination_arn_env.',
      );
    }
  }

  const originAuth = policy && policy.origin && policy.origin.auth;
  const originAuthType = getStringProp(originAuth, 'type');
  const originSecretEnv = getStringProp(originAuth, 'secret_env');
  if (originAuthType === 'custom_header' && originSecretEnv) {
    const envVal = env[originSecretEnv];
    if (envVal !== undefined && envVal.length === 0) {
      warnings.push(
        'origin.auth.secret_env "' +
          originSecretEnv +
          '" is set but empty in the current shell. The edge will refuse to forward the origin-auth header, breaking origin trust. Unset the env or supply a value.',
      );
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
  };
}
