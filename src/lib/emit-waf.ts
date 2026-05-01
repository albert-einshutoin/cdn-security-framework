/**
 * Programmatic API: emitWaf
 *
 * Generate only the WAF/infra config — no edge code. Mirrors the CLI
 * `emit-waf` subcommand and keeps the same flag surface.
 *
 * Input:
 *   {
 *     policyPath:     string,
 *     outDir:         string,
 *     target:         'aws' | 'cloudflare',
 *     format?:        'terraform' | 'cloudformation' | 'cdk',
 *     outputMode?:    'full' | 'rule-group',
 *     ruleGroupOnly?: boolean,
 *     failOnWafApproximation?: boolean,  // cloudflare only
 *     cwd?:           string,
 *     pkgRoot?:       string,
 *     env?:           NodeJS.ProcessEnv,
 *   }
 *
 * Output: same shape as compile() but edgeFiles is always [].
 *
 * Error semantics for unimplemented formats: cloudformation and cdk return
 * { ok: false } with `errors` explaining the format is not implemented. The
 * CLI layer translates this to exit code 2 (see bin/cli.js).
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { lintPolicy } = require('./lint');

const DEFAULT_PKG_ROOT = path.join(__dirname, '..');

type EmitWafTarget = 'aws' | 'cloudflare';
type EmitWafFormat = 'terraform' | 'cloudformation' | 'cdk';

interface EmitWafOptions {
  policyPath?: string;
  outDir?: string;
  target?: EmitWafTarget;
  format?: EmitWafFormat;
  outputMode?: string;
  ruleGroupOnly?: boolean;
  failOnWafApproximation?: boolean;
  cwd?: string;
  pkgRoot?: string;
  env?: NodeJS.ProcessEnv;
}

interface EmitWafResultBase {
  edgeFiles: string[];
  infraFiles: string[];
  policyPath: string | null;
  outDir: string | null;
  target: string;
  format: string;
  formatNotImplemented: boolean;
}

function resolveAbsolute(inputPath: string, cwd: string): string {
  return path.isAbsolute(inputPath) ? inputPath : path.join(cwd, inputPath);
}

function listInfraArtifacts(outDir: string, sinceMs = 0): string[] {
  const infraDir = path.join(outDir, 'infra');
  if (!fs.existsSync(infraDir)) return [];
  return fs
    .readdirSync(infraDir)
    .filter((name: string) => name.endsWith('.tf.json'))
    .map((name: string) => path.join(infraDir, name))
    .filter((filePath: string) => sinceMs <= 0 || fs.statSync(filePath).mtimeMs >= sinceMs);
}

function logicalId(input: string): string {
  const cleaned = String(input || 'Resource')
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .split(/\s+/)
    .map((part: string) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
  const id = cleaned || 'Resource';
  return /^[A-Za-z]/.test(id) ? id : `Resource${id}`;
}

function pascalCase(input: string): string {
  const special: Record<string, string> = {
    cloudwatch_metrics_enabled: 'CloudWatchMetricsEnabled',
    ip_set_reference_statement: 'IPSetReferenceStatement',
    ja3_fingerprint: 'JA3Fingerprint',
    ja4_fingerprint: 'JA4Fingerprint',
    custom_key: 'CustomKeys',
    text_transformation: 'TextTransformations',
  };
  if (special[input]) return special[input];
  return input
    .split('_')
    .map((part: string) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

function toCloudFormationShape(value: any): any {
  if (Array.isArray(value)) return value.map(toCloudFormationShape);
  if (!value || typeof value !== 'object') return value;
  const out: any = {};
  for (const [key, entry] of Object.entries(value)) {
    out[pascalCase(key)] = toCloudFormationShape(entry);
  }
  return out;
}

function cfnAction(action: any): any {
  if (action && action.allow) return { Allow: {} };
  if (action && action.count) return { Count: {} };
  if (action && action.captcha) return { Captcha: {} };
  if (action && action.block && action.block.custom_response) {
    return {
      Block: {
        CustomResponse: toCloudFormationShape(action.block.custom_response),
      },
    };
  }
  return { Block: {} };
}

function cfnOverrideAction(action: any): any {
  if (action && action.count) return { Count: {} };
  return { None: {} };
}

function cfnVisibilityConfig(config: any): any {
  return {
    CloudWatchMetricsEnabled: Boolean(config?.cloudwatch_metrics_enabled),
    MetricName: config?.metric_name || 'cdn-security',
    SampledRequestsEnabled: config?.sampled_requests_enabled !== false,
  };
}

function cfnRules(rules: any[]): any[] {
  return (rules || []).map((rule: any) => {
    const out: any = {
      Name: rule.name,
      Priority: rule.priority,
      Statement: toCloudFormationShape(rule.statement),
      VisibilityConfig: cfnVisibilityConfig(rule.visibility_config),
    };
    if (rule.action) out.Action = cfnAction(rule.action);
    if (rule.override_action) out.OverrideAction = cfnOverrideAction(rule.override_action);
    return out;
  });
}

function cfnCustomResponseBodies(blockResponse: any): any | undefined {
  if (!blockResponse) return undefined;
  return {
    cdn_sec_block: {
      Content: blockResponse.body || 'Forbidden',
      ContentType: blockResponse.content_type || 'TEXT_PLAIN',
    },
  };
}

function buildCloudFormation(policy: any, options: { outputMode: string; ruleGroupOnly?: boolean }) {
  const firewall = policy.firewall || {};
  const waf = firewall.waf || {};
  const geo = firewall.geo || {};
  const ip = firewall.ip || {};
  const projectName = (policy.project || 'cdn-security').replace(/[^a-z0-9-]/gi, '-').toLowerCase();
  const scope = waf.scope === 'CLOUDFRONT' ? 'CLOUDFRONT' : 'REGIONAL';
  const outputMode = options.ruleGroupOnly ? 'rule-group' : (options.outputMode || 'full');
  const resources: any = {};

  const wafRules: any[] = [];
  let priority = 1;
  const fingerprintActionType = waf.fingerprint_action === 'count' ? 'count' : 'block';
  const blockResponse = waf.block_response || null;
  const blockResponseKey = blockResponse ? 'cdn_sec_block' : null;
  const blockAction = () => blockResponseKey
    ? { block: { custom_response: { response_code: Number(blockResponse.status_code) || 403, custom_response_body_key: blockResponseKey } } }
    : { block: {} };
  const actionFor = (actionName: string) => {
    if (actionName === 'count') return { count: {} };
    if (actionName === 'captcha') return { captcha: {} };
    return blockAction();
  };

  if (waf.rate_limit) {
    wafRules.push({
      name: 'rate-based-rule',
      priority: priority++,
      action: blockAction(),
      statement: {
        rate_based_statement: {
          limit: Number(waf.rate_limit) || 2000,
          aggregate_key_type: 'IP',
        },
      },
      visibility_config: {
        cloudwatch_metrics_enabled: true,
        metric_name: projectName + '-rate-limit',
        sampled_requests_enabled: true,
      },
    });
  }

  if (Array.isArray(waf.rate_limit_rules)) {
    for (const rule of waf.rate_limit_rules) {
      if (!rule || !rule.name || !rule.limit) continue;
      const aggregateKeyType = rule.aggregate_key_type || 'IP';
      const rateStmt: any = {
        limit: Number(rule.limit),
        aggregate_key_type: aggregateKeyType,
      };
      if (aggregateKeyType === 'CUSTOM_KEYS' && Array.isArray(rule.custom_keys)) {
        rateStmt.custom_key = rule.custom_keys;
      }
      if (rule.scope_down_statement && typeof rule.scope_down_statement === 'object') {
        rateStmt.scope_down_statement = rule.scope_down_statement;
      }
      wafRules.push({
        name: rule.name,
        priority: Number(rule.priority) || priority++,
        action: actionFor(rule.action),
        statement: { rate_based_statement: rateStmt },
        visibility_config: {
          cloudwatch_metrics_enabled: true,
          metric_name: projectName + '-' + rule.name,
          sampled_requests_enabled: true,
        },
      });
    }
  }

  const addFingerprintRules = (fieldName: string, fingerprints: unknown[], rulePrefix: string, metricPrefix: string) => {
    if (!Array.isArray(fingerprints) || fingerprints.length === 0) return;
    for (const fp of fingerprints) {
      if (!fp) continue;
      const fpStr = String(fp);
      const slug = fpStr.slice(0, 12).toLowerCase();
      wafRules.push({
        name: `${rulePrefix}-${fingerprintActionType}-${slug}`,
        priority: priority++,
        action: { [fingerprintActionType]: {} },
        statement: {
          byte_match_statement: {
            field_to_match: { [fieldName]: {} },
            positional_constraint: 'EXACTLY',
            search_string: fpStr,
            text_transformation: [{ priority: 0, type: 'NONE' }],
          },
        },
        visibility_config: {
          cloudwatch_metrics_enabled: true,
          metric_name: `${projectName}-${metricPrefix}-${slug}`,
          sampled_requests_enabled: true,
        },
      });
    }
  };
  addFingerprintRules('ja3_fingerprint', waf.ja3_fingerprints, 'ja3', 'ja3');
  addFingerprintRules('ja4_fingerprint', waf.ja4_fingerprints, 'ja4', 'ja4');

  const ruleGroupLogicalId = logicalId(projectName + '-rate-limit-rule-group');
  const ruleGroup: any = {
    Type: 'AWS::WAFv2::RuleGroup',
    Properties: {
      Name: projectName + '-rate-limit',
      Scope: scope,
      Capacity: Math.max(2, wafRules.length * 2 || 2),
      Rules: cfnRules(wafRules),
      VisibilityConfig: {
        CloudWatchMetricsEnabled: true,
        MetricName: projectName + '-rule-group',
        SampledRequestsEnabled: true,
      },
    },
  };
  const responseBodies = cfnCustomResponseBodies(blockResponse);
  if (responseBodies) ruleGroup.Properties.CustomResponseBodies = responseBodies;
  resources[ruleGroupLogicalId] = ruleGroup;

  if (waf.managed_rules && waf.managed_rules.length > 0 && outputMode !== 'rule-group') {
    const webAclLogicalId = logicalId(projectName + '-web-acl');
    const webAcl: any = {
      Type: 'AWS::WAFv2::WebACL',
      Properties: {
        Name: projectName + '-waf-acl',
        Scope: scope,
        DefaultAction: { Allow: {} },
        Rules: waf.managed_rules.map((ruleName: string, idx: number) => ({
          Name: `AWS-${ruleName}`,
          Priority: 10 + idx,
          OverrideAction: { None: {} },
          Statement: {
            ManagedRuleGroupStatement: {
              VendorName: 'AWS',
              Name: ruleName,
            },
          },
          VisibilityConfig: {
            CloudWatchMetricsEnabled: true,
            MetricName: `${projectName}-${ruleName}`,
            SampledRequestsEnabled: true,
          },
        })),
        VisibilityConfig: {
          CloudWatchMetricsEnabled: true,
          MetricName: projectName + '-waf-acl',
          SampledRequestsEnabled: true,
        },
      },
    };
    if (responseBodies) webAcl.Properties.CustomResponseBodies = responseBodies;
    resources[webAclLogicalId] = webAcl;
  }

  if (geo.block_countries || geo.allow_countries) {
    const geoRuleGroupLogicalId = logicalId(projectName + '-geo-rule-group');
    const geoStatement = geo.allow_countries
      ? { NotStatement: { Statement: { GeoMatchStatement: { CountryCodes: geo.allow_countries } } } }
      : { GeoMatchStatement: { CountryCodes: geo.block_countries } };
    resources[geoRuleGroupLogicalId] = {
      Type: 'AWS::WAFv2::RuleGroup',
      Properties: {
        Name: projectName + '-geo-block',
        Scope: scope,
        Capacity: 1,
        Rules: [{
          Name: 'geo-block-rule',
          Priority: 1,
          Action: { Block: {} },
          Statement: geoStatement,
          VisibilityConfig: {
            CloudWatchMetricsEnabled: true,
            MetricName: projectName + '-geo-block',
            SampledRequestsEnabled: true,
          },
        }],
        VisibilityConfig: {
          CloudWatchMetricsEnabled: true,
          MetricName: projectName + '-geo-rule-group',
          SampledRequestsEnabled: true,
        },
      },
    };
  }

  const addIpSet = (kind: 'allowlist' | 'blocklist', action: 'Allow' | 'Block') => {
    const addresses = ip[kind];
    if (!Array.isArray(addresses) || addresses.length === 0) return;
    const ipSetLogicalId = logicalId(`${projectName}-${kind}-ip-set`);
    const ruleGroupLogicalId = logicalId(`${projectName}-${kind}-rule-group`);
    resources[ipSetLogicalId] = {
      Type: 'AWS::WAFv2::IPSet',
      Properties: {
        Name: `${projectName}-ip-${kind}`,
        Scope: scope,
        IPAddressVersion: 'IPV4',
        Addresses: addresses,
      },
    };
    resources[ruleGroupLogicalId] = {
      Type: 'AWS::WAFv2::RuleGroup',
      Properties: {
        Name: `${projectName}-ip-${kind}`,
        Scope: scope,
        Capacity: 1,
        Rules: [{
          Name: `ip-${kind}-rule`,
          Priority: 1,
          Action: { [action]: {} },
          Statement: { IPSetReferenceStatement: { ARN: { 'Fn::GetAtt': [ipSetLogicalId, 'Arn'] } } },
          VisibilityConfig: {
            CloudWatchMetricsEnabled: true,
            MetricName: `${projectName}-ip-${kind}`,
            SampledRequestsEnabled: true,
          },
        }],
        VisibilityConfig: {
          CloudWatchMetricsEnabled: true,
          MetricName: `${projectName}-ip-${kind}-group`,
          SampledRequestsEnabled: true,
        },
      },
    };
  };
  addIpSet('blocklist', 'Block');
  addIpSet('allowlist', 'Allow');

  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: `Generated by cdn-security-framework for ${projectName}`,
    Resources: resources,
  };
}

function emitWaf(opts: EmitWafOptions = {}) {
  opts = opts || {};
  const cwd = opts.cwd || process.cwd();
  const pkgRoot = opts.pkgRoot || DEFAULT_PKG_ROOT;
  const env = opts.env || process.env;
  const format = opts.format || 'terraform';
  const target = opts.target || 'aws';

  const errors: string[] = [];
  const warnings: string[] = [];
  const baseResult: EmitWafResultBase = {
    edgeFiles: [],
    infraFiles: [],
    policyPath: null,
    outDir: null,
    target,
    format,
    formatNotImplemented: false,
  };

  if (!opts.policyPath) {
    return { ok: false, errors: ['policyPath is required'], warnings, ...baseResult };
  }
  if (!opts.outDir) {
    return { ok: false, errors: ['outDir is required'], warnings, ...baseResult };
  }
  if (target !== 'aws' && target !== 'cloudflare') {
    return {
      ok: false,
      errors: [`Unknown target: ${target} (expected aws | cloudflare)`],
      warnings,
      ...baseResult,
    };
  }
  if (!['terraform', 'cloudformation', 'cdk'].includes(format)) {
    return {
      ok: false,
      errors: [`Unknown --format: ${format} (expected terraform | cloudformation | cdk)`],
      warnings,
      ...baseResult,
    };
  }
  if (format === 'cdk') {
    return {
      ok: false,
      errors: [
        `--format ${format} is not yet implemented. Terraform and CloudFormation are generated today; CDK is reserved and intentionally fails loudly to prevent silent fallback.`,
      ],
      warnings,
      ...baseResult,
      formatNotImplemented: true,
    };
  }

  const policyPath = resolveAbsolute(opts.policyPath, cwd);
  const outDir = resolveAbsolute(opts.outDir, cwd);
  const emitStartedAt = Date.now() - 1000;
  baseResult.policyPath = policyPath;
  baseResult.outDir = outDir;

  if (!fs.existsSync(policyPath)) {
    return {
      ok: false,
      errors: [`policy file not found: ${policyPath}`],
      warnings,
      ...baseResult,
    };
  }

  const lint = lintPolicy({ policyPath, pkgRoot, env });
  warnings.push(...lint.warnings);
  if (!lint.ok) {
    errors.push(...lint.errors);
    return { ok: false, errors, warnings, ...baseResult };
  }

  if (format === 'cloudformation') {
    if (target !== 'aws') {
      return {
        ok: false,
        errors: ['--format cloudformation is only supported with --target aws'],
        warnings,
        ...baseResult,
      };
    }
    const infraDir = path.join(outDir, 'infra');
    fs.mkdirSync(infraDir, { recursive: true });
    const cloudformation = buildCloudFormation(lint.policy, {
      outputMode: opts.outputMode || 'full',
      ruleGroupOnly: opts.ruleGroupOnly,
    });
    const outPath = path.join(infraDir, 'waf-cloudformation.json');
    fs.writeFileSync(outPath, JSON.stringify(cloudformation, null, 2), 'utf8');
    baseResult.infraFiles = [outPath];
    return { ok: true, errors, warnings, ...baseResult };
  }

  if (target === 'aws') {
    const infraPath = path.join(pkgRoot, 'scripts', 'compile-infra.js');
    const result = spawnSync(
      process.execPath,
      [
        infraPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        '--output-mode', opts.outputMode || 'full',
        ...(opts.ruleGroupOnly ? ['--rule-group-only'] : []),
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (result.status !== 0) {
      errors.push(`infra compile failed (status ${result.status})`);
      if (result.stderr) errors.push(result.stderr.trim());
      return { ok: false, errors, warnings, ...baseResult };
    }
    if (result.stderr) {
      warnings.push(...result.stderr.trim().split('\n').filter(Boolean));
    }
    baseResult.infraFiles = listInfraArtifacts(outDir, emitStartedAt);
  } else {
    const cfWafPath = path.join(pkgRoot, 'scripts', 'compile-cloudflare-waf.js');
    const result = spawnSync(
      process.execPath,
      [
        cfWafPath,
        '--policy', policyPath,
        '--out-dir', outDir,
        ...(opts.failOnWafApproximation ? ['--fail-on-waf-approximation'] : []),
      ],
      { cwd, encoding: 'utf8', env },
    );
    if (result.status !== 0) {
      errors.push(`cloudflare waf compile failed (status ${result.status})`);
      if (result.stderr) errors.push(result.stderr.trim());
      return { ok: false, errors, warnings, ...baseResult };
    }
    if (result.stderr) {
      warnings.push(...result.stderr.trim().split('\n').filter(Boolean));
    }
    baseResult.infraFiles = listInfraArtifacts(outDir, emitStartedAt);
  }

  return { ok: true, errors, warnings, ...baseResult };
}

module.exports = { emitWaf };
