#!/usr/bin/env node
/**
 * Compile Infra Config: security.yml の firewall/transport/origin セクションを読み、dist/infra/*.tf.json に出力する。
 * Usage: node scripts/compile-infra.js [path/to/security.yml] [--policy path] [--out-dir dir]
 * Output:
 *   - dist/infra/waf-rules.tf.json (WAF rate limit, managed rules)
 *   - dist/infra/geo-restriction.tf.json (Geo blocking)
 *   - dist/infra/ip-sets.tf.json (IP allowlist/blocklist)
 *   - dist/infra/cloudfront-settings.tf.json (TLS/HTTP settings)
 *   - dist/infra/cloudfront-origin.tf.json (Origin timeout settings)
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..');
const argv = process.argv.slice(2);
const securityPath = path.join(repoRoot, 'policy', 'security.yml');
const basePath = path.join(repoRoot, 'policy', 'base.yml');
let policyPath = fs.existsSync(securityPath) ? securityPath : basePath;
let outDir = path.join(repoRoot, 'dist');
let ruleGroupOnly = false;
let outputMode = 'full';
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--policy' && argv[i + 1]) { policyPath = argv[++i]; continue; }
  if (argv[i] === '--out-dir' && argv[i + 1]) { outDir = argv[++i]; continue; }
  if (argv[i] === '--rule-group-only') { ruleGroupOnly = true; continue; }
  if (argv[i] === '--output-mode' && argv[i + 1]) { outputMode = argv[++i]; continue; }
  if (!argv[i].startsWith('--')) { policyPath = argv[i]; }
}

if (ruleGroupOnly) outputMode = 'rule-group';
if (!['full', 'rule-group'].includes(outputMode)) {
  console.error('Error: invalid --output-mode. Use "full" or "rule-group".');
  process.exit(1);
}

let policy;
try {
  const content = fs.readFileSync(policyPath, 'utf8');
  policy = yaml.load(content);
} catch (e: any) {
  if (e.code === 'ENOENT') {
    console.error('Error: policy file not found:', policyPath);
    process.exit(1);
  }
  console.error('Error: failed to parse policy YAML:', e.message);
  process.exit(1);
}

const firewall = policy.firewall || {};
const waf = firewall.waf || {};
const geo = firewall.geo || {};
const ip = firewall.ip || {};
const transport = policy.transport || {};
const origin = policy.origin || {};
const projectName = (policy.project || 'cdn-security').replace(/[^a-z0-9-]/gi, '-').toLowerCase();
const scope = (waf.scope === 'CLOUDFRONT') ? 'CLOUDFRONT' : 'REGIONAL';

const distDir = path.join(outDir, 'infra');
fs.mkdirSync(distDir, { recursive: true });

// 1. WAF Rules (rate limit + managed rules)
const wafRules = [];
let priority = 1;
const fingerprintActionType = (waf.fingerprint_action === 'count') ? 'count' : 'block';

// Custom block response (referenced by every block action when configured)
const blockResponse = waf.block_response || null;
const blockResponseKey = blockResponse ? 'cdn_sec_block' : null;
function blockAction() {
  if (blockResponseKey) {
    return {
      block: {
        custom_response: {
          response_code: Number(blockResponse.status_code) || 403,
          custom_response_body_key: blockResponseKey,
        },
      },
    };
  }
  return { block: {} };
}

function actionFor(actionName: string) {
  if (actionName === 'count') return { count: {} };
  if (actionName === 'captcha') return { captcha: {} };
  return blockAction();
}

// Rate limit rule (legacy single global rule)
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

// rate_limit_rules[] — fine-grained per-URI / per-key rate limits
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

function addFingerprintRules(fieldName: string, fingerprints: unknown[], rulePrefix: string, metricPrefix: string) {
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
}

// JA3/JA4 fingerprint rules
addFingerprintRules('ja3_fingerprint', waf.ja3_fingerprints, 'ja3', 'ja3');
addFingerprintRules('ja4_fingerprint', waf.ja4_fingerprints, 'ja4', 'ja4');

const ruleGroupDef: any = {
  name: projectName + '-rate-limit',
  scope,
  capacity: Math.max(2, wafRules.length * 2 || 2),
  rule: wafRules,
  visibility_config: {
    cloudwatch_metrics_enabled: true,
    metric_name: projectName + '-rule-group',
    sampled_requests_enabled: true,
  },
};
if (blockResponse) {
  ruleGroupDef.custom_response_body = [{
    key: blockResponseKey,
    content: blockResponse.body || 'Forbidden',
    content_type: blockResponse.content_type || 'TEXT_PLAIN',
  }];
}
const tfWafJson: any = {
  resource: {
    aws_wafv2_rule_group: {
      [projectName + '-rate-limit']: ruleGroupDef,
    },
  },
};

// Add managed rules if present (as a separate web_acl reference)
if (waf.managed_rules && waf.managed_rules.length > 0) {
  if (outputMode === 'rule-group') {
    console.log('[INFO] output-mode=rule-group: skipping aws_wafv2_web_acl generation.');
    console.log('[INFO] managed_rules are intentionally not emitted because AWS managed rule groups can only be attached from Web ACL.');
  } else {
    const webAclName = projectName + '-waf-acl';
    const webAcl: any = {
      name: webAclName,
      scope,
      default_action: { allow: {} },
      rule: waf.managed_rules.map((ruleName: string, idx: number) => ({
        name: `AWS-${ruleName}`,
        priority: 10 + idx,
        override_action: { none: {} },
        statement: {
          managed_rule_group_statement: {
            vendor_name: 'AWS',
            name: ruleName,
          },
        },
        visibility_config: {
          cloudwatch_metrics_enabled: true,
          metric_name: `${projectName}-${ruleName}`,
          sampled_requests_enabled: true,
        },
      })),
      visibility_config: {
        cloudwatch_metrics_enabled: true,
        metric_name: webAclName,
        sampled_requests_enabled: true,
      },
    };
    if (blockResponse) {
      webAcl.custom_response_body = [{
        key: blockResponseKey,
        content: blockResponse.body || 'Forbidden',
        content_type: blockResponse.content_type || 'TEXT_PLAIN',
      }];
    }
    tfWafJson.resource.aws_wafv2_web_acl = { [webAclName]: webAcl };

    // Logging configuration
    const logging = waf.logging || {};
    if (logging.enabled) {
      const arnEnv = logging.destination_arn_env || 'WAF_LOG_DESTINATION_ARN';
      const arnVarName = arnEnv.toLowerCase();
      tfWafJson.variable = tfWafJson.variable || {};
      tfWafJson.variable[arnVarName] = {
        description: `WAF log destination ARN (Kinesis Firehose / S3 / CloudWatch Logs). Sourced from $${arnEnv}.`,
        type: 'string',
      };
      const redactedFields = (logging.redacted_fields || []).map((field: string) => {
        if (field === 'authorization' || field === 'cookie' || field === 'x-api-key' || field === 'x-csrf-token' || field === 'set-cookie') {
          return { single_header: { name: field } };
        }
        return { single_header: { name: field } };
      });
      tfWafJson.resource.aws_wafv2_logging_configuration = {
        [webAclName + '-logging']: {
          log_destination_configs: ['${var.' + arnVarName + '}'],
          resource_arn: '${aws_wafv2_web_acl.' + webAclName + '.arn}',
          redacted_fields: redactedFields,
        },
      };
    }
  }
}

fs.writeFileSync(path.join(distDir, 'waf-rules.tf.json'), JSON.stringify(tfWafJson, null, 2), 'utf8');
console.log('Build complete:', path.join(distDir, 'waf-rules.tf.json'));

// 2. Geo Restriction
if (geo.block_countries || geo.allow_countries) {
  const geoTfJson: any = {
    resource: {
      aws_wafv2_rule_group: {
        [projectName + '-geo-block']: {
          name: projectName + '-geo-block',
          scope,
          capacity: 1,
          rule: [{
            name: 'geo-block-rule',
            priority: 1,
            action: geo.block_countries ? { block: {} } : { allow: {} },
            statement: {
              geo_match_statement: {
                country_codes: geo.block_countries || geo.allow_countries,
              },
            },
            visibility_config: {
              cloudwatch_metrics_enabled: true,
              metric_name: projectName + '-geo-block',
              sampled_requests_enabled: true,
            },
          }],
          visibility_config: {
            cloudwatch_metrics_enabled: true,
            metric_name: projectName + '-geo-rule-group',
            sampled_requests_enabled: true,
          },
        },
      },
    },
  };

  // If allow_countries is used, we need to negate the statement
  if (geo.allow_countries) {
    geoTfJson.resource.aws_wafv2_rule_group[projectName + '-geo-block'].rule[0].action = { block: {} };
    geoTfJson.resource.aws_wafv2_rule_group[projectName + '-geo-block'].rule[0].statement = {
      not_statement: {
        statement: {
          geo_match_statement: {
            country_codes: geo.allow_countries,
          },
        },
      },
    };
  }

  fs.writeFileSync(path.join(distDir, 'geo-restriction.tf.json'), JSON.stringify(geoTfJson, null, 2), 'utf8');
  console.log('Build complete:', path.join(distDir, 'geo-restriction.tf.json'));
}

// 3. IP Sets
if (ip.allowlist || ip.blocklist) {
  const ipTfJson: any = { resource: {} };

  if (ip.blocklist && ip.blocklist.length > 0) {
    ipTfJson.resource.aws_wafv2_ip_set = ipTfJson.resource.aws_wafv2_ip_set || {};
    ipTfJson.resource.aws_wafv2_ip_set[projectName + '-ip-blocklist'] = {
      name: projectName + '-ip-blocklist',
      scope,
      ip_address_version: 'IPV4',
      addresses: ip.blocklist,
    };

    ipTfJson.resource.aws_wafv2_rule_group = ipTfJson.resource.aws_wafv2_rule_group || {};
    ipTfJson.resource.aws_wafv2_rule_group[projectName + '-ip-block'] = {
      name: projectName + '-ip-block',
      scope,
      capacity: 1,
      rule: [{
        name: 'ip-blocklist-rule',
        priority: 1,
        action: { block: {} },
        statement: {
          ip_set_reference_statement: {
            arn: '${aws_wafv2_ip_set.' + projectName + '-ip-blocklist.arn}',
          },
        },
        visibility_config: {
          cloudwatch_metrics_enabled: true,
          metric_name: projectName + '-ip-blocklist',
          sampled_requests_enabled: true,
        },
      }],
      visibility_config: {
        cloudwatch_metrics_enabled: true,
        metric_name: projectName + '-ip-block-group',
        sampled_requests_enabled: true,
      },
    };
  }

  if (ip.allowlist && ip.allowlist.length > 0) {
    ipTfJson.resource.aws_wafv2_ip_set = ipTfJson.resource.aws_wafv2_ip_set || {};
    ipTfJson.resource.aws_wafv2_ip_set[projectName + '-ip-allowlist'] = {
      name: projectName + '-ip-allowlist',
      scope,
      ip_address_version: 'IPV4',
      addresses: ip.allowlist,
    };

    ipTfJson.resource.aws_wafv2_rule_group = ipTfJson.resource.aws_wafv2_rule_group || {};
    ipTfJson.resource.aws_wafv2_rule_group[projectName + '-ip-allow'] = {
      name: projectName + '-ip-allow',
      scope,
      capacity: 1,
      rule: [{
        name: 'ip-allowlist-rule',
        priority: 1,
        action: { allow: {} },
        statement: {
          ip_set_reference_statement: {
            arn: '${aws_wafv2_ip_set.' + projectName + '-ip-allowlist.arn}',
          },
        },
        visibility_config: {
          cloudwatch_metrics_enabled: true,
          metric_name: projectName + '-ip-allowlist',
          sampled_requests_enabled: true,
        },
      }],
      visibility_config: {
        cloudwatch_metrics_enabled: true,
        metric_name: projectName + '-ip-allow-group',
        sampled_requests_enabled: true,
      },
    };
  }

  fs.writeFileSync(path.join(distDir, 'ip-sets.tf.json'), JSON.stringify(ipTfJson, null, 2), 'utf8');
  console.log('Build complete:', path.join(distDir, 'ip-sets.tf.json'));
}

// 4. Transport (TLS/HTTP) Settings
if (transport.tls || transport.http) {
  const tlsPolicy = transport.tls?.security_policy || 'TLSv1.2_2021';
  const httpVersions = transport.http?.versions || ['http2'];

  // Map versions to CloudFront http_version
  let httpVersion = 'http2';
  if (httpVersions.includes('http3') && httpVersions.includes('http2')) {
    httpVersion = 'http2and3';
  } else if (httpVersions.includes('http3')) {
    httpVersion = 'http3';
  } else if (httpVersions.includes('http1.1')) {
    httpVersion = 'http1.1';
  }

  const transportTfJson = {
    locals: {
      cdn_security_transport: {
        viewer_certificate: {
          minimum_protocol_version: tlsPolicy,
        },
        http_version: httpVersion,
      },
    },
  };

  fs.writeFileSync(path.join(distDir, 'cloudfront-settings.tf.json'), JSON.stringify(transportTfJson, null, 2), 'utf8');
  console.log('Build complete:', path.join(distDir, 'cloudfront-settings.tf.json'));
}

// 5. Origin Settings (timeout)
if (origin.timeout) {
  const originTfJson = {
    locals: {
      cdn_security_origin_config: {
        connection_timeout: origin.timeout.connect || 10,
        read_timeout: origin.timeout.read || 30,
      },
    },
  };

  fs.writeFileSync(path.join(distDir, 'cloudfront-origin.tf.json'), JSON.stringify(originTfJson, null, 2), 'utf8');
  console.log('Build complete:', path.join(distDir, 'cloudfront-origin.tf.json'));
}
