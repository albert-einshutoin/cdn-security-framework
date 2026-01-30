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
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--policy' && argv[i + 1]) { policyPath = argv[++i]; continue; }
  if (argv[i] === '--out-dir' && argv[i + 1]) { outDir = argv[++i]; continue; }
  if (!argv[i].startsWith('--')) { policyPath = argv[i]; }
}

let policy;
try {
  const content = fs.readFileSync(policyPath, 'utf8');
  policy = yaml.load(content);
} catch (e) {
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

// Rate limit rule
if (waf.rate_limit) {
  wafRules.push({
    name: 'rate-based-rule',
    priority: priority++,
    action: { block: {} },
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

const tfWafJson = {
  resource: {
    aws_wafv2_rule_group: {
      [projectName + '-rate-limit']: {
        name: projectName + '-rate-limit',
        scope,
        capacity: 2,
        rule: wafRules,
        visibility_config: {
          cloudwatch_metrics_enabled: true,
          metric_name: projectName + '-rule-group',
          sampled_requests_enabled: true,
        },
      },
    },
  },
};

// Add managed rules if present (as a separate web_acl reference)
if (waf.managed_rules && waf.managed_rules.length > 0) {
  tfWafJson.resource.aws_wafv2_web_acl = {
    [projectName + '-waf-acl']: {
      name: projectName + '-waf-acl',
      scope,
      default_action: { allow: {} },
      rule: waf.managed_rules.map((ruleName, idx) => ({
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
        metric_name: projectName + '-waf-acl',
        sampled_requests_enabled: true,
      },
    },
  };
}

fs.writeFileSync(path.join(distDir, 'waf-rules.tf.json'), JSON.stringify(tfWafJson, null, 2), 'utf8');
console.log('Build complete:', path.join(distDir, 'waf-rules.tf.json'));

// 2. Geo Restriction
if (geo.block_countries || geo.allow_countries) {
  const geoTfJson = {
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
  const ipTfJson = { resource: {} };
  
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
