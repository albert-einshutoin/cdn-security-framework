"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildWafRules = buildWafRules;
const value_normalize_1 = require("./value-normalize");
const BLOCK_RESPONSE_BODY_KEY = 'cdn_sec_block';
function buildWafRules(waf = {}, projectName) {
    const rules = [];
    let priority = 1;
    const fingerprintActionType = waf.fingerprint_action === 'count' ? 'count' : 'block';
    const blockResponse = waf.block_response || null;
    const blockResponseKey = blockResponse ? BLOCK_RESPONSE_BODY_KEY : null;
    function blockAction() {
        if (blockResponseKey) {
            return {
                block: {
                    custom_response: {
                        response_code: (0, value_normalize_1.numberOr)(blockResponse.status_code, 403),
                        custom_response_body_key: blockResponseKey,
                    },
                },
            };
        }
        return { block: {} };
    }
    function actionFor(actionName) {
        if (actionName === 'count')
            return { count: {} };
        if (actionName === 'captcha')
            return { captcha: {} };
        return blockAction();
    }
    if (waf.rate_limit) {
        rules.push({
            name: 'rate-based-rule',
            priority: priority++,
            action: blockAction(),
            statement: {
                rate_based_statement: {
                    limit: (0, value_normalize_1.numberOr)(waf.rate_limit, 2000),
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
            if (!rule || !rule.name || !rule.limit)
                continue;
            const aggregateKeyType = rule.aggregate_key_type || 'IP';
            const rateStmt = {
                limit: Number(rule.limit),
                aggregate_key_type: aggregateKeyType,
            };
            if (aggregateKeyType === 'CUSTOM_KEYS' && Array.isArray(rule.custom_keys)) {
                rateStmt.custom_key = rule.custom_keys;
            }
            if (rule.scope_down_statement && typeof rule.scope_down_statement === 'object') {
                rateStmt.scope_down_statement = rule.scope_down_statement;
            }
            const rulePriority = (0, value_normalize_1.numberOr)(rule.priority, 0) || priority++;
            rules.push({
                name: rule.name,
                priority: rulePriority,
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
    function addFingerprintRules(fieldName, fingerprints, rulePrefix, metricPrefix) {
        if (!Array.isArray(fingerprints) || fingerprints.length === 0)
            return;
        for (const fp of fingerprints) {
            if (!fp)
                continue;
            const fpStr = String(fp);
            const slug = fpStr.slice(0, 12).toLowerCase();
            rules.push({
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
    addFingerprintRules('ja3_fingerprint', waf.ja3_fingerprints, 'ja3', 'ja3');
    addFingerprintRules('ja4_fingerprint', waf.ja4_fingerprints, 'ja4', 'ja4');
    return {
        rules,
        blockResponse,
        blockResponseKey,
        capacity: Math.max(2, rules.length * 2 || 2),
    };
}
