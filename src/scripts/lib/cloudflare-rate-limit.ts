import { createHash } from 'node:crypto';

// Local configuration profiles, not account entitlement or deployed-WAF proof.
// API discrete values and plan limits checked 2026-10-13:
// https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/
// https://developers.cloudflare.com/waf/rate-limiting-rules/#availability
export function buildCloudflareRateRules(waf: any = {}): any[] {
  const fail = (reason: string): never => { throw new Error('CLOUDFLARE_RATE_LIMIT_INVALID: ' + reason); };
  if (!waf || typeof waf !== 'object' || Array.isArray(waf)) fail('WAF rate configuration must be an object');
  const periods = [10, 60, 120, 300, 600];
  const mitigations = [10, 60, 120, 300, 600, 3600, 86400];
  const plan = waf.cloudflare_rate_limit_plan;
  if (plan !== undefined && !['free', 'business'].includes(plan)) fail('supported plans are free and business');
  const declaredPeriod = waf.cloudflare_rate_limit_period;
  if (declaredPeriod !== undefined && !periods.includes(declaredPeriod)) fail('unsupported discrete counting period');
  const mitigation = waf.rate_limit_mitigation_timeout === undefined ? 10 : waf.rate_limit_mitigation_timeout;
  if (mitigation === 0) fail('mitigation 0 is block throttling, which requires Enterprise; free/business support positive block durations only');
  if (!mitigations.includes(mitigation)) fail('unsupported discrete mitigation timeout');
  const threshold = (n: any) => {
    if (!Number.isInteger(n) || n < 100 || n > 2000000000) fail('threshold must be an integer from 100 to 2000000000');
    return n;
  };
  const hasGlobal = waf.rate_limit !== undefined;
  const entries = waf.rate_limit_rules === undefined ? [] : waf.rate_limit_rules;
  if (!Array.isArray(entries)) fail('rate_limit_rules must be an array');
  if (hasGlobal) threshold(waf.rate_limit);
  const count = (hasGlobal ? 1 : 0) + entries.length;
  if (plan === 'free' && ((declaredPeriod !== undefined && declaredPeriod !== 10) || mitigation !== 10)) fail('Free requires period 10 and mitigation timeout 10');
  if (count === 0) return [];
  if (plan === undefined) fail('explicit cloudflare_rate_limit_plan is required');
  if (plan === 'free' && declaredPeriod === undefined) fail('Free requires an explicit 10-second counting period and chosen threshold');
  const period = declaredPeriod === undefined ? 300 : declaredPeriod;
  if (plan === 'free' && (period !== 10 || mitigation !== 10)) fail('Free requires period 10 and mitigation timeout 10');
  if (count > (plan === 'free' ? 1 : 5)) fail('generated global plus individual rule count exceeds the selected profile');
  const validateExpression = (expression: any): string => {
    if (typeof expression !== 'string' || expression.length > 4096) fail('unsupported expression');
    if (expression === 'true') return expression;
    const field = '(?:http\\.request\\.uri\\.path|lower\\(http\\.request\\.uri\\.path\\))';
    const literal = '("(?:[^"\\\\]|\\\\.)*")';
    const match = new RegExp('^starts_with\\(' + field + ',\\s*' + literal + '\\)$').exec(expression)
      || new RegExp('^' + field + '\\s+eq\\s+' + literal + '$').exec(expression);
    if (!match) fail('only true or a single URI-path eq/starts_with expression is supported');
    let value: any;
    try { value = JSON.parse(match![1]); } catch { fail('invalid expression string'); }
    if (JSON.stringify(value) !== match![1]) fail('expression path string must use canonical JSON quoting');
    if (!value.startsWith('/') || value.length > 2048 || /[\x00-\x1f\x7f]/.test(value)) fail('invalid URI-path literal');
    return expression;
  };
  const scopeExpression = (rule: any): string => {
    if (rule.expression_cloudflare !== undefined) return validateExpression(rule.expression_cloudflare);
    const sd = rule.scope_down_statement;
    if (sd === undefined) return 'true';
    if (!sd || typeof sd !== 'object' || Array.isArray(sd)) fail('invalid scope_down_statement');
    if (Object.keys(sd).length === 0) return 'true';
    const bm = sd?.byte_match_statement;
    if (!bm || Object.keys(sd).length !== 1 || bm.positional_constraint !== 'STARTS_WITH'
      || Object.keys(bm).some(k => !['positional_constraint', 'field_to_match', 'search_string', 'text_transformation'].includes(k))
      || !bm.field_to_match?.uri_path || Object.keys(bm.field_to_match).join() !== 'uri_path'
      || typeof bm.field_to_match.uri_path !== 'object' || Array.isArray(bm.field_to_match.uri_path) || Object.keys(bm.field_to_match.uri_path).length !== 0
      || typeof bm.search_string !== 'string') fail('unsupported scope_down_statement; supply a supported exact Cloudflare path expression');
    const transforms = bm.text_transformation;
    let field = 'http.request.uri.path';
    if (transforms !== undefined) {
      if (!Array.isArray(transforms) || transforms.length !== 1 || transforms[0]?.priority !== 0
        || Object.keys(transforms[0]).some(k => !['priority', 'type'].includes(k))
        || !['NONE', 'LOWERCASE'].includes(transforms[0]?.type)) fail('unsupported path text transformation');
      if (transforms[0].type === 'LOWERCASE') field = 'lower(' + field + ')';
    }
    return validateExpression('starts_with(' + field + ', ' + JSON.stringify(bm.search_string) + ')');
  };
  const br = waf.block_response;
  let response: any = null;
  if (br !== undefined) {
    if (!br || typeof br !== 'object' || Array.isArray(br)) fail('invalid block response');
    if (Object.keys(br).some(k => !['status_code', 'body', 'content_type'].includes(k))) fail('unsupported block response field');
    const status = br.status_code === undefined ? 403 : br.status_code;
    const body = br.body === undefined ? 'blocked' : br.body;
    const contentType = br.content_type === undefined ? 'TEXT_PLAIN' : br.content_type;
    if (!Number.isInteger(status) || status < 400 || status > 499 || typeof body !== 'string'
      || Buffer.byteLength(body) > 30000 || !['TEXT_PLAIN', 'TEXT_HTML', 'APPLICATION_JSON'].includes(contentType)) fail('rate-limit block response requires 400..499, supported MIME and at most 30000 bytes');
    response = { status_code: status, content: body, content_type: { TEXT_PLAIN: 'text/plain', TEXT_HTML: 'text/html', APPLICATION_JSON: 'application/json' }[contentType as 'TEXT_PLAIN'] };
  }
  const make = (name: string, limit: number, expression: string) => ({
    description: name, enabled: true, expression, action: 'block', action_parameters: { response },
    ratelimit: { characteristics: ['cf.colo.id', 'ip.src'], period, requests_per_period: limit, mitigation_timeout: mitigation },
  });
  const rules: any[] = hasGlobal ? [make('Global IP rate limit', waf.rate_limit, 'true')] : [];
  const priorities = new Set<number>();
  for (const [index, rule] of entries.entries()) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)
      || typeof rule.name !== 'string' || !/^[a-zA-Z0-9-]{1,64}$/.test(rule.name)) fail('individual rule requires a valid name and threshold');
    if (Object.keys(rule).some(k => !['name', 'limit', 'action', 'aggregate_key_type', 'custom_keys', 'cloudflare_characteristics', 'expression_cloudflare', 'scope_down_statement', 'priority'].includes(k))) fail('unsupported individual rule field');
    const priority = rule.priority === undefined ? index + 1 : rule.priority;
    if (!Number.isInteger(priority) || priority < 1 || priority > 10000 || priorities.has(priority)) fail('individual priorities must be unique integers from 1 to 10000');
    priorities.add(priority);
    if (rule.action !== undefined && rule.action !== 'block') fail('only block rate-limit action is supported');
    if (rule.aggregate_key_type !== undefined && rule.aggregate_key_type !== 'IP') fail('only IP rate-limit aggregation is supported');
    if (rule.custom_keys !== undefined) fail('custom rate-limit keys are unsupported');
    if (rule.cloudflare_characteristics !== undefined) {
      const chars = rule.cloudflare_characteristics;
      if (!Array.isArray(chars) || chars.length === 0 || new Set(chars).size !== chars.length
        || !chars.includes('ip.src') || chars.some((c: any) => c !== 'ip.src' && c !== 'cf.colo.id')) fail('characteristics must contain IP and only optional cf.colo.id');
    }
    rules.push({ ...make(rule.name, threshold(rule.limit), scopeExpression(rule)), priority });
  }
  const global = hasGlobal ? rules.shift() : undefined;
  rules.sort((a, b) => a.priority - b.priority);
  for (const rule of rules) delete rule.priority;
  return global ? [global, ...rules] : rules;
}

export function assessCloudflareFreeWaf(resources: unknown, inventoryText?: string, referenceTimeMs = Date.now()) {
  function invalid(reason: string): never { throw new Error('CLOUDFLARE_FREE_INVALID: ' + reason); }
  const object = (value: unknown): value is Record<string, any> => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  if (!object(resources) || !Number.isSafeInteger(referenceTimeMs) || referenceTimeMs < 0) invalid('INPUT');
  const reasons = new Set<string>(['LIVE_DEPLOYMENT_UNVERIFIED', 'POLICY_COVERAGE_UNVERIFIED']);
  let unsupported = false, unknown = false, custom = 0, rate = 0, customSets = 0;
  const reject = (reason: string, known = false) => { reasons.add(reason); if (known) unsupported = true; else unknown = true; };
  const customExpression = (expression: unknown) => {
    if (typeof expression !== 'string' || Buffer.byteLength(expression) > 4096) return false;
    let valid = true;
    const stripped = expression.replace(/"(?:[^"\\\x00-\x1f]|\\.)*"/g, literal => {
      try {
        const value = JSON.parse(literal);
        if (JSON.stringify(value) !== literal || /[\x00-\x1f\x7f]/.test(value)) valid = false;
      } catch { valid = false; }
      return '""';
    });
    if (/\bmatches\b/.test(stripped)) reject('REGEX_NOT_FREE', true);
    if (/\bcf\.bot_management\./.test(stripped)) reject('BOT_MANAGEMENT_NOT_FREE', true);
    // Full emitted shapes, after validating/removing literals. Keywords inside UA
    // strings cannot introduce operators or manufacture a paid-feature finding.
    return valid && (/^(?:not )?\(ip\.geoip\.country in \{""(?: "")*\}\)$/.test(stripped)
      || /^\(lower\(http\.user_agent\) contains ""(?: or lower\(http\.user_agent\) contains "")*\)$/.test(stripped));
  };
  for (const [type, entries] of Object.entries(resources as Record<string, unknown>)) {
    if (!object(entries) || Object.keys(entries).length > 16) invalid('RESOURCE_SHAPE_OR_LIMIT');
    if (type === 'cloudflare_logpush_job') { reject('METERED_RESOURCE_NOT_ALLOWED', true); continue; }
    if (type !== 'cloudflare_ruleset') { reject('RESOURCE_NOT_SUPPORTED'); continue; }
    for (const set of Object.values(entries)) {
      if (!object(set) || !Array.isArray(set.rules) || set.rules.length > 1000) invalid('RULESET_SHAPE_OR_LIMIT');
      if (set.kind !== 'zone') reject('SCOPE_NOT_SUPPORTED');
      const isCustom = set.phase === 'http_request_firewall_custom';
      const isRate = set.phase === 'http_ratelimit';
      if (isCustom) { custom += set.rules.length; customSets++; }
      else if (isRate) rate += set.rules.length;
      else { reject('PHASE_NOT_SUPPORTED'); continue; }
      for (const rule of set.rules) {
        if (!object(rule)) invalid('RULE_SHAPE');
        if (rule.action === 'log') reject('LOG_ACTION_NOT_FREE', true);
        else if (rule.action !== 'block') reject('ACTION_NOT_SUPPORTED');
        if (Object.keys(rule).some(k => !['ref', 'description', 'enabled', 'expression', 'action', 'action_parameters', ...(isRate ? ['ratelimit'] : [])].includes(k))) reject('RULE_FIELD_NOT_SUPPORTED');
        if (!object(rule.action_parameters) || Object.keys(rule.action_parameters).join() !== 'response' || rule.action_parameters.response !== null) reject('ACTION_PARAMETERS_NOT_SUPPORTED');
        if (isCustom) {
          if (!customExpression(rule.expression)) reject('EXPRESSION_NOT_SUPPORTED');
        } else {
          const limit = rule.ratelimit;
          if (!object(limit) || Object.keys(limit).sort().join() !== 'characteristics,mitigation_timeout,period,requests_per_period') { reject('RATE_FIELDS_NOT_SUPPORTED'); continue; }
          if (limit.period !== 10 || limit.mitigation_timeout !== 10) reject('RATE_WINDOW_NOT_FREE', true);
          try {
            // Reuse the canonical Free rate validator, including its expression
            // subset, rather than adding another rate-profile interpretation.
            buildCloudflareRateRules({ cloudflare_rate_limit_plan: 'free', cloudflare_rate_limit_period: limit.period,
              rate_limit_mitigation_timeout: limit.mitigation_timeout, rate_limit_rules: [{ name: 'preflight', limit: limit.requests_per_period,
                action: rule.action, cloudflare_characteristics: limit.characteristics, expression_cloudflare: rule.expression }] });
          } catch { reject('RATE_CONFIGURATION_NOT_SUPPORTED'); }
        }
      }
    }
  }
  if (custom > 5) reject('CUSTOM_RULE_LIMIT_EXCEEDED', true);
  if (customSets > 1) reject('CUSTOM_RULESET_LIMIT_EXCEEDED', true);
  if (rate > 1) reject('RATE_RULE_LIMIT_EXCEEDED', true);

  let existingCustom: number | null = null, existingRate: number | null = null, capturedAtMs: number | null = null;
  let inventoryComplete = false;
  if (inventoryText === undefined) reasons.add('INVENTORY_MISSING');
  else {
    if (typeof inventoryText !== 'string' || Buffer.byteLength(inventoryText) > 8192) invalid('INVENTORY_BYTES');
    let data: unknown;
    try { data = JSON.parse(inventoryText); } catch { invalid('INVENTORY_JSON'); }
    if (!object(data) || data.scope !== 'saved-cloudflare-free-inventory' || !Number.isSafeInteger(data.version) || data.version < 1) invalid('INVENTORY_SCOPE_OR_VERSION');
    if (data.version !== 1) reasons.add('INVENTORY_VERSION_UNSUPPORTED');
    else {
      const keys = ['version', 'scope', 'capturedAtMs', 'complete', 'plan', 'existingCustomRules', 'existingRateRules'];
      if (Object.keys(data).length !== keys.length || keys.some(k => !Object.hasOwn(data, k))) invalid('INVENTORY_FIELDS');
      if (typeof data.complete !== 'boolean' || (data.plan !== null && data.plan !== 'free')
        || !Number.isSafeInteger(data.capturedAtMs) || data.capturedAtMs < 0 || data.capturedAtMs > referenceTimeMs) invalid('INVENTORY_TYPES_OR_TIME');
      for (const key of ['existingCustomRules', 'existingRateRules']) if (data[key] !== null && (!Number.isSafeInteger(data[key]) || data[key] < 0 || data[key] > 10000)) invalid('INVENTORY_COUNT');
      existingCustom = data.existingCustomRules; existingRate = data.existingRateRules; capturedAtMs = data.capturedAtMs;
      if (!data.complete) reasons.add('INVENTORY_PARTIAL');
      if (data.plan === null) reasons.add('INVENTORY_PLAN_UNKNOWN');
      if (existingCustom === null || existingRate === null) reasons.add('INVENTORY_COUNTS_UNKNOWN');
      if (referenceTimeMs - data.capturedAtMs > 86400000) reasons.add('INVENTORY_STALE');
      inventoryComplete = data.complete && data.plan === 'free' && existingCustom !== null && existingRate !== null && referenceTimeMs - data.capturedAtMs <= 86400000;
    }
  }
  // Unknown/partial/stale inventories never stand in for an empty account or
  // current capacity. Only the generated count is independently known then.
  const customExceeded = custom > 5 || (inventoryComplete && existingCustom !== null && custom + existingCustom > 5);
  const rateExceeded = rate > 1 || (inventoryComplete && existingRate !== null && rate + existingRate > 1);
  if (customExceeded) reasons.add('CUSTOM_RULE_CAPACITY_EXCEEDED');
  if (rateExceeded) reasons.add('RATE_RULE_CAPACITY_EXCEEDED');
  return Object.freeze({ version: 1, scope: 'local-cloudflare-free-preflight', checkedSpecificationDate: '2026-10-26',
    localGeneration: unsupported ? 'unsupported' : unknown ? 'unknown' : 'supported',
    savedCapacity: customExceeded || rateExceeded ? 'exceeded' : inventoryComplete ? 'fits' : 'unknown',
    liveDeployment: 'unknown', policyCoverage: 'unknown', reasons: Object.freeze([...reasons].sort()),
    generated: Object.freeze({ customRules: custom, rateRules: rate }),
    inventory: Object.freeze({ capturedAtMs, referenceTimeMs, existingCustomRules: existingCustom, existingRateRules: existingRate,
      inputSha256: inventoryText === undefined ? null : createHash('sha256').update(inventoryText).digest('hex') }),
  });
}
