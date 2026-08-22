export const ROUTE_RELATIONS = [
  'definitely-covered',
  'definitely-disjoint',
  'possibly-overlapping',
  'unknown',
] as const;

export type RouteRelation = typeof ROUTE_RELATIONS[number];

export type OpenApiPath =
  | { kind: 'exact'; value: string }
  | { kind: 'template'; value: string };

export type PolicyPathMatcher =
  | { kind: 'exact'; value: string }
  | { kind: 'prefix'; value: string }
  | { kind: 'pattern'; syntax: 'regex'; value: string };

export type RouteHostMatcher =
  | { kind: 'any' }
  | { kind: 'allowlist'; values: readonly string[] }
  | { kind: 'unknown' };

export interface RouteRelationInput {
  path: OpenApiPath;
  methods: readonly string[];
  hosts: RouteHostMatcher;
}

export interface PolicyRelationInput {
  path: PolicyPathMatcher;
  methods: readonly string[];
  hosts: RouteHostMatcher;
}

export interface RouteRelationOptions {
  phase: 'normalized-path';
  collapseSlashes: boolean;
  removeDotSegments: boolean;
}

export interface RouteRelationResult {
  relation: RouteRelation;
  path: RouteRelation;
  method: RouteRelation;
  host: RouteRelation;
  isProvenDisjoint: boolean;
}

const MAX_VALUE_LENGTH = 16_384;
const MAX_CONDITION_VALUES = 256;
const MAX_CONDITION_CHARACTERS = 65_536;
const TEMPLATE_SEGMENT = /^\{[^{}\/]+\}$/;
const UNSAFE_PATH = /[\u0000-\u001f\u007f?#\\]|%(?:2e|2f|5c)/i;

function normalizePath(
  value: string,
  options: RouteRelationOptions,
  applyRequestNormalization: boolean,
): string | undefined {
  if (typeof value !== 'string'
    || value.length > MAX_VALUE_LENGTH
    || !value.startsWith('/')
    || UNSAFE_PATH.test(value)) return undefined;

  let normalized = applyRequestNormalization && options.collapseSlashes
    ? value.replace(/\/{2,}/g, '/')
    : value;
  if (applyRequestNormalization && options.removeDotSegments) {
    const segments: string[] = [];
    for (const segment of normalized.split('/')) {
      if (segment === '..') segments.pop();
      else if (segment !== '.') segments.push(segment);
    }
    normalized = segments.join('/') || '/';
    if (!normalized.startsWith('/')) return undefined;
  } else if (applyRequestNormalization
    && normalized.split('/').some((segment) => segment === '.' || segment === '..')) {
    return undefined;
  }
  return normalized;
}

function segments(value: string): string[] {
  return value.slice(1).split('/');
}

function templateParts(value: string): { parts: string[]; hasTemplate: boolean } | undefined {
  const parts = segments(value);
  let hasTemplate = false;
  for (const part of parts) {
    if (TEMPLATE_SEGMENT.test(part)) hasTemplate = true;
    else if (part.includes('{') || part.includes('}')) return undefined;
  }
  return { parts, hasTemplate };
}

function exactAgainstTemplate(exact: string, template: string): RouteRelation {
  const parsed = templateParts(template);
  if (!parsed) return 'unknown';
  const exactParts = segments(exact);
  if (exactParts.length !== parsed.parts.length) return 'definitely-disjoint';

  let uncertain = false;
  for (let index = 0; index < parsed.parts.length; index += 1) {
    const part = parsed.parts[index];
    if (TEMPLATE_SEGMENT.test(part)) {
      if (exactParts[index] === '') return 'definitely-disjoint';
      uncertain = true;
    } else if (part !== exactParts[index]) {
      return 'definitely-disjoint';
    }
  }
  return uncertain ? 'possibly-overlapping' : 'definitely-covered';
}

function templateAgainstPrefix(template: string, prefix: string): RouteRelation {
  const parsed = templateParts(template);
  if (!parsed) return 'unknown';
  if (!parsed.hasTemplate) {
    return template === prefix || template.startsWith(`${prefix}/`)
      ? 'definitely-covered'
      : 'definitely-disjoint';
  }

  const prefixParts = segments(prefix);
  if (prefixParts.length > parsed.parts.length) return 'definitely-disjoint';
  let uncertain = false;
  for (let index = 0; index < prefixParts.length; index += 1) {
    const part = parsed.parts[index];
    if (TEMPLATE_SEGMENT.test(part)) {
      if (prefixParts[index] === '') return 'definitely-disjoint';
      uncertain = true;
    } else if (part !== prefixParts[index]) {
      return 'definitely-disjoint';
    }
  }
  return uncertain ? 'possibly-overlapping' : 'definitely-covered';
}

function regexLiteral(value: string): string | undefined {
  if (!value.startsWith('^/') || !value.endsWith('$')) return undefined;
  const literal = value.slice(1, -1);
  return /[\\[\]().*+?{}|^$]/.test(literal) ? undefined : literal;
}

export function relatePath(
  source: OpenApiPath,
  policy: PolicyPathMatcher,
  options: RouteRelationOptions,
): RouteRelation {
  const sourcePath = normalizePath(source.value, options, true);
  let policyKind = policy.kind;
  let policyValue = normalizePath(policy.value, options, false);
  if (policy.kind === 'pattern') {
    const literal = regexLiteral(policy.value);
    if (!literal) return 'unknown';
    policyKind = 'exact';
    policyValue = normalizePath(literal, options, false);
  }
  if (!sourcePath || !policyValue) return 'unknown';

  if (source.kind === 'exact') {
    if (policyKind === 'exact') {
      return sourcePath === policyValue ? 'definitely-covered' : 'definitely-disjoint';
    }
    return sourcePath === policyValue || sourcePath.startsWith(`${policyValue}/`)
      ? 'definitely-covered'
      : 'definitely-disjoint';
  }
  if (policyKind === 'exact') return exactAgainstTemplate(policyValue, sourcePath);
  return templateAgainstPrefix(sourcePath, policyValue);
}

export function relateMethods(source: readonly string[], policy: readonly string[]): RouteRelation {
  if (source.length === 0 || !withinConditionBudget(source) || !withinConditionBudget(policy)) {
    return 'unknown';
  }
  const allowed = new Set(policy);
  const covered = new Set(source.filter((method) => allowed.has(method))).size;
  if (covered === 0) return 'definitely-disjoint';
  if (covered === new Set(source).size) return 'definitely-covered';
  return 'possibly-overlapping';
}

type HostRule = { kind: 'exact' | 'wildcard'; value: string };

function withinConditionBudget(values: readonly string[]): boolean {
  return values.length <= MAX_CONDITION_VALUES
    && values.every((value) => typeof value === 'string'
      && value.length > 0
      && value.length <= MAX_VALUE_LENGTH)
    && values.reduce((total, value) => total + value.length, 0) <= MAX_CONDITION_CHARACTERS;
}

function parseHostRule(value: string, stripRequestPort: boolean): HostRule | undefined {
  if (typeof value !== 'string' || value.length > MAX_VALUE_LENGTH) return undefined;
  let normalized = value.trim().toLowerCase();
  if (!normalized || /[\u0000-\u0020/\\\[\]]/.test(normalized)) return undefined;
  if (stripRequestPort) normalized = normalized.split(':')[0];
  if (normalized.startsWith('*.')) {
    const suffix = normalized.slice(2);
    return suffix && !suffix.includes('*') && !suffix.includes(':')
      ? { kind: 'wildcard', value: suffix }
      : undefined;
  }
  if (normalized.includes('*')) return undefined;
  return { kind: 'exact', value: normalized };
}

function wildcardMatches(host: string, suffix: string): boolean {
  return host.length > suffix.length + 1 && host.endsWith(`.${suffix}`);
}

function hostRuleRelation(source: HostRule, policy: readonly HostRule[]): RouteRelation {
  if (source.kind === 'exact') {
    return policy.some((rule) => rule.kind === 'exact'
      ? rule.value === source.value
      : wildcardMatches(source.value, rule.value))
      ? 'definitely-covered'
      : 'definitely-disjoint';
  }

  let overlaps = false;
  for (const rule of policy) {
    if (rule.kind === 'exact') {
      if (wildcardMatches(rule.value, source.value)) overlaps = true;
      continue;
    }
    if (source.value === rule.value || source.value.endsWith(`.${rule.value}`)) {
      return 'definitely-covered';
    }
    if (rule.value.endsWith(`.${source.value}`)) overlaps = true;
  }
  return overlaps ? 'possibly-overlapping' : 'definitely-disjoint';
}

export function relateHosts(source: RouteHostMatcher, policy: RouteHostMatcher): RouteRelation {
  if (source.kind === 'unknown' || policy.kind === 'unknown') return 'unknown';
  if (source.kind === 'allowlist' && !withinConditionBudget(source.values)) return 'unknown';
  if (policy.kind === 'allowlist' && !withinConditionBudget(policy.values)) return 'unknown';
  if (policy.kind === 'any') return 'definitely-covered';
  const policyRules = policy.values.map((value) => parseHostRule(value, false));
  if (policyRules.some((rule) => !rule)) return 'unknown';
  const validPolicyRules = policyRules as HostRule[];
  if (source.kind === 'any') {
    return validPolicyRules.length === 0 ? 'definitely-disjoint' : 'possibly-overlapping';
  }
  const sourceRules = source.values.map((value) => parseHostRule(value, true));
  if (sourceRules.length === 0 || sourceRules.some((rule) => !rule)) return 'unknown';
  const relations = (sourceRules as HostRule[]).map((rule) => hostRuleRelation(rule, validPolicyRules));
  if (relations.every((relation) => relation === 'definitely-covered')) return 'definitely-covered';
  if (relations.every((relation) => relation === 'definitely-disjoint')) return 'definitely-disjoint';
  return 'possibly-overlapping';
}

function combine(relations: readonly RouteRelation[]): RouteRelation {
  if (relations.includes('definitely-disjoint')) return 'definitely-disjoint';
  if (relations.every((relation) => relation === 'definitely-covered')) return 'definitely-covered';
  if (relations.includes('unknown')) return 'unknown';
  return 'possibly-overlapping';
}

export function relateRoute(
  source: RouteRelationInput,
  policy: PolicyRelationInput,
  options: RouteRelationOptions,
): RouteRelationResult {
  const path = relatePath(source.path, policy.path, options);
  const method = relateMethods(source.methods, policy.methods);
  const host = relateHosts(source.hosts, policy.hosts);
  const relation = combine([path, method, host]);
  return { relation, path, method, host, isProvenDisjoint: relation === 'definitely-disjoint' };
}
