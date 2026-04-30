const fs = require('fs');
const yaml = require('js-yaml');

import type { CDNSecurityFrameworkPolicy } from '../types/policy';

export type ParsePolicyOptions = {
  policyPath?: string;
};

export type ParsePolicyResult = {
  ok: boolean;
  errors: string[];
  policy: Partial<CDNSecurityFrameworkPolicy> | null;
};

export function parsePolicyFile(opts: ParsePolicyOptions = {}): ParsePolicyResult {
  const policyPath = opts && opts.policyPath;
  if (!policyPath) {
    return { ok: false, errors: ['policyPath is required'], policy: null };
  }

  try {
    const policy = yaml.load(fs.readFileSync(policyPath, 'utf8')) as Partial<CDNSecurityFrameworkPolicy>;
    return { ok: true, errors: [], policy };
  } catch (e: unknown) {
    if (e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT') {
      return { ok: false, errors: [`policy file not found: ${policyPath}`], policy: null };
    }
    const message = e instanceof Error ? e.message : String(e);
    return {
      ok: false,
      errors: [`failed to parse policy YAML: ${message}`],
      policy: null,
    };
  }
}
