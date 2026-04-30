const fs = require('fs');
const yaml = require('js-yaml');

export type ParsePolicyOptions = {
  policyPath?: string;
};

export type ParsePolicyResult = {
  ok: boolean;
  errors: string[];
  policy: any | null;
};

export function parsePolicyFile(opts: ParsePolicyOptions = {}): ParsePolicyResult {
  const policyPath = opts && opts.policyPath;
  if (!policyPath) {
    return { ok: false, errors: ['policyPath is required'], policy: null };
  }

  try {
    const policy = yaml.load(fs.readFileSync(policyPath, 'utf8'));
    return { ok: true, errors: [], policy };
  } catch (e: any) {
    if (e && e.code === 'ENOENT') {
      return { ok: false, errors: [`policy file not found: ${policyPath}`], policy: null };
    }
    return {
      ok: false,
      errors: [`failed to parse policy YAML: ${e && e.message ? e.message : String(e)}`],
      policy: null,
    };
  }
}
