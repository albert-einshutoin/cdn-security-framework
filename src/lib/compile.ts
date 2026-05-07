/**
 * Programmatic API: compile
 *
 * Build edge runtime + infra config from a policy file. Stable public
 * contract; emission is delegated to the compiler emitter phase so the API no
 * longer owns script orchestration details directly.
 */

const { compileArtifacts } = require('../emitter');

type CompileTarget = 'aws' | 'cloudflare';

interface CompileOptions {
  policyPath?: string;
  outDir?: string;
  target?: CompileTarget;
  failOnPermissive?: boolean;
  failOnWafApproximation?: boolean;
  allowPlaceholderToken?: boolean;
  outputMode?: string;
  ruleGroupOnly?: boolean;
  cwd?: string;
  pkgRoot?: string;
  env?: NodeJS.ProcessEnv;
}

function compile(opts: CompileOptions = {}) {
  return compileArtifacts(opts);
}

module.exports = { compile };
