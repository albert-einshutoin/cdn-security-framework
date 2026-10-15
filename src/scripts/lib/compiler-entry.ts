import path from 'node:path';
import { parseArgs, hasFlag, loadPolicyWithWarnings, reportPolicyWarnings } from './policy-io';

export type CompilerOptions = {
  outDir: string;
  rootDir?: string;
  env?: NodeJS.ProcessEnv;
  logger?: Pick<Console, 'log' | 'error' | 'warn'>;
  allowPlaceholderToken?: boolean;
  failOnPermissive?: boolean;
  strictOriginAuth?: boolean;
  failOnWafApproximation?: boolean;
  outputMode?: string;
  ruleGroupOnly?: boolean;
};

// CLI adapters load once; programmatic callers pass their validated snapshot.
export function runCompilerCli(compile: (policy: any, options: CompilerOptions) => unknown, argv = process.argv.slice(2)): void {
  const rootDir = path.join(__dirname, '..', '..');
  try {
    const { policyPath, outDir } = parseArgs(argv, rootDir, { consumeOutputMode: true });
    const parsed = loadPolicyWithWarnings(policyPath);
    reportPolicyWarnings(parsed.warnings, policyPath);
    const outputModeAt = argv.indexOf('--output-mode');
    compile(parsed.policy, { rootDir, outDir,
      allowPlaceholderToken: hasFlag(argv, '--allow-placeholder-token'),
      failOnPermissive: hasFlag(argv, '--fail-on-permissive'),
      strictOriginAuth: hasFlag(argv, '--strict-origin-auth'),
      failOnWafApproximation: !hasFlag(argv, '--allow-waf-approximation'),
      ruleGroupOnly: hasFlag(argv, '--rule-group-only'),
      outputMode: outputModeAt < 0 ? 'full' : argv[outputModeAt + 1],
    });
  } catch (error: unknown) {
    console.error('Error:', (error as Error).message);
    const details = (error as { validationErrors?: string[] }).validationErrors;
    if (details) for (const detail of details) console.error('  -', detail);
    process.exitCode = 1;
  }
}
