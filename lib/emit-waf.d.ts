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
export {};
