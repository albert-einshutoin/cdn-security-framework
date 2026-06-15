export type PolicyLoadResult = {
    policy: any;
    warnings: string[];
};
export type CompilerArgs = {
    policyPath: string;
    outDir: string;
    allowPlaceholderToken: boolean;
    failOnPermissive: boolean;
    strictOriginAuth: boolean;
    failOnWafApproximation: boolean;
};
export type ParseArgsOptions = {
    consumeOutputMode?: boolean;
};
export type PolicyLoadError = Error & {
    code?: string;
};
/**
 * Resolve the default policy path under `rootDir`:
 *   `<rootDir>/policy/security.yml` if it exists, otherwise
 *   `<rootDir>/policy/base.yml`.
 *
 * Centralized so every entry point that resolves a default policy (the AWS
 * compiler, the Cloudflare compiler, the infra compiler, the Cloudflare WAF
 * compiler, and the CLI's inline fallback) makes the same choice. Issue #182.
 */
export declare function defaultPolicyPath(rootDir: string): string;
/**
 * Default output directory under `rootDir`: `<rootDir>/dist`.
 */
export declare function defaultOutDir(rootDir: string): string;
/**
 * Parse a compiler-style argv.
 *
 * Behavior preserved exactly from the pre-#182 inline copies:
 *   - default policy is `defaultPolicyPath(rootDir)`
 *   - default outDir is `defaultOutDir(rootDir)`
 *   - `--policy <value>` and `<positional>` compete for `policyPath`; the
 *     LAST one seen wins (so argv order between them matters: a positional
 *     that appears after `--policy` overrides the flag, and vice versa)
 *   - `--policy` without any following token is ignored. When a following
 *     token exists, it is consumed as the value, matching the old loop
 *   - `--out-dir <value>` sets `outDir`; same end-of-argv ignored rule
 *   - `--output-mode <value>` is only consumed when callers opt in via
 *     `{ consumeOutputMode: true }`. This keeps non-infra compilers on their
 *     legacy behavior where the value can still become a positional policy
 *     path, while letting infra-style emitters keep `rule-group` out of
 *     policyPath.
 *   - any other flag (including `--allow-placeholder-token`,
 *     `--fail-on-permissive`, `--strict-origin-auth`,
 *     `--fail-on-waf-approximation`, `--rule-group-only`, etc.) is ignored
 *     by the parser — flag detection is handled by the dedicated `has*`
 *     helpers in compile-core
 *   - boolean flags (any `--flag` with no following non-flag value) are
 *     treated as no-arg flags and skipped
 */
export declare function parseArgs(argv: string[], rootDir: string, options?: ParseArgsOptions): {
    policyPath: string;
    outDir: string;
};
export declare function parseCompilerArgs(argv: string[], rootDir: string): CompilerArgs;
export declare function hasFlag(argv: string[], flagName: string): boolean;
/**
 * Load a policy file and return the parsed policy. Wraps the lower-level
 * `loadPolicyWithWarnings` so callers that only care about the policy object
 * (and not the parser warnings) get a one-liner.
 */
export declare function loadPolicy(policyPath: string): any;
/**
 * Load a policy file and return both the parsed policy and any parser
 * warnings. Throws an Error with `code === 'ENOENT'` when the file is
 * missing (so callers can map that to a friendlier "policy file not found"
 * message) and a plain Error otherwise.
 */
export declare function loadPolicyWithWarnings(policyPath: string): PolicyLoadResult;
export declare function reportPolicyWarnings(warnings: string[], policyPath?: string, logger?: Pick<Console, 'warn'>): void;
export declare function reportPolicyLoadError(policyPath: string, error: unknown, logger?: Pick<Console, 'error'>): void;
