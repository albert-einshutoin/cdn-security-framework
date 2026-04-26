/**
 * Programmatic API: compile
 *
 * Build edge runtime + infra config from a policy file. Stable public
 * contract. Internally delegates to the existing compiler scripts via
 * spawnSync (see note in lib/index.js); that will be replaced by in-process
 * module boundaries in #69 without changing this surface.
 *
 * Input:
 *   {
 *     policyPath:       string,     // required, absolute or relative to cwd
 *     outDir:           string,     // required, absolute or relative to cwd
 *     target:           'aws' | 'cloudflare',
 *     failOnPermissive?: boolean,
 *     failOnWafApproximation?: boolean,           // Cloudflare only
 *     outputMode?:      'full' | 'rule-group',   // AWS only
 *     ruleGroupOnly?:   boolean,                  // AWS only
 *     cwd?:             string,     // defaults to process.cwd()
 *     pkgRoot?:         string,     // defaults to installed package root
 *     env?:             NodeJS.ProcessEnv,
 *   }
 *
 * Output:
 *   {
 *     ok:         boolean,
 *     errors:     string[],
 *     warnings:   string[],
 *     edgeFiles:  string[],    // absolute paths to emitted edge code
 *     infraFiles: string[],    // absolute paths to emitted infra config
 *     policyPath: string,      // resolved policy path
 *     outDir:     string,      // resolved output dir
 *     target:     string,
 *   }
 */
export {};
