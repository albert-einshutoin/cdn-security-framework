/**
 * Programmatic API: migratePolicy
 *
 * v1 is the only shipped schema, so this is a no-op for v1 → v1. Reports
 * structured errors for unknown targets, missing versions, and unregistered
 * migration paths. The CLI `migrate` subcommand translates this into exit
 * codes 0/1/2.
 *
 * Input:
 *   {
 *     policyPath: string,
 *     toVersion?: number | string,   // default: 1
 *     cwd?:       string,
 *   }
 *
 * Output:
 *   {
 *     ok:          boolean,
 *     errors:      string[],
 *     warnings:    string[],
 *     fromVersion: number | undefined,
 *     toVersion:   number,
 *     migrated:    boolean,           // true iff a migration actually ran
 *     noop:        boolean,           // true iff already at target
 *     reservedExit2?: boolean,        // true for "no migration path registered" — CLI exits 2
 *   }
 */
export {};
