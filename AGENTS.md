# Repository validation commands

TypeScript under `src/` is authoritative; do not edit generated JavaScript.

| Purpose | Command |
|---|---|
| TypeScript build / types | `npm run build:ts` / `npm run typecheck` |
| Complete validation, independent of impact planner | `npm run test:ci` |
| Native Cloudflare HTTP / JWKS E2E, also included in complete validation | `npm run test:cloudflare-http-e2e` |
| PR impact plan / execution | `npm run impact:analyze -- --base <base> --head <head> --output <analysis>` / `npm run impact:run -- --analysis <analysis> --output <report>` |
| Package artifact gate tests | `node scripts/single-pack-unit-tests.js` after build |
| Opt-in internal finite auth/cache model regression gate | `node scripts/auth-cache-regression.js <repo-root> <base-commit> <head-commit> <bundle-relative-path>` after build; exact SHA1 commits, head must be repo HEAD; exit 0 PASS / 1 required VIOLATED or UNKNOWN / 2 Error; no Cloud or automatic product CI wiring |
| Next.js advisory check (local or scheduled consumer CI) | `node bin/cli.js advisory check --package-json package.json --package-lock package-lock.json --deployment self-hosted --workspace-root .` after build; requires a matching direct production Next.js dependency and HTTPS to GitHub |
| Release approval, workflow permissions and artifact binding checks | `node scripts/release-binding-unit-tests.js` after build; does not publish |
| Single-pack producer / consumer / aggregate | `node scripts/single-pack.js produce <artifact-dir>` / `consume <artifact-dir> <row> <result>` / `aggregate <artifact-dir> <results-dir> <summary>` |

Single-pack commands require the fixed `CSF_SOURCE`, `GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT`. Consumers and aggregate also require the producer's `CSF_TGZ_SHA256`. The aggregate requires successful producer/consumer job states. See the EN/JA Node support sections for evidence and offline preparation. Existing parent approval and safety rules continue to apply.

The opt-in model gate requires Git with `--no-lazy-fetch` support and a committed bundle v1 containing both explicit model v2 providers. Missing promisor objects fail without fetching. Git/model work shares a 2-second budget; model evaluation uses a bounded Worker and resource exhaustion is Error 2. This does not change existing CI or public CLI exit contracts.
