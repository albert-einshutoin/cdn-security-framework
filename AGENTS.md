# Repository validation commands

TypeScript under `src/` is authoritative; do not edit generated JavaScript.

| Purpose | Command |
|---|---|
| TypeScript build / types | `npm run build:ts` / `npm run typecheck` |
| Complete validation, independent of impact planner | `npm run test:ci` |
| PR impact plan / execution | `npm run impact:analyze -- --base <base> --head <head> --output <analysis>` / `npm run impact:run -- --analysis <analysis> --output <report>` |
| Package artifact gate tests | `node scripts/single-pack-unit-tests.js` after build |
| Single-pack producer / consumer / aggregate | `node scripts/single-pack.js produce <artifact-dir>` / `consume <artifact-dir> <row> <result>` / `aggregate <artifact-dir> <results-dir> <summary>` |
| Dev-only Source-aware CI connection | Installed candidate's `node scripts/source-aware-ci.js run <config.json> <candidate-dir> <new-workspace-output-dir>`, then `publish <ci-record.json> <candidate-dir> <new-stage-dir>`, `verify-stage <ci-record.json> <candidate-dir> <delivery.json>` before upload, and `gate <ci-record.json> <candidate-dir> <delivery.json>` |

Single-pack commands require the fixed `CSF_SOURCE`, `GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT`. Consumers and aggregate also require the producer's `CSF_TGZ_SHA256`. The aggregate requires successful producer/consumer job states. See the EN/JA Node support sections for evidence and offline preparation. Existing parent approval and safety rules continue to apply.

`policy-lint.yml` runs complete validation on manual dispatch; PRs targeting `main` use impact selection plus shadow/full comparison, and package checks use the same producer. Its `source-aware-ci` job runs only for manual `dev/2.1-source-aware` or `feat/source-aware-ci/` refs, with the successful single-pack producer and acceptance as prerequisites. The job uses a synthetic fixture and the installed candidate, checks Summary/SARIF and exact staged bytes before uploading explicit files, and fails its final gate on analysis, output, transfer, stage, artifact, or prerequisite failure. The [dev CI guide](docs/source-aware-ci-dev.md) records the dispatch command and limits.
