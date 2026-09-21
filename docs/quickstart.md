# Quick Start

## 1. Install the unpublished schema2 candidate in an empty consumer

Published1.4.0 uses schema1. This guide targets the unpublished main schema2 candidate; see the [roadmap](ROADMAP.md). Obtain a tarball prepared by the candidate maintainer with `npm run build:ts` then `npm pack --ignore-scripts`, and verify its commit SHA and SHA-256. Bundled documentation changes also change the digest. The following consumer steps require no repository npm scripts, development checkout dependencies, global install or NODE_PATH.

```bash
# Set this to the verified tarball supplied with the candidate SHA and SHA-256.
export CANDIDATE_TARBALL=/path/to/verified-candidate.tgz
shasum -a 256 "$CANDIDATE_TARBALL"
mkdir consumer
cd consumer
npm init -y
npm install --save-dev "$CANDIDATE_TARBALL"
./node_modules/.bin/cdn-security --help
```

The retained `--version` value1.4.0 cannot distinguish this candidate from the published baseline. Only after2.0.0 is actually released may you replace the tarball install with `npm install --save-dev cdn-security-framework@2.0.0`. That future command is not claimed as tested here. Do not use npm latest to verify the candidate.

## 2. Profile init, lint and AWS build

```bash
./node_modules/.bin/cdn-security init --platform aws --profile balanced
export EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy
node node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
./node_modules/.bin/cdn-security build --policy policy/security.yml --target aws --out-dir dist/aws
```

All commands should exit0. Balanced allows GET/HEAD/POST and protects `/admin`, `/docs`, `/swagger` with the `x-edge-token` / `EDGE_ADMIN_TOKEN` static-token gate. The public synthetic value above is only for local fixtures, never production. Do not overwrite an existing policy with `--force`; use a new empty directory to repeat the guide.

`dist/aws/edge/` contains runtime artifacts; `dist/aws/infra/` contains IaC fragments. Build produces reviewable local files without cloud access or deployment. Edit Policy rather than generated JS or CFG.

## 3. Local HTTP fixtures

Save this JSON as `cases.json` in the empty consumer:

```json
{
  "fixtures": [
    {"name":"public GET","request":{"method":"GET","path":"/","headers":{"user-agent":"docs-fixture"}}},
    {"name":"PATCH rejected","request":{"method":"PATCH","path":"/","headers":{"user-agent":"docs-fixture"}}},
    {"name":"admin missing token","request":{"method":"GET","path":"/admin","headers":{"user-agent":"docs-fixture"}}},
    {"name":"admin valid synthetic token","request":{"method":"GET","path":"/admin","headers":{"user-agent":"docs-fixture","x-edge-token":"docs-fixture-token-not-for-deploy"}}},
    {"name":"POST JSON","request":{"method":"POST","path":"/api/items","headers":{"user-agent":"docs-fixture","Content-Type":"application/json"},"body":{"name":"synthetic-item"}}}
  ]
}
```

```bash
./node_modules/.bin/cdn-security playground --policy policy/security.yml --target aws --fixture cases.json --json
```

Expect CLI exit0 and, in fixture order:200/pass,405/block,401/block,200/pass,200/pass. A200 is local stub passage, not a production-origin guarantee. AWS viewer-request cannot read bodies: including POST JSON does not prove body inspection. Repository-only commands such as `npm run test:unit` are not needed in a consumer.

Auth gates require their referenced environment variables. `--allow-placeholder-token` is exclusively for non-production fixtures; never deploy placeholder artifacts. Cloudflare playground replaces external fetch with its existing stub and uses built-in non-production environment values. Do not reuse the AWS fixture's custom token unchanged against that stub. See the [CLI fixture contract](cli.md#playground).

## 4. Guided setup and Cloudflare JWT

Instead of a profile, `init --guided` selects application shape and authentication. It prompts in a TTY; this example closes stdin and supplies the selected configuration flags. Use a separate directory rather than overwriting the AWS policy:

```bash
mkdir cf-jwt
(
  cd cf-jwt
  ../node_modules/.bin/cdn-security init --guided --platform cloudflare \
    --app-shape rest-api --auth jwt --admin-paths /api \
    --cors-origins https://app.example.com --waf balanced \
    --geo-block '' --ip-allowlist '' --deployment build-only --project docs-jwt </dev/null
  node ../node_modules/cdn-security-framework/scripts/policy-lint.js policy/security.yml
  ../node_modules/.bin/cdn-security build --policy policy/security.yml --target cloudflare
)
```

Expect exit0. Generated JWT JWKS URL/issuer values at example.com are configuration examples; lint/build do not fetch real JWKS. This is not production authentication validation. Missing-token `/api` returns401 and public `/` returns200 through the existing playground stub. Valid JWT acceptance needs a separate local signing/JWKS fixture. AWS JWT/signed_url builds are unsupported and non-success; do not remove authentication to bypass the boundary. See [CLI init](cli.md#init).


```bash
cat > cf-jwt/cases.json <<'JSON'
{"fixtures":[{"name":"missing JWT","request":{"method":"GET","path":"/api","headers":{"user-agent":"docs-fixture"}}},{"name":"public","request":{"method":"GET","path":"/","headers":{"user-agent":"docs-fixture"}}}]}
JSON
./node_modules/.bin/cdn-security playground --policy cf-jwt/policy/security.yml --target cloudflare --fixture cf-jwt/cases.json --json
```

Expect exit0, then401/block and200/pass in fixture order.

## 5. OpenAPI to review

```bash
cp node_modules/cdn-security-framework/examples/openapi/openapi.yaml openapi.yaml
./node_modules/.bin/cdn-security openapi inspect --input openapi.yaml --workspace-root .
./node_modules/.bin/cdn-security openapi generate-policy --input openapi.yaml \
  --workspace-root . --profile balanced --out policy/openapi.candidate.yml
./node_modules/.bin/cdn-security contract diff --openapi openapi.yaml \
  --policy policy/security.yml --target aws --workspace-root . --fail-on never
```

Expect exit0. `--fail-on never` keeps this finding-review demo non-blocking; it is not advice to weaken a production CI gate. Candidate and `.meta.json` are review-only; active Policy is not overwritten, merged or applied. Review differences and omissions manually. Distinguish the repository workflow in the [OpenAPI guide](openapi-integration.md) from these consumer commands. Source Analyzer core is an Experimental programmatic API; standard Source-aware CLI remains Planned.

## 6. Migration preview and explicit save

Use this disposable single-file v1 fixture. Exclusive creation fails if these files already exist:

```bash
node - <<'JS'
const fs = require('node:fs');
const policy = 'version: 1\nmetadata: { owner: migration-rehearsal }\nrequest: { allow_methods: [HEAD, GET] }\nresponse_headers: {}\n';
fs.writeFileSync('migration-v1.yml', policy, { flag: 'wx' });
fs.writeFileSync('migration-original.yml', policy, { flag: 'wx' });
JS
./node_modules/.bin/cdn-security migrate --policy migration-v1.yml
cmp migration-original.yml migration-v1.yml
./node_modules/.bin/cdn-security migrate --policy migration-v1.yml --write
cmp migration-original.yml migration-v1.yml.v1.bak
node node_modules/cdn-security-framework/scripts/policy-lint.js migration-v1.yml
./node_modules/.bin/cdn-security build --policy migration-v1.yml --target aws --out-dir dist/migrated-aws
./node_modules/.bin/cdn-security build --policy migration-v1.yml --target cloudflare --out-dir dist/migrated-cf
```

Expect exit0. Omitted `--to` means2; preview prints only the fixed `MIGRATION_PREVIEW` summary, not the converted Policy. The API's returned `policy` is an artifact that may contain secrets; do not log it as a diagnostic. Manual decisions (difficulty5/6, AWS nonce/JWT/signed_url, target clarification) exit2; parse/schema/I/O failures exit1. Schema validity, provider build success and production applicability are separate claims.

Graph migration with `extends` or root `$ref` stops as unsupported. Do not bypass it by manually changing version. Before-commit save failures do not commit a new input; successful explicit save replaces it with v2 and retains original bytes in `.v1.bak`. Existing backups and leaf symlink/hardlink inputs are refused. Trust and exclusive management of a POSIX local directory are required; arbitrary post-check races, power loss, Windows/network filesystems are not guaranteed. YAML comments/format/anchor spelling and ACL/xattrs are not retained. See the [complete save contract](schema-migration.md).

## 7. Isolated published1.4.0 rollback rehearsal

This is a non-production rehearsal using the preceding backup. Candidate dependencies stay unchanged. Pin the old package in a new rollback directory and explicitly add its missing Cloudflare build dependency `esbuild@0.28.0`. Do not modify the published tarball:

```bash
(
  set -eu
  mkdir rollback-1.4.0
  npm install --prefix rollback-1.4.0 --save-exact cdn-security-framework@1.4.0 esbuild@0.28.0
  cp migration-v1.yml.v1.bak rollback-1.4.0/policy.yml
  cmp migration-original.yml migration-v1.yml.v1.bak
  cmp migration-original.yml rollback-1.4.0/policy.yml
  shasum -a 256 migration-original.yml migration-v1.yml.v1.bak rollback-1.4.0/policy.yml
  cd rollback-1.4.0
  node node_modules/cdn-security-framework/scripts/policy-lint.js policy.yml
  ./node_modules/.bin/cdn-security build --policy policy.yml --target aws --out-dir dist/aws
  ./node_modules/.bin/cdn-security build --policy policy.yml --target cloudflare --out-dir dist/cloudflare
)
```

Verify identical SHA-256 for original, backup and restored bytes, then old-package lint/AWS/Cloudflare build exit0. Pristine published1.4.0 fails the Cloudflare build without the dependency. This addition is a rollback-environment prerequisite, not a promise that this version will remain safe or approval for production rollback. Returning to the old package loses subsequent safety hardening.

## 8. Before applying artifacts

Generated `dist/edge`/`dist/infra` are review inputs to the operator's IaC/CDN workflow. Read [IaC](iac.md), [Origin authentication](origin-auth.md), [Threat model](threat-model.md), and [Observability](observability.md). Do not deploy this guide's synthetic/placeholder artifacts.
