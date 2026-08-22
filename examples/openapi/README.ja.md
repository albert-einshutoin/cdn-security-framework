# OpenAPI Review Example

このfixtureは、人間レビューを前提とするOpenAPI workflowを示します。repository
rootで実行します。

```bash
npm ci
mkdir -p reports
npx cdn-security openapi inspect \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --json \
  --out reports/openapi-contract.json
npx cdn-security openapi generate-policy \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --profile balanced \
  --out policy/openapi.candidate.yml
npm run lint:policy -- policy/openapi.candidate.yml
npx cdn-security build \
  --policy policy/openapi.candidate.yml \
  --out-dir dist/openapi-candidate
```

生成されたCandidateと`policy/openapi.candidate.meta.json`を確認してから、必要な設定だけをactive
Policyへ反映します。生成処理は`policy/security.yml`の上書き、Policyの適用、
artifactのdeployを行いません。

fixtureには、明示publicなhealth endpoint、認証付きuser endpoint、admin風の
endpoint、必須tenant header、上限付きquery parameter、JSON body、size不明の
multipart upload、local component `$ref`があります。`/admin/reports`という名前は
privileged authorizationを証明せず、Bearer schemeだけではJWT issuer、audience、
JWKS、algorithm、secretを安全に推測できません。

Threat Model、review checklist、limit、troubleshootingは
[OpenAPI導入ガイド](../../docs/openapi-integration.ja.md)を参照してください。
