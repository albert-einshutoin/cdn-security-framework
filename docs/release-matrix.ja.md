# Release compatibility matrix

Release workflow は Node 20.17.0、Node 22、Node 24 で package を検証します。
`full-validation` は Node 24 で完全な `npm run test:ci` gate を実行し、同じ matrix
で generated-boundary、documentation、API contract、packed install、CLI、OpenAPI、
NestJS example、AWS/Cloudflare build を実行します。

各 matrix job は `schemaVersion: 1` の JSON report を作成します。含めるのは次だけです。

- Node / package version
- public export key と schema digest
- CLI と代表 example の pass/fail
- 相対 generated-file path、size、SHA-256 digest

`full-release-matrix-audit` は3つの report を必須とし、Node major、package version、
API export、schema、example check、生成 artifact digest の差分で失敗します。report は
GitHub Actions artifact として30日保存し、環境変数、absolute path、OpenAPI source、
生成 runtime 本文は含めません。

ローカルで代表 report を作る例です（hosted Node 20/22 の証拠の代替ではありません）。

```bash
EDGE_ADMIN_TOKEN=matrix-token-not-for-deploy \
ORIGIN_SECRET=matrix-origin-not-for-deploy \
JWT_SECRET=matrix-jwt-not-for-deploy \
npm run test:release-matrix -- --output reports/release-matrix/local.json
```

対応 engine range（`>=20.17.0`）、OS matrix、performance percentage gate は変更しません。
