# Deterministic output audit

`npm run test:determinism` は現行 contract / report format の release audit です。
対応 fixture を同じ条件で2回実行し、次を byte-identical として固定します。

- OpenAPI inspection と review 専用 policy candidate（metadata を含む）
- NestJS Source Analyzer の合成 example
- AWS / Cloudflare の生成 artifact
- JSON / SARIF / GitHub Summary の contract-diff report
- semantic identity が同じまま evidence/object order や message だけを変えた Finding ID と sort 順

さらに committed golden 49ファイルを inventory 化し、workspace-relative path、
secret-like literal、home/temp の absolute path、壊れた fixture entry を検査します。
`reports/determinism-audit.json` に記録するのは scenario count と SHA-256 digest だけで、
source 本文、policy secret、query、runtime timestamp は記録しません。

Golden は semantic review の代替ではなく、現在の output contract の証拠です。暗黙の update
mode はありません。golden の変更は別の review 済み diff とし、出力差分の理由を記録します。
CI を通すためだけに再生成しないでください。

本番用でない fixture 値を使ったローカル実行:

```bash
EDGE_ADMIN_TOKEN=determinism-token-not-for-deploy \
ORIGIN_SECRET=determinism-origin-not-for-deploy \
JWT_SECRET=determinism-jwt-not-for-deploy \
npm run test:determinism -- --output reports/determinism-audit.json
```
