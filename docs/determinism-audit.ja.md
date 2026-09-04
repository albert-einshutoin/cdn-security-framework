# Deterministic output audit

`npm run test:determinism` は現行 contract / report format の release audit です。
同じ LF fixture を異なる2つの workspace root で実行し、次を byte-identical として固定します。

- OpenAPI inspection と review 専用 policy candidate（metadata を含む）
- NestJS Source Analyzer の合成 example
- AWS / Cloudflare の生成 artifact
- JSON / SARIF / GitHub Summary の contract-diff report
- semantic identity が同じまま evidence/object order や message だけを変えた Finding ID と sort 順

Finding identity は100回反復し、Windows / POSIX の path separator も比較します。さらに
OpenAPI、policy、生成 artifact を CRLF input で再実行します。CRLF report の比較で除外するのは
byte 由来の digest、instance ID、byte size だけで、それ以外の semantic output は一致必須です。
contract report には有効な exception と期限切れ exception を1件ずつ含め、JSON / SARIF /
GitHub Summary の suppression と governance output を一緒に比較します。

さらに committed golden 49ファイルを inventory 化し、workspace-relative path、
secret-like literal、home/temp の absolute path、壊れた fixture entry を検査します。
`reports/determinism-audit.json` に記録するのは scenario count と SHA-256 digest だけで、
source 本文、policy secret、query、runtime timestamp は記録しません。

Golden は semantic review の代替ではなく、現在の output contract の証拠です。暗黙の update
mode はありません。golden の変更は別の review 済み diff とし、出力差分の理由を記録します。
CI を通すためだけに再生成しないでください。

audit の child process は最小限の環境で実行し、`EDGE_ADMIN_TOKEN`、`ORIGIN_SECRET`、
`JWT_SECRET` を固定された本番用でない fixture 値で上書きします。runner の secret によって
digest が変化することはありません。report は `reports/` 直下に限定し、symlink と
hard link の出力先は拒否します。

```bash
npm run test:determinism -- --output reports/determinism-audit.json
```
