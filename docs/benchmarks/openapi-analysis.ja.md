# OpenAPI 解析ベンチマーク

`npm run benchmark:openapi` は固定 seed の入力を一時ディレクトリへ生成し、本番の解析経路を直接実行します。

1. 文書 parse と安全性検証
2. local `$ref` 解決
3. security-contract IR の正規化と serialize

JSON report は cold/warm を分離し、parse・ref 解決・正規化・合計 wall time、概算 heap 差分、入力 byte、operation 数、解決文書数、ref 数、出力 byte を記録します。hostname、絶対 path、timestamp は含めません。network ref は無効のままです。

## Workload

| ID | 目的 |
| --- | --- |
| `operations-100` | ref なし 100 operation |
| `shared-refs-1000` | component ref を共有する 1,000 operation |
| `nested-refs-10000` | nested local schema ref を使う 10,000 operation |
| `deep-schema` | default depth limit 付近の schema |
| `repeated-refs` | 同一 ref の反復と cache 挙動 |
| `early-document-limit` | ref 解決・正規化前の oversized input 早期拒否 |

大きな fixture は commit せず生成します。`test/fixtures/openapi/generated/` はこの境界だけを記録します。

## 代表 baseline

Apple Silicon、macOS arm64、各 workload 2 sample。表は warm 合計 ms です。個別 machine 名は記録しません。

| Node | 100 ops | 1,000 shared refs | 10,000 nested refs | Deep | Repeated refs | Early reject |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 20.17.0 | 5.597 | 44.564 | 596.136 | 0.446 | 31.844 | 0.106 |
| 22.23.2 | 5.057 | 40.093 | 521.080 | 0.461 | 27.449 | 0.123 |
| 24.19.0 | 3.796 | 35.140 | 523.620 | 0.454 | 29.599 | 0.103 |

時間と heap の完全な baseline は `openapi-analysis-baseline.json` にあります。

## CI 方針

- 通常検証は `shared-refs-1000` だけを実行し、合計 15 秒・概算 heap 差分 512 MiB の余裕ある絶対上限を適用します。10,000 operation は実行しません。
- schedule/manual の `OpenAPI Analysis Benchmark` だけが全 workload を Node 20.17.0、22、24 で実行します。percentage gate は warm wall time 50%、概算 heap 差分 100% です。
- 共有 runner の揺らぎだけで PR の percentage check が失敗することはありません。

完全な JSON report は `npm run benchmark:openapi -- --iterations 3 --output report.json` で取得できます。閾値変更時は変更前後 report、Node version、host class、変更理由を PR に残してください。microbenchmark の改善を製品速度の改善とは扱いません。Rust/WASM への置換は対象外です。
