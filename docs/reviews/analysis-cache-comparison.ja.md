# 解析キャッシュの変更前後比較

認証解析の代入候補を同じ解析内で一度だけ収集し、Symbol別の完了結果を共有する。OpenAPIでは文書別のJSON Pointer解決結果と、loaderが検証済みの文書パスを再利用する。公開APIと解析結果の形式は変更しない。

基準commit: `3bf4d0dbfd309641830cbf86e77259114bf92677`。Node v24.2.0 / darwin / arm64。固定入力を同じホストで比較したローカル測定。各プロセス6回中、初回を除く5回を集計する。

| 対象 | 変更前平均ms | 変更後平均ms | 短縮ms | 短縮率 |
|---|---:|---:|---:|---:|
| ソース解析・比較 100 operation | 56.18 | 60.05 | -3.87 | -6.9% |
| ソース解析・比較 1000 operation | 540.26 | 441.04 | 99.22 | 18.4% |
| ソース解析・比較 5000 operation | 4685.10 | 2148.77 | 2536.33 | 54.1% |
| OpenAPI operations-100 | 4.010 | 3.846 | 0.165 | 4.1% |
| OpenAPI shared-refs-1000 | 42.022 | 39.538 | 2.484 | 5.9% |
| OpenAPI nested-refs-10000 | 609.905 | 496.963 | 112.942 | 18.5% |
| OpenAPI deep-schema | 0.595 | 0.464 | 0.131 | 22.0% |
| OpenAPI repeated-refs | 67.647 | 64.192 | 3.455 | 5.1% |
| OpenAPI early-document-limit | 0.108 | 0.080 | 0.028 | 25.7% |

ソース解析はAB/BAの2組、各側10 warm sample。OpenAPIは最初の組でparse・resolve・normalize全体に大きな変動を観測したため、比較を未確定として元データを保存し、追加ABを1組だけ測定した。表のOpenAPIは隣接する2・3組目の平均である。JSONには最初の組を含む全観測値の集計、全cold/warm sample、組ごとの結果、ばらつきを残している。変動の原因は特定していない。

ソース解析はロード単体の計測・AST走査単体の計測・IR生成・契約比較を含む。IR生成は内部で別途projectをロードするため、loader probeのcache hitを解析全体のcache hitと呼ばない。初回のSymbol結果キャッシュだけの実装では5,000 operationが5075.21→5058.90msで改善未達だった。代入候補の一度だけの収集へ変更した結果を最終値とする。

5,000 operationの3,300ms目標とOpenAPI 10,000 operationの500ms目標は達成。ソース解析1,000 operationの400ms目標は未達。100 operationでは短縮を確認できない。目標未達を隠すための認証境界・filesystem検証の省略は行わない。

## 機能と安全性の確認

- 対象12 files / 251 tests、OpenAPI最終7 files / 88 tests、既存benchmark unit checksが成功。
- 同名Symbol、source変更後の再解析、同じfragmentの別文書、scalar schemaの参照文脈を4件の回帰テストで確認。追加テストは変更前の実装でも成功した。
- 固定入力のソース解析3規模について結果全体・診断、OpenAPI6 workloadについて参照グラフ・IR・サイズ上限拒否が変更前と一致。
- 専門レビューは初回、共有index修正、文書パス再利用の最終差分でALLOW。最初のレビュー時点では性能目標を確認していない。
- 新規テストの初回は参照順の期待値を誤って固定したため1件失敗。参照先の集合を確認する期待値へ修正し、再実行で4件成功。製品の欠陥の再現とは扱わない。

## 再測定

同じホスト・Node・依存でbaselineと変更後を別々にbuildし、各コマンドを独立2プロセスで実行する。実行順は入力ごとにbaseline→変更後、次は変更後→baselineとする。

```sh
npm run build:ts
node scripts/benchmark-source-analysis.js --profile full --controllers 10 --iterations 6
node scripts/benchmark-source-analysis.js --profile full --controllers 100 --iterations 6
node scripts/benchmark-source-analysis.js --profile full --controllers 500 --iterations 6
node scripts/benchmark-openapi.js --profile full --iterations 6
node node_modules/vitest/vitest.mjs run test/source-analysis test/openapi --maxWorkers=2
node scripts/openapi-benchmark-unit-tests.js
node scripts/source-analysis-benchmark-unit-tests.js
```

完全検証は `npm run test:ci`。データ・source/generated input hashes・元データhashは [analysis-cache-comparison.json](analysis-cache-comparison.json) を参照する。生成JavaScriptを編集せず、TypeScriptからbuildした。メモリ欄は概算heap差分であり、total/peak memoryの測定ではない。
