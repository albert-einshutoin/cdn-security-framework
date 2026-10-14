# 解析キャッシュの変更前後比較

## 追加改善: PR #1106 の初回commitからの比較

変更前は `96743ec29291efeda72ffa0be147d50a135d0f6a`。新しい負荷生成器を変更前・変更後の両側に同じbytesで適用し、製品実装だけを比較した。Node v24.2.0 / darwin / arm64、同じローカルホストでの合成入力。測定中のbuild・test・他benchmarkは並列実行していない。

NestJSでは代入先Symbolを列挙する既存規則を共有visitorへ移し、snapshotごとにSymbol→代入候補の索引を一度だけ完成させる。可変binding・保存式・namespace関数がこの索引を共有する。namespaceのwrite存在判定と、可変bindingの代入値判定の違いは維持する。OpenAPIでは正規化呼び出し内でPointerの参照先だけを共有し、各参照のcallback・循環・hop予算を省略しない。

各入力をAB/BAの順で比較し、各側独立2プロセス×6回から各プロセス初回だけを除く10 warm sampleを集計した。通常1,000件に2.93%の平均増加、OpenAPIに大きいばらつきがあったため、この2 commandだけ追加のAB/BAを1回行った。通常1,000件とOpenAPIは最初の値も全件含む各側4プロセス・20 warm sample、それ以外は各側10 sampleである。JSONに全cold/warm sample、標準偏差、組ごとの結果、入力・元データhashを保存した。warmはNodeプロセス内の反復を指し、完全解析がproject cacheを再利用する意味ではない。

### ソース解析・契約比較

件数はmetricsのoperation数。controllerごとに9件のrouteを契約へ出力し、動的パス1件は診断になる。追加3パターンは奇数controllerの9件をunknown、偶数controllerを既存guardのhighとする入力を生成し、unknownの総数を検査する。出力全体は別のparity checkで比較した。代入欄は無関係なcompound assignmentの回数で、パターン固有のwriteは別途含む。

| 入力 | 変更前平均ms | 変更後平均ms | 短縮率 | 変更後min–max ms |
|---|---:|---:|---:|---:|
| routes / 100件 / 代入0回/controller | 54.61 | 54.25 | 0.66% | 50.47–60.51 |
| routes / 1000件 / 代入0回/controller | 417.64 | 432.01 | -3.44% | 403.19–481.10 |
| routes / 5000件 / 代入0回/controller | 2012.66 | 1997.90 | 0.73% | 1945.86–2063.13 |
| mutable-decorators / 1000件 / 代入32回/controller | 1011.41 | 479.30 | 52.61% | 450.37–532.27 |
| namespace-decorators / 1000件 / 代入32回/controller | 4509.20 | 530.30 | 88.24% | 497.50–578.27 |
| assignment-heavy / 100件 / 代入32回/controller | 69.27 | 65.68 | 5.18% | 58.28–81.37 |
| assignment-heavy / 1000件 / 代入32回/controller | 937.92 | 530.90 | 43.40% | 482.48–629.78 |
| assignment-heavy / 5000件 / 代入32回/controller | 13421.96 | 2352.12 | 82.48% | 2246.70–2451.19 |

### OpenAPI解析・正規化・直列化

| 入力 | 変更前平均ms | 変更後平均ms | 短縮率 | 変更後min–max ms |
|---|---:|---:|---:|---:|
| operations-100 | 3.84 | 4.54 | -18.07% | 3.21–8.98 |
| shared-refs-1000 | 39.52 | 43.11 | -9.06% | 33.87–103.51 |
| nested-refs-10000 | 495.24 | 457.67 | 7.59% | 402.03–622.35 |
| deep-schema | 1.21 | 0.53 | 56.40% | 0.34–0.91 |
| repeated-refs | 65.97 | 65.01 | 1.45% | 61.50–72.01 |
| early-document-limit | 0.08 | 0.08 | -0.79% | 0.06–0.11 |

nested-refs-10000の正規化段階は平均170.17→119.50ms。変更後500ms超は20 sample中2件。通常1,000件は417.64→432.01msで、400ms目標の達成は確認できない。平均と最大値は別々に評価し、安定した500ms以内やproduction latencyの保証とは扱わない。小さい差はばらつきの範囲の可能性があり、すべての入力で短縮したとは主張しない。初回改善の未達も、下の初回結果として残す。

### 検証と失敗記録

- 追加3件のregression checkは変更前・変更後とも成功。関連12 files / 254 testsとbenchmark unit checksが成功。
- source8入力の結果全体・診断、OpenAPI6入力のgraph・IR・上限拒否が変更前後で一致。
- 専門レビューで認証のunknown境界、snapshot/Symbol分離、完了後のみのcache公開、cancel/deadline、OpenAPI参照ごとの検査を確認し、指摘なし。
- 最初のfixture期待値（動的パスは契約出力に含まれない）とhop testの予算が誤って失敗したため修正。製品不具合の再現とは扱わない。
- 最初の計測は代入負荷5,000件が既定maxDiagnostics=1000で拒否され停止した。失敗と完了済みデータをJSONのincompleteAttemptに保存し、測定用だけmaxDiagnostics=10000へ揃えて全比較を再実行した。製品の既定上限は変更しない。
- 完全検証 npm run test:ci はREADME指定のダミーEDGE_ADMIN_TOKENをプロセスだけへ設定して実行し、exit 0、166090.50ms。最初の実行はこのfixture未設定でbuildが拒否されたため、失敗ログを保存して再実行した。

再測定: baselineとcandidateを別checkoutで同じ依存からbuildし、次を各側2プロセス、AB/BAで実行する。

```sh
npm run build:ts
node scripts/benchmark-source-analysis.js --profile full --workload routes --controllers 100 --assignments 0 --iterations 6
node scripts/benchmark-source-analysis.js --profile full --workload mutable-decorators --controllers 100 --assignments 32 --iterations 6
node scripts/benchmark-source-analysis.js --profile full --workload namespace-decorators --controllers 100 --assignments 32 --iterations 6
node scripts/benchmark-source-analysis.js --profile full --workload assignment-heavy --controllers 500 --assignments 32 --iterations 6
node scripts/benchmark-openapi.js --profile full --iterations 6
node node_modules/vitest/vitest.mjs run test/source-analysis test/openapi --maxWorkers=2
node scripts/source-analysis-benchmark-unit-tests.js
```

routesとassignment-heavyはcontrollers=10/100/500で比較した。benchmark sourceをbaselineへも適用する前提。メモリ値はheap差分の概算で、total/peak memoryの測定ではない。

## 初回改善: 3bf4d0d → 96743ec2 の保存済み結果

以下は初回commit時点の測定・検証であり、追加改善の現在値と混ぜて集計しない。

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
