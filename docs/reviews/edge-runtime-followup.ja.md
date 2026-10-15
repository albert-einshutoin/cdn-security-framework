# 生成edgeの追加最適化・本文解放

基準はPR #1106のhead `53013fd3fd8fd8f9c803f09bb6db4d1c4f7dc250`。変更対象は生成テンプレート、設定生成、emitterと対応テスト。既存の別checkoutの変更は触っていない。PR #1106のマージ後の追加最適化として別PRにまとめる。全sample、入力・生成コード・driver hash、source manifestは [JSON](edge-runtime-followup.json) に記録する。

## 実装と維持する契約

- DLP header block / JWKS non-OKで破棄するresponse bodyを共通cleanupでcancelする。cancel完了待ちで拒否を遅延させず、失敗は診断する。成功本文、uploadの単一所有者、JWKS redirect拒否・TTL・negative cache・refresh budgetを維持。
- 32prefix以上を生成時のprefix→gate ID索引へ変換。既存のslash境界・case・empty-prefix解釈を保持し、候補をpolicy順に重複除去して全て評価する。signed_url exact判定も残し、responseの広いcache保護は別索引で維持。小規模設定は従来の単純配列。索引を使う場合だけAWS補助コードを出力。AWSは最終minify/wrapper込みの実バイト数を測り、10KiBを超える場合だけ同じrendererの配列方式を生成時に選ぶ。request/responseで独立して選択し、出力は各1方式だけ。構文/変換/export/read/writeエラーは選択条件にせずError、配列でも超過ならwrite前にError。
- Cloudflareの無効Challenge / GraphQL / DLP / CORS / auth種別 / origin auth / nonce / allow samplingをliteral条件に確定し、既存esbuildで未使用関数・awaitを除去。設定宣言は従来の表現を保つ。AWS responseにもCORS/nonce用の既存方式のmarkerを適用。有効な機能を省略しない。
- URL解析を共有し、header count/sizeを1走査で集計。拒否とmonitorログの順序を維持。anomalyの独立した検査は維持。
- AWS object queryをraw文字列から再decodeせず元オブジェクトから正規化。raw limit/anomaly検査を維持し、重複値・特殊名・文字列/オブジェクト出力・drop keyのencoded比較を維持。過大queryはcountの走査も省く。
- Cloudflare queryは存在する削除キーだけnative deleteし、最後に表記を正規化。削除対象不在時の`%20`→`+`等の従来挙動も維持。全pairの再構築方式はworkerdで利点が確認できず、この方式へ変更。
- origin署名でqueryを選ばない設定ではquery正規化/sortを行わない（AWS/CF共通）。GraphQL検査済みのbytes/viewはorigin hashへ直接渡し、同じbytesを転送。全文署名のための必須buffer、bodyなしnull、UTF-8、view offsetを維持。
- emitterはlintで得たpolicy snapshotを各compilerへ渡す。子Node起動2回と同じpolicy/extends graphの再parseを除去。CLIは同じcompiler関数の入口adapterに集約。env/pkgRoot/output flags、構造検証、fail-closed、警告、ファイル単位atomic writeを維持。

## 回帰とレビュー

補正済みfixtureでDLP header block / JWKS 302 / JWKS 500はbeforeでcancel 0回の3失敗、afterは各1回で成功。初回DLP fixtureのUA不足による400は再現証拠に使わない。セルフレビューではempty prefixのresponse cache解釈と設定文字列中のRUNTIME marker誤一致を発見し、2件とも修正前失敗→修正後成功を確認。専門レビューで見つかったnative benchmarkのquery署名検証不整合も修正済み。

初期対象Vitestは5ファイル29/29成功。既存AWS runtimeは専用distと固定synthetic tokenで75/75、CF runtime/compiler/infra/WAFの対象チェックも成功。初回AWS runtimeの10失敗は既存distとのtoken前提不一致で、製品回帰とは扱わない。新emitter testの必須字段不足/任意methodを不正としたfixtureも補正。専門レビューと19 source/test対象のCompanion Stop Review GateはALLOW。完全検証の初回は意図した生成物のdriftで停止したため、`node scripts/check-drift.js --update`で29 edge golden fixtureを再生成し、通常のdrift checkも成功。Node→workerd→ローカルoriginのHTTP E2Eも成功（runtime・origin・port・temp cleanupを含む）。追加fixtureの最終GateもALLOW。完全検証の2回目は新内部モジュールの配布inventory未登録で停止したため、`docs/api-manifest.json`にJS/d.ts 4件を登録し、packed install smokeは成功。登録4行の専門レビューはALLOW。登録4行のStop GateもALLOW。完全検証3回目のVitestは670/671で、旧子NodeにNODE_OPTIONSで故障注入する1テストが残っていた。現在のin-process共有経路で同じunlink EPERMを注入する方式へ更新し、期待値（失敗、残存tmp、0600、秘密値非露出）を維持。write-safety対象15/15と専門レビューALLOWを確認。coverageは41ファイル671/671成功（lines/statements81.79%、branches81.25%、functions82.6%）。完全検証4回目は既存NestJS APP_GUARDテストの通常5秒deadlineで停止。worker数2に限定した一時障害の再実行は完全検証exit 0だったが、その後に発見したAWS size回帰の修正前の結果として記録する。

## Node生成コードの前後比較

Node v24.2.0 / darwin arm64。originはin-process stub。Request作成・response drain・origin署名再検証を含むwall timeで、edge CPU時間ではない。A1→B1→B2→A2、各側2独立process、30 warmup後の5batch×2=10batch平均。呼出数/first request/ばらつき/全sampleはJSON。生成・transpile時間はrequest時間から除外。

| 負荷 | before ms | after ms | 平均短縮率 |
|---|---:|---:|---:|
| followup-cf-routes-0 | 0.022100 | 0.020832 | 5.74% |
| followup-cf-routes-500 | 0.026585 | 0.016187 | 39.11% |
| followup-cf-headers-64 | 0.047420 | 0.045922 | 3.16% |
| followup-cf-query-100 | 0.110730 | 0.052403 | 52.67% |
| followup-cf-query-100-signed-without-query | 0.193415 | 0.110126 | 43.06% |
| followup-cf-graphql-hash-32768 | 0.178135 | 0.164492 | 7.66% |
| followup-aws-query-100 | 0.088017 | 0.047838 | 45.65% |
| followup-emitter-aws | 119.657905 | 6.111489 | 94.89% |
| followup-emitter-cloudflare | 124.983118 | 11.317722 | 90.94% |

通常のrouteなし構成とheader負荷の小差、GraphQL併用の重なる分布から安定的な高速化までは主張しない。routeなしの平均差は旧candidate計測の-3.32%から現計測の+5.74%へ符号が変わるため、安定的な改善とは主張しない。旧raw sampleもJSONのnodePreviousCandidateへ保持する。emitterの数字は生成処理時間であり、利用者のedge request時間とは区別する。

無効機能を含むCF出力は同一ベンチpolicyで 74,364→21,201 bytes。これは生成TSのサイズで、Wranglerの配布bundleサイズではない。AWS既存0/1/3/10route構成に加え、修正後32/64/80routeの生成・動作・10KiB gateを確認。

## native workerd HTTP

workerd 1.20261012.1 / compatibility_date 2026-07-20。外向き通信はloopback originへ固定、internetはdeny-all。500route+origin HMAC+GraphQLを含む共通policyで比較。A1→B1→B2→A2、各process各負荷10warmup+100sample、各側200sample。4process×330=1,320 HTTP request全成功。originが受信本文とqueryからSHA256/HMACを独立再計算し、全processのruntime/origin/temp cleanup成功。

| 負荷 | before ms | after ms | 平均短縮率 |
|---|---:|---:|---:|
| routes-500 | 0.398225 | 0.336888 | 15.40% |
| query-100 | 0.542544 | 0.437623 | 19.34% |
| graphql-hash-32768 | 0.497227 | 0.457222 | 8.05% |

Node client・loopback・workerd・originの検証を含むローカルwall time。managed Cloudflare/AWSのCPU、cold start、本番network TTFB、peak memoryは未計測。

## 再実行

```sh
npm run build:ts
npx vitest run test/cloudfront-size-selection.test.ts test/compiler-write-safety.test.ts test/edge-followup.test.ts test/emitter-followup.test.ts test/edge-runtime-optimizations.test.ts test/cloudflare-body-inspection.test.ts test/compiler-contract.test.ts
node scripts/benchmark-edge-runtime.js --root <built-checkout> --output <result.json> --fixture <same-private-synthetic-fixture.json> --only followup-
node scripts/benchmark-edge-http.js --root <built-checkout> --output <result.json>
VITEST_MAX_WORKERS=2 EDGE_ADMIN_TOKEN=synthetic-local-full-validation npm run test:ci
```

beforeは基準HEADを別ディレクトリへ展開し、同じ依存でbuildする。after側の同一driver bytesを両rootに使用し、前後比較はA/B/B/A順で実施する。RSA fixtureは初回だけ生成される使い捨て秘密鍵で、repoへ保存しない。今回のscratchは `/tmp/csf-edge-followup-BQQ6SB`。

## CloudFront生成サイズ回帰の修正と最終検証

32・64ルートの既存ポリシーが新索引で10KiBを超える回帰を発見したため、索引/配列を同じ共有rendererで生成し、最終バイト数だけで1方式を選択する設計へ修正した。prefix一覧の二重保持と不要なobject query再decodeを除き、固定mode/log format/guard限界値を設定文字列に触れずruntimeだけで確定する。32/64/80ルートの生成・最後の認証・slash境界・response no-store、重なるstatic/basic認証のAND/順序、100個の長いresponse-only prefix、monitor/text/JSON/correlation/case、policy文字列、構文/export失敗、両候補超過時の無生成を10テストで確認し、全成功。render改修のindex設定キー誤りも修正前1失敗/8成功のpublic path回帰テストで検出し、修正後成功。初回のraw basic credentials/転送path小文字化を期待したfixtureは既存契約に修正し再現証拠から除外した。AWS runtime75/75とcompiler unitも成功。専門レビューはALLOW、typecheck/diff-check成功。

| AWSルート数 | before bytes | after bytes | 生成時に選択した方式 |
|---|---:|---:|---|
| 32 | 9,523 | 9,834 | index |
| 64 | 9,939 | 9,861 | array |
| 80 | 10,147 | 10,069 | array |

現AWS修正でNode A/B/B/A全9負荷を再測定した（`size-final-node-A1/B1/B2/A2.json`）。native workerdのCF policy/生成コード/実行module/driverのSHA256は再生成した現bytesと完全一致するため、既存の1,320件のHTTP計測を維持する（`native-current-binding.json`）。current revisionのStop GateはALLOW（source21/21、golden29/29、package manifest1/1の現hash一致）。レビュー確定後、`VITEST_MAX_WORKERS=2 EDGE_ADMIN_TOKEN=synthetic-local-full-validation npm run test:ci` はexit 0。現source21件・golden29件・package manifestのSHA256が実行時と終了後で一致することも確認した。

P2追加指摘を確認する前の完全検証ではnpm auditの脆弱性0件、生成物境界・docs・policy lint・build/type・drift・決定性・security baseline・package smoke・全テスト・coverageが成功。Vitestは42ファイル681/681、coverage lines/statements81.86%、branches80.88%、functions82.76%。既存のCloudflare HTTP E2Eは46ケース・50 JWKS関連レコード成功、全cleanup成功。AWS/CF runtime/compilerの対象検証と、上記本番未計測の境界も維持する。完全検証後の新しい探索レビュー・コード変更は行っていない。このレポートはローカル検証の証拠であり、hosted CI・merge・deployの成功を示すものではない。

## GitHubレビューP2: APIの設定エラー詳細を保持

PR head `8f1ed592432259533f4dbf941b19b8e26c51c807`への[自動レビュー指摘](https://github.com/albert-einshutoin/cdn-security-framework/pull/1107#discussion_r4276977297)で、in-process emitterが`PolicyValidationError.validationErrors`を返していない回帰を確認した。上記の指摘なし・681テスト・hosted成功という結果は、この修正前のheadに対する記録であり、新しいheadの証拠とは扱わない。前回のユーザー向け「指摘なし」はGitHub上の追加指摘の確認漏れだった。

CLIと同じ構造属性の詳細配列をAPIにも保持する2行の修正。既存のgeneric error、収集diagnostics、`ok:false`、artifactを生成しない契約を維持する。実policyでstatic/basicの不足envを複数ルート分返すこと、提供済みsecretの非露出、出力dir未生成を回帰テストで確認した。修正前1失敗/3成功、修正後はemitter4・compiler契約3・write-safety15の22/22成功。API契約・buildも成功し、指摘範囲の最終専門レビューはALLOW。

生成runtimeのテンプレート・設定・goldenとemitter成功経路は変更していない。上記の計測raw sampleは修正前source hashと共に保持し、このエラー処理修正による新しい性能改善は主張しない。修正のStop GateはALLOW。最初のGateはartifact manifestのhash対象をroot package.jsonと取り違えてBLOCKしたため、`packageManifestPath: docs/api-manifest.json`を明示し、全hash一致で解消した（履歴をJSONに保持）。レビュー確定後の完全検証はexit 0、42ファイル682/682。coverage statements 81.86%、branches 80.89%、functions 82.76%、lines 81.86%。現source21/golden29/manifestのhash一致も確認。更新PRのhosted CIとmerge結果はPR上で別に確認する。
