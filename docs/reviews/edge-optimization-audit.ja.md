# 生成edgeを中心とした最適化・品質調査

> 2026-10-14の監査時点の保存記録。実装後の結果は [追加実装・前後比較](edge-runtime-optimization.ja.md) を参照。以下の未実装・未解決・ローカルのみという記述は監査時点の状態。

基準HEAD: `0dcf905817ae205d970e5465bebb04d145defcea`（PR #1106）。今回の変更はローカル作業ツリー。commit・push・PR更新・merge・deployは行っていない。

## 調査範囲と判断

`src/` と `templates/` の145ファイル・55,656行・3,715関数本体をTypeScript ASTで棚卸しした。80 token以上の同一関数本体は5グループ。これは構造的な全体調査であり、全行の手動精読や完全な脆弱性不存在の証明ではない。生成edgeの通常通過、認証、クエリ、パス照合、GraphQL、DLP、origin署名を重点精読・実測し、compiler/validator、TypeScript/NestJS解析、OpenAPI、契約比較、reporter、CLI/log集計の主要経路も確認した。CI/release基盤の変更、外部負荷試験は対象に含めていない。

改善候補はある。優先するのはリクエストごとの重複計算・鍵変換・本文保持である。通常の軽量パスの差は小さく、ローカル測定で0.001ms程度の差を高速化の確証とは扱わない。以下の未実装候補に削減率を約束するものはない。

## 再現して修正した欠陥

### B1: Cloudflare本文検査のキャンセル待ち

対象: `templates/cloudflare/index.ts:336`、`readLimitedRequestText`、`applyResponseDlp`。

cloneした本文の一方をcancelすると、元の本文の消費が終わるまでPromiseが完了しないことがある。cancel完了を待ってから転送/応答する経路は循環待ちになる。生成コードをNodeのRequest/Responseで動かす回帰チェックでは、GraphQL reportとDLP report_only/mask/blockの4ケースが500ms期限で失敗。共有 `cancelBodyInspection` からキャンセルを開始し、その完了を応答の前提にしない形へ修正した。キャンセルrejectionは本文や例外値を含まない固定ログで観測する。

GraphQLのblock/report判断と、DLPの上限超過時に元のstatus/header/bodyを返す既存仕様を維持。修正後は5/5ケース成功。初回のGraphQL blockチェックにはテスト側cleanupのalready-closedエラーがあり、修正後のbaselineでは成功していた。製品不具合の再現数は4件とする。

workerd HTTP E2Eでは46ケースが成功し、originへの到達・元本文・response全体を検査した。追加のGraphQL reportは0.762ms、DLP pass-throughは1.695ms（各1回、ローカル往復時間）。Nodeの500ms期限とは測定環境が異なるため、これらを前後短縮率に換算しない。

### B2: AWSの特殊クエリ名による欠落・共有オブジェクト変更

対象: `templates/aws/viewer-request.js:556`、`normalizeQuerystringOutput`。

通常の `{}` に対する `if (!next[key])` は、`__proto__`・`constructor`・`toString` を既存のクエリ項目と誤認する。複数値を追加すると共有prototype/functionへ書き込み、クエリ名自体も失われる。出力辞書を `Object.create(null)` に変更した。生成・minify済みのCloudFrontコードを隔離VMで実行し、3ケースすべて修正前失敗・修正後成功。通常キー、複数値、追跡パラメータ削除、JSON出力、共有オブジェクトと次のリクエストへの非汚染を確認した。

バグ修正前後のAWS通常経路は各条件とも平均約0.001ms/req。計測のばらつきが差より大きく、性能改善・性能同等の厳密な証明とは扱わない。生成サイズは17 bytes増加した。

## 生成edgeの優先度 中〜高の追加設計（未実装）

| 優先度 | 対象・根拠 | 仕様を保つ改善設計 | 必須の検証 |
|---|---|---|---|
| 高 | Cloudflare `hmacSha256Base64Url` / `verifyJwt`。HS256・RS256とも1,031 requestでimportKeyが1,031回。RS256のJWKS fetchは1回。 | JWK object identityに結びついたCryptoKeyの再利用。HMACは設定済みgateと実際のsecret/algorithm/usageに結びつけた有限の状態へ限定する。署名検証そのものは毎回行う。 | 同kidの鍵更新、endpoint分離、secret rotation、並行cold、import失敗、expiry/issuer/audience/alg拒否。攻撃者入力を無制限なcache keyにしない。 |
| 高 | AWS `getAuthGates` と `template-inject.ts:50`。今回の10 static-token route構成は11,295→11,312 bytesで10,240 bytes制限によりbuild拒否。1 routeは9,620、3 routeは9,996 bytes。 | 設定で使うauth種別だけの処理を生成し、固定値とprefixの重複表現を削減する。設定された全機能・gate順序を保持する。 | 各auth構成・重複prefix・monitor/enforceの生成コード実行、サイズ境界、secret非出力。今回の10 route構成の観測であり全Policyの一律上限ではない。 |
| 中 | Cloudflare `normalizeForMatch` / `pathMatchesPrefix`、AWS request/responseのprefix比較。500 routeの公開通過は約0.048ms、0 routeは約0.026ms。 | 確定済みpathの比較用小文字化をrequestごとに1回、設定prefixの小文字化をbuildまたはmodule初期化時に1回にする。まず線形scanを保つ小変更から始める。 | 大文字小文字を区別する設定、境界のslash、Unicode、matrix、percent decode、signed URLのexact、重なる全gateとpolicy順序、response cache保護。 |
| 中 | AWS `blockIfQueryLimits` / `normalizeQuery`。同じqueryを2回serialize/split。100項目で約0.063ms、0項目は約0.001ms。 | リクエスト内でraw serialized queryと分割結果を共有する。limits/anomalyが生入力を見る順序を保ち、正規化後の値を逆流させない。 | object/string、multiValue、特殊名、空値、encode/decode、drop規則、CRLF、長さ/個数上限、monitor動作。 |
| 中 | Cloudflare GraphQL/DLPのclone、chunk蓄積、結合/復号。32KiB paddingのGraphQLは約0.118ms、64KiB DLP maskは約0.338ms。 | 本文の所有者を一つにして、検査済みprefixと残りを再生する方式を候補評価する。現在の小さなキャンセル修正とは別の設計変更。上限到達・error・cancel・backpressureを先に定義する。 | byte列完全一致、分割UTF-8、上限ぴったり/超過、chunked/不正content-length、report/mask/block、origin署名との併用、切断時cleanup、native workerd。無制限bufferや機能省略で高速化しない。 |
| 中 | Cloudflare `replaceAllWithDetector` はcustom regexを本文/ヘッダーごとにnew RegExpする。`scanAndMaskDlp` はreport_onlyでも置換文字列を作る。 | まずglobal flag付きregexの事前準備とlastIndex初期化を評価する。report/block専用scanは、既存の逐次maskが後続detector結果へ与える影響まで同じにできる場合に限る。 | 複数requestのlastIndex分離、全detector集合・順序、custom/built-in重複、mask内の検出文字、ReDoSチェック。単なるtest/早期returnへの置換は等価でない。 |
| 中 | Cloudflare `include_body_hash` はrequest.clone().arrayBuffer()で全文を保持し、origin送信前にhashする。 | managed runtimeでのpeak memoryとTTFBを先に測り、正しい署名bytesを保つ範囲で重複bufferを減らす。本文hashの無効化や暗黙のbody上限追加は行わない。 | 大きいbody、chunked、署名と実際の転送bytesの一致、キャンセル/失敗、GraphQLとの併用。現在のWebCryptoの全buffer要求と既存公開契約が設計制約。 |

## compiler・解析・CLIの追加候補（未実装）

| 優先度 | 対象・根拠 | 改善設計と維持する境界 |
|---|---|---|
| 中 | `src/validator/index.ts:75`。validatePolicyごとにschema read/parseとAJV compile。今回の同一policy反復は平均10.016ms。 | schema bytesとpkgRootのidentityに結びつくcompile結果を再利用。schema変更、custom pkgRoot、compile失敗、env依存のauth検証を正しく扱う。APIをまたぐ無条件の永続cacheは避ける。 |
| 中 | `src/source/typescript/project-loader.ts:1069`、`:1135`、`:1181`。cache hit判定前にcreateProgram/createSourceFileとAST計数を行う。 | 境界検証済みのfile content/identity/compiler optionsごとのAST再利用。FS/root/symlink検証、import解決の変化、論理的なnode/byte budget、deadlineを省略しない。今回は新たな速度測定なし。 |
| 中 | `src/source/nestjs/decorator-symbols.ts:3068`。receiverごとに全projectの変数宣言を収集し、alias集合が安定するまで全宣言を再走査する経路が残る。 | snapshot単位の宣言/参照indexと依存先worklistを利用。既存indexとの意味差を先に整理する。Symbol分離、destructuring、順序、mutation/escape、unknownとキャンセルを保持。今回のassignment index改善とは別経路で、削減幅は未測定。 |
| 中 | `src/contract/drift/index.ts` / `shared.ts`。結合比較から3回の入力検証、auth/requestで重複するmatchingAuthRules。 | 結合API内部で検証済みcontextとrequest内path relationを共有。個別公開APIの入口検証は維持し、cache hitでも論理的なcomparison budgetを変更しない。優先度はedge処理より下。 |
| 中 | `src/bin/analyze.ts:237`。ログ全体のreadFileSync後にsplitで全行を保持する。 | 同期APIを維持してchunk単位のreadSync/UTF-8復号を行い、line番号・最後の改行なし・診断・全件集計を保つ。集計mapに必要なメモリは別に残る。効果は大きいログ入力で別測定が必要。 |
| 低 | reporterのsort comparator内serialization、Findingの再sanitize、cookie/サンプリング関数などのsource重複。 | 比較keyの事前計算やbuild時のソース共有は候補。小さいcompareText関数を全体共通化しても速度改善は期待できず、独立したedge artifactは実行時にはそれぞれコードを持つ必要がある。 |

## 実測一覧

環境: Node v24.2.0 / darwin arm64。生成されたコードを実行し、CloudflareはNodeのRequest/Response/WebCryptoとローカルstub origin、AWSはminify済みhandlerを使った。compile/fixture生成は計測外。各workloadでfirst requestを別記録し、30回warmup、以下の5 batchを逐次測定。数値は1 request当たりのwall timeで、Request生成、stub origin、response drainを含む。min–maxは5個のbatch平均の範囲であり、個々のrequestのp95/p99ではない。CPU欄の元データはプロセス全体のCPU時間で、managed edgeのCPU utilizationではない。

AWSのbefore/afterは今回のquery辞書修正だけの比較。同じcompiler・policy、変更前template snapshotを使う単一AB順で、差が小さくJIT/順序影響を除外できない。Cloudflare rowsは変更後の負荷別baseline。各条件の全sample、生成物とinputのSHAはJSONへ保存した。

| workload | 平均ms/req | batch平均min–max ms | warm sample数 |
|---|---:|---:|---:|
| aws-before-routes-0 | 0.001 | 0.001–0.001 | 2000×5 |
| aws-after-routes-0 | 0.001 | 0.001–0.001 | 2000×5 |
| aws-before-routes-1 | 0.001 | 0.001–0.001 | 2000×5 |
| aws-after-routes-1 | 0.001 | 0.001–0.002 | 2000×5 |
| aws-before-routes-3 | 0.001 | 0.001–0.001 | 2000×5 |
| aws-after-routes-3 | 0.001 | 0.001–0.001 | 2000×5 |
| aws-query-0 | 0.001 | 0.001–0.002 | 1000×5 |
| aws-query-100 | 0.063 | 0.061–0.066 | 1000×5 |
| cf-routes-0-public | 0.026 | 0.016–0.042 | 200×5 |
| cf-routes-100-public | 0.027 | 0.020–0.031 | 200×5 |
| cf-routes-100-last-auth | 0.028 | 0.024–0.034 | 200×5 |
| cf-routes-500-public | 0.048 | 0.041–0.054 | 200×5 |
| cf-routes-500-last-auth | 0.057 | 0.051–0.064 | 200×5 |
| cf-jwt-HS256 | 0.049 | 0.041–0.059 | 200×5 |
| cf-jwt-RS256 | 0.073 | 0.069–0.076 | 200×5 |
| cf-graphql-1024 | 0.041 | 0.037–0.048 | 200×5 |
| cf-graphql-32768 | 0.118 | 0.113–0.128 | 200×5 |
| cf-dlp-report_only-4096 | 0.046 | 0.041–0.050 | 200×5 |
| cf-dlp-report_only-65536 | 0.273 | 0.262–0.298 | 200×5 |
| cf-dlp-mask-4096 | 0.051 | 0.046–0.054 | 200×5 |
| cf-dlp-mask-65536 | 0.338 | 0.316–0.357 | 200×5 |
| cf-origin-body-hash-0 | 0.139 | 0.068–0.395 | 200×5 |
| tooling-validate-policy | 10.016 | 9.264–10.958 | 10×5 |

GraphQL workloadの1024/32768はJSONのpadding byte数であり、wire bodyにはquery等の追加bytesがある。DLPの4096/65536は検査対象body bytes。

native workerd 1.20261012.1、compatibility_date 2026-07-20のloopback HTTPでは、1KiBと1MiBのorigin body hashを各110回実行（最初の10回を除く100 sample）。実際の転送本文からoriginでSHA-256とHMAC署名を再計算して一致を検査した。

| body | 平均ms | min–max ms | 成功 |
|---|---:|---:|---:|
| 1024 bytes | 0.560 | 0.269–3.477 | 110/110 |
| 1048576 bytes | 3.347 | 2.791–4.592 | 110/110 |

この値にはNode HTTP client、loopback、workerd、origin側再検証が含まれる。managed Cloudflare/AWSのcold start、CPU制限、実ネットワークのTTFB、peak memoryは未観測。

## 失敗・未解決事項

- 最初の計測はAWS 10 route構成のコードサイズ拒否で終了。その失敗を保存し、最終reportにもbefore/afterの拒否を載せた。安全なサイズgateを緩めていない。
- 次の2回はNode上の1MiB origin body hashが `Response body object should not be disturbed or locked` で失敗。生成Worker単独の切り分けでも1KiB 100回成功後、1MiBの97回目で再現した。単純なRequest clone/hash/forward対照は300回成功。この追加切り分けの件数は当セッションのtool output観測を転記した記録で、raw processログとは区別する。根本原因は未確定であり、製品修正や成功へ置き換えていない。
- Nodeの当該ケースには有効な速度を割り当てず、`unmeasuredWorkloads` にfailedとして残した。同じ機能のnative workerdは上記220回成功。これだけでNode側の原因が解消したとはしない。
- 初回本文回帰テストのcleanup例外と修正済みbaseline、実際の4 timeoutを分けて保存した。
- 最初の完全検証は生成コードのgolden driftで停止（exit 1、約15,437ms）。既存コマンドで期待値を再生成し、15ファイルが今回の2修正だけに対応することを確認・限定レビューしてから再実行した。失敗ログも保存した。

## 検証と納品境界

- 新規回帰: Cloudflare 5、AWS 3の計8件成功。既存Cloudflare runtime tests成功。
- native workerd HTTP E2E: 46ケース成功、runtime/origin/temp/portsのcleanup全項目成功。JWKS関連50ケースも同じharnessで成功。
- 専門レビュー: gpt-5.6-sol / medium、変更5ファイル、および再生成したgolden 15ファイルの限定レビューはALLOW、要修正なし。managed edge実行は未観測。
- ローカル完全検証: `EDGE_ADMIN_TOKEN=<READMEのdummy> npm run test:ci`、exit 0、148909.225ms。実secretは利用していない。Vitestは36 files / 644 tests成功。security baseline、package smoke、npm auditも成功。全内訳は保存ログ。
- 最終Companion Gateは、この確定差分と測定・検証証拠に限定して別receiptへ記録する。hosted CI、commit/push、PR更新は今回未実施。

再現: `npm run build:ts` 後、`node node_modules/vitest/vitest.mjs run test/cloudflare-body-inspection.test.ts test/aws-query-normalization.test.ts --maxWorkers=1`、`node scripts/cloudflare-runtime-tests.js`、`node scripts/cloudflare-http-e2e-tests.js --report reports/edge-optimization-audit/http-e2e-repeat.json`。測定driver・元データは `reports/edge-optimization-audit/` に保存し、input/source/evidence hashは [JSON report](edge-optimization-audit.json) で照合できる。測定driverは調査用であり通常CIへ追加していない。
