# 生成edgeと解析処理の最適化・Node本文修正

PR #1106の追加実装。基準HEADは `0dcf905817ae205d970e5465bebb04d145defcea`。測定前には前回の2バグ修正が未commitで存在したため、beforeはこのHEADへ [baseline patch](edge-runtime-before.patch) を適用した状態とする。patchはAWS query辞書とCloudflare clone cancellationだけで、コンパイラーは同一。before/afterの13 source hashesと全sampleは [JSON](edge-runtime-optimization.json) に保存した。以前の監査と解析/OpenAPI比較の記録は歴史的な別stageとして維持する。

## 実装した中〜高優先度の改善

| 優先度 | 対象 | 最終実装・維持した仕様 |
|---|---|---|
| 高 | HMAC/RS256 key conversion | 設定済みownerごとに現在secretのimport Promiseを1件保持。JWKはobject identityのWeakMap。並行import、失敗削除、secret rotation、同kid更新を扱う。署名・claim・alg検査は毎request実行。 |
| 高 | AWS生成コード | 使用するauth種別のみを残し、未使用metadataを省く。隣接してtype/header/token/credentialsが全一致するgateだけprefix統合。異なるgateの順序とAND条件、認証拒否、size gateを維持。 |
| 中 | path照合 | 比較用pathをrequestで1回、設定prefixをbuild/module初期化で1回正規化。case flag、slash境界、canonical path、signed URL exact、response cache保護を維持。 |
| 中 | AWS query | rawとpartsをrequest内で共有。length拒否はsplit前、anomalyはraw、monitorは従来の位置でpartsを生成。object/string/multiValue/特殊名/drop動作を維持。 |
| 中 | GraphQL/DLP本文 | 共通bounded readerで必要prefixを読み、超過時は同じreaderからprefixと残りを再生。独立teeを除去。UTF-8/bytes/status/headers/上限とreport-mask-block/cancel/errorを維持。非転送はfinallyで共通cleanup。 |
| 中 | DLP regex/response | custom global regexを準備してlastIndexを初期化。逐次maskと全detector順序を維持。1chunkの連結copyとscan前の不要Response生成を削減。 |
| 中 | origin本文hash | 同一bytesをhashと転送へ使用し、本文なしはnullを維持。一時cloneと独立bufferを除去。全本文を要求するWebCrypto/public契約は維持し、暗黙の上限や署名省略は追加しない。 |
| 中 | schema検証 | pkgRootと実schema bytesが一致するcompile結果だけを1件再利用。schema read、変更/削除/解析失敗、env/auth検証は毎回確認。 |
| 中 | TypeScript loader | 同一options/text/implied formatのASTと完了したnode/depth集計を再利用。ファイルを現在の境界で読み直し、全importを新Programで再解決。論理budget・診断・cancel/deadlineを維持。 |
| 中 | NestJS wrapper alias | snapshotの宣言/動的alias依存を一度索引化し、単調worklistで依存先だけ再評価。Symbol分離、import Alias、member/destructure、mutation/escape/unknownを維持。 |
| 中 | contract drift | 個別公開APIは入力検証contextを作る共通coreを利用。結合APIだけcontextとmatching結果を共有し、既存visit budgetを省略しない。 |
| 中 | log analyze | 同期64KiB chunkとStringDecoderへ変更。全text+全行の同時保持を除去し、UTF-8、CRLF、物理行番号、最後の改行なし、診断/全件集計を維持。最大1行と集計mapのメモリは引き続き必要。 |

## Node 1MiBエラーの原因と修正

Node v24.2.0の埋込みUndici source `process.binding('natives')['internal/deps/undici/undici']` を確認した。`cloneBody` は `tee()` の元Request側branchをWeakRefとしてFinalizationRegistryへ登録する。一時cloneの回収時にfinalizerがそのbranchへ `cancel('Response object has been garbage collected')` を呼び、後のRequest構築がdisturbed bodyとして拒否していた。

GCを明示する同一probeで、beforeは3/3失敗・finalizer cancel 3回・digest時元body未消費、afterは3/3成功・当該cancel 0回・元body消費済み。通常反復でもafterの1KiB/1MiB各100回成功。最終Node負荷の1MiBは2 process×531 requestが成功し、originで実際の転送bytesからSHA256とHMACを独立再計算した。本文なしnullと分割UTF-8も回帰チェックする。GCタイミングだけに依存する再現から、単一所有者の振る舞いを検証するチェックも追加した。

専門レビューでは、新しい単一所有者化に伴うGraphQL report→後続認証拒否のupload未cancelを検出した。try/finallyと共通cleanupへ修正。修正前は401/origin0/cancel0/lock維持、後は401/origin0/cancel1/settle後lock解除。cancel開始と非同期cleanup完了は区別して記録した。

## 生成コードの変更前後 ms

Node v24.2.0 / darwin arm64。生成されたAWS handler/Cloudflare Workerを実行し、CF originはin-process stub。Request生成・response drain・origin署名再検証の時間を含むwall time。production CPU/TTFBではない。

各stageは同一driver bytes・固定入力/RSA鍵・依存でA1→B1→B2→A2。各側2独立process、通常30 warmup後の5 batch×2 process=10 batch平均を全採用。最初のrequestは別保存し、process cold startとは呼ばない。AWS routeは2,000回/batch、queryは1,000回、CFは100回。toolingは表のJSONにcountを保存し、aliasは2 warmup/1回×5 batch、他toolingは3または10回/batch。min–maxはbatch平均の範囲でp95/p99ではない。stddev、first request、全sample、失敗はJSON。

| 負荷 | before平均ms | after平均ms | 短縮率 | before batch min–max | after batch min–max |
|---|---:|---:|---:|---:|---:|
| aws-routes-0 | 0.001085 | 0.000948 | 12.57% | 0.000806–0.001927 | 0.000641–0.001601 |
| aws-routes-1 | 0.001071 | 0.000977 | 8.78% | 0.000700–0.002312 | 0.000752–0.001509 |
| aws-routes-3 | 0.001083 | 0.000987 | 8.89% | 0.000686–0.001577 | 0.000661–0.001588 |
| aws-routes-10 | 失敗/拒否 | 0.001050 | — | — | 0.000807–0.001459 |
| aws-query-0 | 0.001059 | 0.001050 | 0.87% | 0.000757–0.001786 | 0.000695–0.001915 |
| aws-query-100 | 0.064625 | 0.049503 | 23.40% | 0.062499–0.067899 | 0.047929–0.052814 |
| cf-routes-0-public | 0.038981 | 0.036268 | 6.96% | 0.028709–0.058493 | 0.026190–0.057296 |
| cf-routes-100-public | 0.030905 | 0.027779 | 10.11% | 0.024170–0.042000 | 0.019784–0.041313 |
| cf-routes-100-last-auth | 0.033474 | 0.030481 | 8.94% | 0.028626–0.041419 | 0.023552–0.040147 |
| cf-routes-500-public | 0.055213 | 0.052289 | 5.30% | 0.049198–0.071331 | 0.029540–0.095369 |
| cf-routes-500-last-auth | 0.069722 | 0.048686 | 30.17% | 0.056723–0.096392 | 0.036385–0.071975 |
| cf-jwt-HS256 | 0.059288 | 0.046112 | 22.22% | 0.053305–0.066992 | 0.036966–0.052620 |
| cf-jwt-RS256 | 0.087213 | 0.064774 | 25.73% | 0.080174–0.103806 | 0.055362–0.076684 |
| cf-graphql-1024 | 0.046052 | 0.037090 | 19.46% | 0.037739–0.053388 | 0.029768–0.047125 |
| cf-graphql-32768 | 0.156462 | 0.095811 | 38.76% | 0.140009–0.181430 | 0.086955–0.114040 |
| cf-dlp-report_only-4096 | 0.056315 | 0.055454 | 1.53% | 0.045235–0.068235 | 0.048192–0.069003 |
| cf-dlp-report_only-65536 | 0.342808 | 0.295440 | 13.82% | 0.306419–0.413582 | 0.280413–0.335181 |
| cf-dlp-mask-4096 | 0.078016 | 0.050415 | 35.38% | 0.053624–0.111230 | 0.042137–0.059942 |
| cf-dlp-mask-65536 | 0.597901 | 0.305262 | 48.94% | 0.323170–1.461825 | 0.290563–0.322430 |
| cf-dlp-custom-65536 | 0.454135 | 0.455015 | -0.19% | 0.434124–0.499864 | 0.412675–0.518478 |
| cf-origin-body-hash-0 | 0.094716 | 0.075659 | 20.12% | 0.077147–0.120587 | 0.063740–0.092140 |
| cf-origin-body-hash-1048576 | 失敗/拒否 | 2.873074 | — | — | 2.399840–4.606974 |
| tooling-validate-policy | 13.867919 | 0.088770 | 99.36% | 10.493342–22.378133 | 0.052404–0.161425 |
| tooling-project-load-cached | 21.172821 | 2.881756 | 86.39% | 14.352056–41.641556 | 2.429264–3.619125 |
| tooling-analyze-log-20000 | 73.590889 | 59.318374 | 19.39% | 59.796195–106.535278 | 52.920917–70.652958 |
| tooling-wrapper-aliases-10 | 53.096725 | 52.156862 | 1.77% | 49.263333–56.209250 | 48.719375–59.652458 |
| tooling-wrapper-aliases-100 | 458.629925 | 449.871917 | 1.91% | 435.140958–522.642166 | 438.460750–489.733000 |
| tooling-contract-drift-100 | 22.003082 | 19.890672 | 9.60% | 21.117708–22.691208 | 19.099125–20.702736 |

HS256/RS256/origin HMACはいずれもprocess内531 requestのimportKeyが531→1回。RS256のJWKS fetchは両側1回で、署名検証を再利用していない。

AWS 10 static-token route構成はbefore `viewer-request.js is 11312 bytes after optimization; CloudFront Functions allow at most 10240 bytes`、afterは9258 bytesで成功。0/1/3 routeはafter 8122/9150/9174 bytes。今回の設定に限る観測で、任意のPolicyが10 routeまでという意味ではない。小さい通常経路は約0.001msで、割合だけを根拠に有意差やend-user SLAを主張しない。custom DLPとaliasの差も小さく、速度改善の確証とはしない。

## native workerd HTTP

workerd 1.20261012.1 / compatibility_date 2026-07-20。loopbackだけでA/B/B/Aを実行し、各側2 process×110 request、各process最初10回を除く200 warm sample/size。originで受信本文からSHA256/HMACを再計算。全880 requestが成功し、全runtime/origin/temp cleanup成功。

| 本文bytes | before平均ms | after平均ms | before min–max | after min–max |
|---|---:|---:|---:|---:|
| 1024 | 0.607 | 0.569 | 0.310–2.925 | 0.333–1.828 |
| 1048576 | 4.084 | 4.022 | 3.221–6.512 | 3.175–5.249 |

Node client、loopback、workerd、origin再検証を含む時間。1MiBの差は小さく、安定した高速化の証明とは扱わない。managed Cloudflare/AWSのCPU・cold start・実network TTFB・peak memoryは未観測。

## 保存した増加・失敗とstage

- 初回ABBAではDLPと小さいalias入力が増加。不要なResponse再構築/連結copyと、過剰なalias依存購読を削減した。初回sampleを捨てていない。
- primary最終matrixのalias 10でも約52.823→68.059msの増加があり、依存購読を実際のset参照元に限定した。aliasだけ別の固定harness/ABBA stageで10/100入力を再確認した。表のalias 2行はそのstageで、古いprimary行もJSONに残す。stage間のsample・改善率は混ぜない。
- AWS 10 route size拒否、Node 1MiB disturbed/locked失敗はbeforeの失敗として保持し、ms=0や成功にしない。
- 100-controller alias probeは既定diagnostic上限で拒否。失敗を残し、benchmark専用予算10,000件/60秒を両側同一適用して再確認。production既定上限は不変。
- 初期driverのcontract fixtureはcapability/pointer不足で拒否。新規testのcompiled-module参照・route正規化期待値、型エラーを修正して再検証した。これらは製品の再現数へ加算しない。
- 最初の完全検証は658件成功/1件5秒timeoutで停止。生成子processを含む1MiB機能testの上限を15秒にし、期待する完全一致を保ってBuffer.equalsへ変更。既存c8方式の単独実行で8件成功、1MiB約133ms。追加coverage providerを指定した補助commandは未導入のため停止し、依存を追加せず既存c8へ戻した。失敗は保存し、後の成功と分離する。
- 2回目の完全検証では659件とcoverage基準が成功した後、既存VM sandboxにReadableStreamが公開されていないためCloudflare統合testが停止した。実Worker/Nodeに存在する同じネイティブAPIを既存の2 sandboxへ追加し、両統合testを対象再実行した。製品実装やAPIのfallbackは追加していない。失敗receipt/logは保持する。
- AWS runtimeの最初の75件は前回distとdummy token未設定で10件失敗。今回は固定dummyで既存compilerから使い捨てdistを作り直し、75/75成功。失敗ログも保持。

## 検証・レビュー・再現

対象208 tests成功。指摘修正の20 testsとalias最終84 testsも成功。AWS runtime75、Cloudflare runtime、ReDoS、native HTTP46＋JWKS50成功。全HTTP cleanup成功。専門レビューは初回BLOCK→共有経路の一括修正→指摘範囲最終ALLOW。最終Companion Gateは別のbinding/receiptで照合する。

`EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy npm run test:ci` はexit 0、183228.191ms、Vitest 39 files/659 tests成功。実認証secretや外部負荷試験は使用していない。hosted CIの結果はPRへ記録する。

再現は `npm run build:ts` 後、`node scripts/benchmark-edge-runtime.js --root <比較対象checkout> --fixture <両側共通のsynthetic鍵JSON> --output <結果JSON>`。fixture未作成ならdriverがsynthetic keyを一度生成する。alias確認は `--only tooling-wrapper-aliases`、0件はError。before checkoutは基準HEADへbaseline patchを適用して同じ依存でbuildする。baseline patchとsource hashesにより前回未commit修正を含めた比較条件を特定できる。raw evidenceは `reports/edge-optimization-implementation/`、PRには測定driver・全sample JSON・この報告書を含む。
