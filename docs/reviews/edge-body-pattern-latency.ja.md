# GraphQL・1MiB本文・正規表現の遅延調査と改善

基準製品は PR #1110 の `1e0dc81c10c706697e33f5bb243cc783dba0c3aa`。測定基盤の保存commitは `67254c28e462901f6290aae4ab8ba48b88a7e1ea` で、製品sourceは同一。今回の未commit sourceをSHA-256で固定し、同じ依存でbuildした基準archiveと比較した。#1110は未mergeのため、この変更のPRはそのbranchをbaseとする。

## 実装した改善と維持する契約

- **高: 正規表現の不要な照合を生成側で省く。** case-sensitiveで代替を持たない単純な先頭literalだけから必要条件を求め、隣接するpatternの共通literalが3文字以上なら1回のincludesでまとめて判定する。optional quantifierは直前のliteralを除外する。必要条件が証明できないpatternは同じgroup表現内で条件無しの従来RegExp照合を行う。元のregex、順序、enforceの最初の遮断、raw/normalized検査、monitorの全診断を保持。既存のregex受理・ReDoS検証を通った後に生成し、仕様上限を変更しない。
- **中: GraphQLの長い空白をnative走査。** 16個のASCII spaceが続く箇所だけ共有helperから /\S/ による走査を使う。短い空白は従来の文字コードループ、非ASCII空白の /\s/ 分類を維持する。leading paddingも対象にし、keyword Setをrequest毎に再生成しない。field/alias/depth上限、文字列・コメント、本文bytes、診断を保持。
- **中: 測定基盤の検証コストと混同を削減。** 検証originの期待本文hashを事前計算し、実際の本文はSHAを1回計算して内容・body-hash header・HMACの全検証へ再利用する。chunkの不要なcopyも省いた。製品側の高速化量には加算しない。compiler-root、GC/event-loop、origin read/verification、接続保持数を記録し、同時負荷でも前後をAB/BAのbatchで比較する。

HMACで元Requestから直接arrayBufferを読む案は試測定の直列medianが3.223833→3.175459ms程度で、同時p95も不安定だったため撤回した。製品の1MiB本文読込み・SHA-256/HMAC・署名と転送bytesの共有・stream所有権は元のまま。AWS生成物や公開policy契約は変更しない。

## 測定方法と境界

Apple M4 / macOS arm64 / Node v24.2.0 / workerd 1.20261012.1、compatibility date 2026-07-20。loopback client → native workerd → 検証用HTTP originのみ。前後を同一workerdの別isolateへ置き、同一driver・policy・originで比較する。各variantはfirstを別記、warmup200、測定1000。直列と16同時それぞれ独立processで2回実施し、以下は各variant2000sampleのnearest-rank median/p95。各batchは最大16request、variantのbatchを完了してから他方へ進み、順序をAB/BA交替する。外れ値は除外しない。

通常/正規化/深いpath、GraphQL 2/32/64KiB・整形・trailing/leading padding・65535/65536bytes、1MiB転送と別policyのHMAC、256regexの短い/約2KiB/約8KiB missを測定。hot-path fixtureのGraphQL本文上限は1MiB。既存203case matrixの64KiB上限・65537bytes拒否とは別policyであり、仕様境界はmatrixで確認した。

HTTP wall時間にはclient、Node origin、接続・queue・転送が含まれる。16同時のburstと203case matrixのcontinuous closed-loopは異なる負荷形状であり、旧値236msなどとの単純な前後比較はしない。Worker CPU、本番PoP、外部networkやWAFの時間は未測定。first isolateはprocess共通の起動負担も含み、cold改善とは解釈しない。重い検証と並行測定していない。

## 生成edgeの変更前後ms

### 直列

| 負荷 | median ms 前 → 後 | p95 ms 前 → 後 |
|---|---:|---:|
| control-short | 0.144041 → 0.139709 | 0.586417 → 0.597459 |
| canonical-deep256 | 0.203583 → 0.197292 | 0.707541 → 0.672167 |
| control-normalized | 0.141000 → 0.136709 | 0.477417 → 0.503584 |
| graphql-2048 | 0.198875 → 0.189833 | 0.882000 → 0.798584 |
| graphql-32768 | 0.424875 → 0.409250 | 1.070791 → 1.056167 |
| graphql-65536 | 0.808208 → 0.807333 | 1.761125 → 1.741333 |
| graphql-65536-pretty | 0.713250 → 0.729833 | 1.554917 → 1.528375 |
| graphql-65536-padding | 0.463875 → 0.409167 | 1.212209 → 1.166417 |
| graphql-65535-boundary | 0.432125 → 0.383500 | 1.129084 → 1.023500 |
| graphql-65536-boundary | 0.437666 → 0.392083 | 1.050834 → 1.023209 |
| graphql-65536-leading | 0.687625 → 0.444750 | 1.367833 → 1.083459 |
| body-forward-1048576 | 3.009416 → 2.985417 | 5.512750 → 5.343459 |
| response-index-short | 0.218208 → 0.216333 | 2.311125 → 2.448333 |
| response-index-deep256 | 0.258000 → 0.253875 | 1.412500 → 1.290958 |
| index-8KiB-hit | 0.439958 → 0.441333 | 1.129291 → 1.131792 |
| index-8KiB-miss | 0.454625 → 0.455792 | 1.235833 → 1.147250 |
| patterns-short | 0.151167 → 0.144875 | 0.634917 → 0.586750 |
| patterns-2KiB | 0.707917 → 0.260542 | 1.407750 → 0.770542 |
| patterns-8KiB | 2.349042 → 0.495167 | 3.653875 → 1.213417 |
| HMAC / body-forward-1048576 | 3.216125 → 3.242167 | 4.455416 → 4.477708 |

### 16同時

| 負荷 | median ms 前 → 後 | p95 ms 前 → 後 |
|---|---:|---:|
| control-short | 1.327666 → 1.391792 | 3.130708 → 2.715792 |
| canonical-deep256 | 2.600208 → 2.500833 | 3.995666 → 4.002292 |
| control-normalized | 1.184500 → 1.167458 | 3.056291 → 2.829791 |
| graphql-2048 | 1.983333 → 1.682250 | 4.768458 → 3.190375 |
| graphql-32768 | 5.668541 → 5.105917 | 7.521458 → 7.110584 |
| graphql-65536 | 8.599916 → 8.308083 | 11.884333 → 10.642333 |
| graphql-65536-pretty | 7.740041 → 7.608208 | 10.227708 → 11.178583 |
| graphql-65536-padding | 5.328084 → 4.136750 | 9.082833 → 7.925875 |
| graphql-65535-boundary | 5.177917 → 4.362625 | 10.046250 → 8.202875 |
| graphql-65536-boundary | 5.154583 → 4.370000 | 9.996625 → 8.060708 |
| graphql-65536-leading | 8.238250 → 4.283875 | 12.591208 → 9.836875 |
| body-forward-1048576 | 29.425916 → 29.208250 | 39.603292 → 42.392292 |
| response-index-short | 1.159458 → 1.132208 | 2.818542 → 2.952042 |
| response-index-deep256 | 2.747458 → 2.464417 | 5.434667 → 4.585750 |
| index-8KiB-hit | 5.538084 → 5.618292 | 9.029417 → 8.557708 |
| index-8KiB-miss | 5.437083 → 5.417834 | 7.391625 → 7.633708 |
| patterns-short | 1.541166 → 1.382000 | 3.021208 → 2.808042 |
| patterns-2KiB | 9.832959 → 2.507167 | 13.827917 → 6.019875 |
| patterns-8KiB | 33.751959 → 5.643917 | 40.230000 → 7.624417 |
| HMAC / body-forward-1048576 | 36.133083 → 36.101291 | 46.152208 → 44.429167 |

長いleading paddingの16同時medianは約48%短縮、256regex・8KiB missは約83%短縮した。HMACの1MiBは製品経路を変更していないため、36.133→36.101msという差を高速化の根拠にしない。短いGETや整形GraphQL等のp95には上振れもある。全条件での改善は主張しない。

## GraphQL同時負荷p95の変動調査

- 旧matrixでは65536bytesのp95が236.849/13.081ms、1profileの別runでは22.073/9.574msだった。当時の各sampleに対応するCPU/OS/GC traceはなく、その発生源は特定できない。
- 今回のpilotでも最大423.372ms、client/origin event-loop最大140.640msを観測した。同一MacでPerfPowerServices等の高CPU使用も観測したが、過去のp95や各requestとの因果関係は未確定。無関係なprocessを停止していない。
- 同一基準code・module hash一致のA/A対照でも65536境界のp95は7.918916/10.228417msと異なった。medianは5.187083/5.108542ms。p95差だけをcode差と断定できない。leading paddingのA/A p95は14.023042/14.052542ms。
- 最終65536境界はrun別p95が9.240167→8.250875、10.064500→7.266166msで両方改善。leading paddingも12.603291→10.277833、12.492209→9.775250ms。
- 整形GraphQLはpooled p95が10.228→11.179msと上振れたが、run別の符号は逆転した。追加の独立・warmup1000の集中測定でも13.073916→11.173459、9.973625→11.214291msと符号が逆転し、medianは両方短縮した。全rawを保持し、追加runを元の200-warmup分布へ混ぜていない。安定したp95改善・悪化の原因をこの測定だけでは確定しない。

接続保持の対照（同じ基準製品・200sample/50warmup・16同時）では、全profileでAgentを保持した場合とprofile完了後destroyする場合で、65536bytesのp95は7.948958/8.956042ms。65535bytesは13.963458/7.715750ms。socket保持数は161/16だが、結果は一方向でなく、接続保持だけを原因とする根拠はない。両対照203caseとも成功。

## 1MiB本文の内訳と測定失敗

全profileで接続保持した基準matrixの1MiB HMACはmedian47.713542/p95152.346125ms、event-loop p9554.657023/max78.970879ms。originのread median0.352750/p951.296250ms、独立検証median0.477125/p951.044750ms。Node GCは複数回発生し最大4.631209msであり、それだけで全遅延を説明できない。profileごとにAgentを破棄する対照はmedian45.457292/p9586.515708msだった。新しい期待hashの事前計算は毎requestの製品処理を変えず、測定器側の重複処理だけを削減した。

最終candidateの203case matrixでは1MiB HMAC median36.140167/p9550.679541ms、event-loop p9521.331967/max26.361855ms。これは時系列・接続条件・測定基盤が旧matrixと異なり、製品の改善率に使わない。最終の共通driverによる前後比較は上表のHMAC行を正本にする。1MiBを読み、hashし、完全転送する費用は残る。Worker内とhost schedulingの厳密な分離は未完了で、本番のCPU時間を推定しない。

最初の診断full run（1000sample/200warmup）は93case後のJWKSで5秒のrefresh観測窓を超え、失敗した。製品のtimeout/上限やJWKS guardは緩めず、失敗JSONとcleanupを保持し、診断matrixを200sample/50warmupへ限定して再実施した。成功runへ混入しない。

## 生成側の費用

同一process内でprogrammatic compileをAB/BA交替、各variant warmup10・測定60回。出力write込み、CLI起動時間を含まない。

| regex数 | median ms 前 → 後 | p95 ms 前 → 後 | 生成JS bytes 前 → 後 |
|---|---:|---:|---:|
| regex-0 | 9.314625 → 9.308750 | 41.229375 → 24.398334 | 21515 → 21653 |
| regex-256 | 8.261125 → 8.386166 | 9.699833 → 9.661791 | 28018 → 28194 |
| regex-1024 | 11.922958 → 12.028083 | 17.354084 → 23.222375 | 48010 → 48186 |

256本のgroup構築でmedian約0.125ms、1024本で約0.105ms増加する。regex無しfixtureの生成JSは138bytes、256/1024本は176bytes増加。ビルド時の必要条件計算と小さい出力増加によってrequest毎の不要な照合を省く。

## 契約・検証・レビュー

- 追加契約4件は変更前4/4成功。振る舞いを維持する最適化であり、変更前の機能不良を捏造しない。
- 最終sourceで対象8file・40/40成功。optional/alternative/i/escape/anchor、enforce/monitor診断、Unicode空白・alias/field、完全な1MiB転送・clone禁止、native同時比較のHMACと端数batchを確認。
- build:ts、正規のgolden8件再生成、diff whitespace check成功。AWS golden差分無し。
- native generated Workerの既存203caseすべて成功。status/遮断本文、origin到達数/URI/bytes/独立HMAC、JWKS取得回数・状態遷移、DLP/認証/監視mode等のoracleを保持。200sample/50warmup/c16の確認用runで、1000sample比較と混同しない。
- HTTP E2E46case + JWKS50case成功、worker/origin/temp/portsのcleanupすべて成功。全paired comparisonと診断runのcleanupも確認。
- セルフレビューと高リスク専門レビュー（gpt-5.6-sol medium）はP0/P1/P2なし。採用しない直接readを撤回後、該当箇所とgoldenに限定した最終レビューもALLOW touched=[]。
- 初回の完全検証は新helperの配布inventory未登録で停止した。docs/api-manifest.jsonへ生成helperのJSと型定義を登録し、既存の完全一致allowlistを維持した。修正後の実tarball install・Cloudflare生成を含むpackage smokeとAPI契約検証は成功。初回失敗ログを保存した。
- このsource-freezeレポートでは配布metadata修正後のCompanion Stop Review Gate・完全検証・最終hosted CIはpending。実施結果はPR本文/checksを参照し、この保存reportから成功を推定しない。

## 再実行

```sh
# baseline: 67254c2（製品sourceは1e0dc81と同一）を別dirへ展開し、同じlockfileでbuild:ts済みにする
node scripts/benchmark-edge-http.js --root "$CANDIDATE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --samples 1000 --warmup 200 --concurrency 16 --output paired.json
node scripts/benchmark-edge-http.js --root "$CANDIDATE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --path-pattern-count 256 --samples 1000 --warmup 200 --concurrency 16 --output regex.json
node scripts/benchmark-edge-http.js --root "$CANDIDATE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --origin-body-hash --only body-forward-1048576 --samples 1000 --warmup 200 --concurrency 16 --output body.json
# 上記を独立processで2回ずつ、concurrency1も同様に実施
node scripts/benchmark-edge-http.js --root "$BASELINE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --samples 1000 --warmup 200 --concurrency 16 --output aa.json
node scripts/benchmark-edge-security.js --compiler-root "$BASELINE_ROOT" --diagnostics true --agent-scope all --samples 200 --warmup 50 --concurrency 16 --output diagnostics-all.json
node scripts/benchmark-edge-security.js --diagnostics true --agent-scope profile --samples 200 --warmup 50 --concurrency 16 --output security-203.json
node scripts/cloudflare-http-e2e-tests.js --report http-e2e.json
```

主要5負荷の全warm sample、全負荷のfirst・paired delta summary・run別summary、生成source/module/policy/driverのSHA、診断の選択結果、203caseの結果、証拠hashと生成側driverを[構造化データ](edge-body-pattern-latency.json)へ保存。全負荷の精度を丸めていないsample・origin timing・pair deltaを含むraw、全診断rawと失敗runは既存のignored `reports/edge-body-pattern-latency-20261016` に保持し、JSONからhashを照合できる。
