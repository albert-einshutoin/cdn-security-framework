# 生成Cloudflare Workerの予備計測 — 2026-10-16

状態：**部分測定で失敗、資格判定INCONCLUSIVE**。関連：[Issue #1026](https://github.com/albert-einshutoin/cdn-security-framework/issues/1026)。Issue完了・性能ゲート確定とはしません。

## 環境・負荷

- compiler commit：[`7f1e1c4a1d2d5e02565b71c728566d7eff2bf048`](https://github.com/albert-einshutoin/cdn-security-framework/commit/7f1e1c4a1d2d5e02565b71c728566d7eff2bf048)。source tree `45198d20e9138dfe7ec93e5a4c73a2d9f83053c9` はmainのmerge `597335d5e3a97eedc74a1adf31e30cb0f01bf47d` と同一です。
- 実Cloudflare Workers Free、compatibility date `2026-10-12`、flag `global_fetch_strictly_public`。検証gateway → Service Binding → 生成Workerまたは `fetch(request)` のno-op → 合成HTTP origin。JWKS・認証値も合成fixtureです。生成コードに計測処理を挿入せず、`--no-bundle` でデプロイしました。deployment versionを保存しましたが、remote module bytesの再download・hash照合は未実施です。
- 通常GET、正規表現256件・約8KiBパス、GraphQL 64KiB、1MiB本文署名、RS256/JWKSの5ケース。選定した正常・拒否、転送内容、hash、署名、security headerに正当性チェックを設けました。
- 入力は合成値です。GraphQL 64KiBは小さなqueryを空白で埋め、8KiBパスはASCII反復、1MiB署名本文は同じASCII文字を反復しています。同じbyte数の複雑な本番入力を代表するものではありません。
- 同時client要求は最大4件、開始頻度は最大50件/秒に制限。上限付きclosed-loop試験で、固定throughputの維持や飽和性能は測定していません。PoPはKIX/PDXが混在しました。
- 予定は各case・variant・runでwarmup100件＋測定500件を3周、別のno-op A/A区間も用意。実際は8,809要求を開始し、500件の測定区間13個＝6,500件を保存しました。完了series＋smokeの個別行は8,314件。中断seriesの495件は個別保存しておらず、結果分類はunknownです。

## CPUの観測値

以下は**pilot全体のproviderログ集計表示値**です。起動・smoke・warmup・完了/中断した測定区間を含み、各500件の測定区間だけのCPU分布ではありません。今回の専用Worker名prefixに限定し、Worker別に `$workers.cpuTimeMs` を集計しました。有効CPUサンプル数、元データの分解能、query sampling、分位点推定の精度は未確認です。`uniq($metadata.requestId)` をCPUサンプル数には採用していません。

|生成ケース|CPU p50 ms|CPU p95 ms|CPU p99 ms|
|---|---:|---:|---:|
|通常転送|1|1|2|
|正規表現256件・約8KiBパス|1|2|5|
|GraphQL 64KiB|1|3|6|
|HMAC本文署名1MiB|3|5|15|
|RS256/JWKS|1|4|7|

複数入力を共有するno-opの表示は1 / 1 / 2msでした。分位点を差し引いて各機能の追加CPUにすることはできません。gateway・originは別系列とし、Service BindingのCPU rollup帰属が未確定なため分位点を加算していません。RS256には初回鍵取得と後続要求が混在し、全isolateのcache hitは証明していません。

GraphQL Analyticsでは、通常通過・生成物のrun 0だけCPU p50/p95/p99推定 **0.941 / 1.369 / 2.028ms** を取得しました。送信500件に対する推定要求数は520、`avg.sampleInterval` は約4.19、quantile reservoirのNはunknownです。CPU/wallのraw fieldはmicrosecondsで、msへ換算しました。残り16/17区間では対象Workerのデータが空で、時間を置いた1回の再確認でも空だったため **UNKNOWN** を保持しています。API rate limitによりlifetime queryも未完了です。この推定値とpilot全体のログ表示は母集団が異なり、混合しません。

## クライアント応答時間

5ケースがそろった比較はrun 0のみです。各cellは個別500件のnearest-rank分位点、単位ms。client開始から応答本文drainまでを測定し、network、gateway、origin、本文転送、PoP混在を含みます。

|入力|no-op p50 / p95 / p99 ms|生成物 p50 / p95 / p99 ms|
|---|---:|---:|
|通常転送|22.751 / 131.785 / 140.127|23.606 / 131.429 / 133.865|
|正規表現・約8KiB|22.436 / 38.248 / 134.674|25.877 / 131.805 / 134.027|
|GraphQL 64KiB|32.826 / 137.534 / 157.774|39.758 / 143.144 / 155.617|
|HMAC 1MiB|124.535 / 187.969 / 203.523|123.405 / 190.694 / 201.849|
|RS256|26.485 / 131.179 / 135.254|24.325 / 132.163 / 138.255|

PoPの比率差だけでもp95は大きく動きます。正規表現の差や、生成物の分位点がno-opより低いことからコードの退行・改善を断定しません。製品の旧/新revision比較は行っていません。run 1の補足区間は[集計JSON](cloudflare-edge-pilot.json)に分けて保存しています。

## 失敗・削除・証跡の限界

2周目のno-op・1MiB経路で**検証gateway**がHTTP 503、`Worker exceeded CPU time limit.` となりました。provider invocation表示はCPU 10ms / wall 34ms。この経路は生成HMACコードを通りません。gatewayは本文を保持・連結・転送しますが、内部処理ごとの消費msはprofileしていません。fixture失敗から製品不具合へ帰属せず、plan・CPU上限も引き上げていません。

この試行は364.727秒で検証Worker8個すべての削除確認まで終了しました。それ以前のデプロイ試行は負荷開始前にhost再起動で中断し、15分以内の削除を達成できませんでした。8名前の不存在を確認してから1回だけ再試行しました。両試行のresourceは削除済みです。既存site、DNS、route、権限、契約は変更していません。

公開JSONは選定した集計値・負荷条件・ローカル保持証跡のSHA-256を含みます。全raw log、cloud runner/fixture、個別CPUサンプルは公開しておらず、**第三者が独立して再現できるbenchmark packageには未到達**です。認証情報、account識別子、デプロイURL、ローカルpath、raw request headerは掲載しません。文書CIで過去測定を再実行することもありません。

## 正式なベンチマークに必要な条件

1. **測定fixtureの適格性。** 入力上限・正当性oracleを保ち、gatewayの不要な本文copyを減らし、そのoverheadを独立計測します。負荷hostを失っても削除できる仕組みが必要です。fixture上限・エラーは測定無効とし、閾値を緩めて成功扱いにしません。
2. **観測値と母集団の結合。** compiler、policy/input hash、生成bytes、deployment version、runtime/plan、PoP、request ID、区間を固定・記録します。対象WorkerのCPU/wallを単位・分解能・sampling率・完全性と共に取得し、欠落・エラー・timeout・打ち切りも残します。Worker実行前のCDN WAF/cache応答を生成コードの性能へ帰属しません。
3. **条件の分離。** 正常、早期/後段拒否、本文/path/header境界、JWT/JWKS cold/cache hit、GraphQL、regex、DLP、対応攻撃群に期待結果を定義。PoP、platform/event stage、cache、同時数を分離し、同じfixtureでno-opと生成物を交互に測定し、no-op A/Aも確認します。
4. **負荷方式と実際の負荷。** 固定同時数と固定到着率を測り分け、送信待ち、開始できなかった要求、error、throughput、client資源上限を記録します。HTTP負荷ツールで得るclient latencyとは別に、Edge CPUのprovider telemetryが必要です。
5. **統計・回帰基準の資格確認。** 案は比較可能なcase/variantごとに測定1000件×3run以上。A/A安定性とtelemetry完全性を満たしてからp95を評価します。p99はまず10000件×5runなどの大きな調査でtailの変動・時間相関を確認するまで記述値とします。これらはプロジェクト案で、普遍的な統計的十分性を保証しません。run/PoPの分位点は平均せず、相対閾値には計測誤差を超える絶対floorと明示的baseline reviewを設けます。本報告で閾値を強制していません。

## 利用できる既存ツール・公開スイート

今後の候補として調査したもので、今回の文書変更で導入・実行していません。

|ツール・スイート|用途|適用範囲|
|---|---|---|
|[Grafana k6](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/)・[thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/)|シナリオ、固定到着率、分位点・エラー閾値|十分なVUを確保し、dropped iterationsも報告。CPUはprovider側で取得。|
|[Vegeta](https://github.com/tsenart/vegeta)|一定rateのHTTP負荷とレポート|製品固有の入力・oracleを併用。Edge securityの共通scoreではない。|
|[wrk2](https://github.com/giltene/wrk2)|一定throughput・coordinated omissionを考慮したlatency測定|READMEがlatencyの約±1ms粒度を明記。sub-msのCPU費用の確定には使わない。|
|[OWASP CRSの回帰入力群](https://github.com/coreruleset/coreruleset/tree/main/tests/regression/tests)・[go-ftw](https://github.com/coreruleset/go-ftw)|HTTP security回帰入力の再利用。cloud modeはHTTP statusで判定|対応controlを選び、本製品の契約に期待結果を合わせる。正当性corpusだけで性能負荷の定義にはならない。|
|[OWASP Benchmark](https://owasp.org/projects/benchmark)|Java/Pythonの脆弱性検出ツール評価|ASTツール向けで、生成Edge CPUの測定をそのまま代替しない。|

本プロジェクトでは **k6＋版を固定した既存workload/oracle＋provider CPU証跡** を基本とし、対応するCRS入力を正当性検証に取り入れる設計が妥当と考えます。確認した資料に、生成Edge CPU・latency・全security動作を一つの標準scoreで満たすものはありません。他のスイートが存在しないという主張ではありません。

provider一次資料：[invocationのCPU/wall field](https://developers.cloudflare.com/changelog/post/2025-04-09-workers-timing/)、[metrics・reservoir分位点・CPU rollover](https://developers.cloudflare.com/workers/observability/metrics-and-analytics/)。

## 再実行可能なハーネスの整備

source checkoutに `benchmarks/edge/k6.js`、loopback専用native-workerd runner、共通の合成入力・期待結果、明示実行するprovider CPU collectorを追加しました。生成する製品コードは変更せず、過去のpilotを資格合格に変更するものでもありません。公式k6バイナリを別途用意し、release checksumを確認してください。npm依存・製品runtime依存には追加していません。

```sh
npm run build:ts
node scripts/edge-benchmark-unit-tests.js
mkdir -p reports
node scripts/benchmark-edge-k6.js --output reports/edge-k6-run \
  --k6 /absolute/path/to/k6 --samples 100 --warmup 20 --rate 20 --runs 3
```

出力先は毎回新しいディレクトリにします。9ケースは通常転送、method拒否、正規表現256件・8KiBパスと最終pattern拒否、空白paddingしたGraphQL 64KiBとdepth拒否、HMAC 1MiB、RS256正常・不正です。それぞれno-opと生成物で実行し、周回ごとに順序を反転します。`--only hmac --samples 1000 --warmup 100 --rate 50 --runs 3` で1MiB経路に絞れます。選定ケースの検証であり、全対応攻撃・全runtimeの実測ではありません。

gatewayは認証・期限を検査し、Cloudflareの `FixedLengthStream` とnativeの本文読み取りで長さを検証します。入力chunkごとのJavaScript読み取り・コピーを除き、短い本文400・上限超過413はtarget呼出前に拒否します。writerとreaderの完了を両方待ち、既知の長さ不一致以外のエラーは伝播します。サイズ制約とoriginの本文・hash・署名の期待結果は維持します。native workerdでの正当性確認と、managed EdgeのCPU上限エラー解消の確認は区別します。不正な期限設定もfail-closedにします。

runnerはk6のconstant-arrival-rate executorを使い、VU上限4、開始頻度上限50件/秒、preflightを含む要求上限2万件、ローカルwatchdog15分を設けます。実行時間の境界でも余分な要求を送信しません。metric欠落、期待結果不一致、dropped iterations、中断、不正・途中書込みのartifactは失敗とします。失敗seriesと解析できた完全な行のprefixを診断・raw file hashと共に保持し、不正JSONを飛ばして合格にはしません。raw fileはignore対象の `reports/` に保存し、manifest/configは合成probe認証値を含むため公開しません。

`report.json` はwarmupと測定を分け、個別k6 pointからnearest-rankのp50/p95/p99を記録します。この指標はHTTP sending＋waiting＋receivingで、接続確立・送信待ちを除きます。pilotのclient開始〜本文drain計測とは別指標です。ローカルworkerdはmanaged Edge CPUの証跡にはなりません。予算採用前にはJWKS cold/cache hitの帰属、no-op A/A安定性、hostノイズ、providerデータの完全性の資格確認が必要です。

同じfixtureを使う許可済みの使い捨てcloud計測には、`collect-edge-benchmark-cpu.js` が最大3回・各2,000eventの [Workers Observability query](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/) を行います。account/tokenはprocess環境から渡し、コマンド引数やcommitへ入れません。このqueryにもAPI資料上は `Workers Observability Write` 権限が必要です。403では取得を停止し、権限を自動拡張しません。ローカル生成ではデプロイしません。

```sh
node scripts/collect-edge-benchmark-cpu.js --directory reports/cloud-run \
  --series r0-hmac-generated-measured --worker csf-1026-HEX-hmac --version DEPLOYED_VERSION
```

collectorは成功したclient件数とpoint hashを要求し、Worker/version/時間区間を固定して、個別CPU/wallをclient ID・PoPへ結び付けます。CPU欠落・event欠落/切り詰め・PoP不明は集計値へfallbackせず `UNKNOWN` とし、不正入力、重複invocation、失敗outcome、version/区間不一致はErrorです。全件取得しても `CAPTURE_COMPLETE` と資格 `INCONCLUSIVE` を分けます。完全取得だけで性能予算、providerの元分解能、比較条件、本番SLOは確定しません。gateway・originのCPUは別系列とし、分位点の差し引き・加算をしません。ローカルの予算チェックは明示指定した相対許容値と絶対floorを使い、閾値超過の検出テストを用意しました。未実測の本番閾値は強制しません。

collectorはinvocation log（`$metadata.type = cf-worker-event`）を選び、実際のprovider応答にあるinvocationの `request.cf.colo` を参照します。例外ログを追加のCPU標本にはしません。`--model iterations` は4 VU・有界deadlineで予定件数を処理し、開始をpaceする測定モードです。VUが空くまで待つ方式で、一定の到着頻度を保証しません。HTTP時間にpace用sleepは含めません。既定の `arrival` は維持し、取りこぼしを失敗にします。50件/秒・4 VUでは、約80ms以上の遅延が重なると全VUが使用中になり得ます。固定件数の成功はこのストレス条件の合格を示さず、欠落要求や過去の失敗試行も記録に残します。

## PoP・個別ログの資格確認と反復測定

2026-10-17の小標本managed試行では、生成物180/180件、no-op178/180件のIDにCPUが対応しましたが、Service Binding先の新規Requestには `cf.colo` がなく、厳格なPoP結合は成立しませんでした。gatewayのinvocationも341/360件で、ログ欠落をリクエスト未到達と解釈できません。過去のcollectorがAPIのrun状態・総件数・ABR情報を捨てていたため、保存済み配列からサンプリングと検索結果未返却を区別することはできません。これらのCPUを正式baselineへ昇格しません。

`--topology direct` は認証・期限・サイズ制約を共通のwrapperで維持し、生成handlerを直接の公開invocation内で呼びます。入力パス・header・本文・署名のoracleはgatewayと共通です。manifestは各roleの使い捨てURLを固定し、directからgatewayへの退避を拒否します。元の生成TS、変換後handler、配備wrapperのhashを区別します。個別CPUは**wrapper込み**であり、ラッパーを除いたCPUとの同一視やno-op分位点の差し引きはしません。`x-csf-ingress-colo` とprovider invocationの `request.cf.colo` をID単位で照合します。[`cf.colo`](https://developers.cloudflare.com/workers/runtime-apis/request/) は入口data centerで、物理的な実行場所の保証ではありません。

collectorはprivate snapshotにquery結果全体を保持し、`run.status=COMPLETED`、総件数一致、明示的 `statistics.abr_level=1` を要求します。短いpageでも総件数に達するまでcursorで最大3page、各2,000件を取得します。未完了・ABR不明/有効・取得上限・空pageの早期終了は `UNKNOWN`、cursor重複や総件数変動はErrorです。全件のCPU/PoP/version/outcome照合も別途必要です。この保守的なABR判定では、providerが値を省略した応答も未資格です。残る欠落はquery receiptとclient ID差分を使って調査し、集計CPUや推測PoPで補いません。[API仕様](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/)を参照してください。

```sh
# AAでは両armを同一no-opへ送る。ABでは既存のno-op/生成物比較。
node scripts/benchmark-edge-k6.js --output reports/edge-aa --k6 /absolute/path/to/k6 \
  --only basic,graphql,hmac --samples 1000 --warmup 100 --rate 50 --runs 3 \
  --model iterations --topology direct --comparison AA
```

ABは新しい出力先と `--comparison AB` で実行します。ローカルは外部接続を遮断し、managed CPUとPoPの資格は `UNKNOWN` のままです。各case・入口PoP・arm・runで1,000件以上、3run以上を最初のp50/p95候補条件とします。PoPが分散して1,000件未満なら、そのPoPを未資格とし、別PoPを合算しません。`assessAaRepeatability` は同じcase/PoP/no-op配備の拘束、全arm/runのp50・p95変動、二項分布に基づく95%order-statistic区間幅を、事前指定した相対許容値と絶対floorで検査します。区間は独立同分布を仮定し、時系列相関への保証にはなりません。通過しても `READY_FOR_BASELINE_REVIEW` で、本番SLOではありません。p99は常に記述値とし、10,000件×5runなどの別tail調査を経て再設計します。JWKS cold/hitも明示的な別測定が必要です。

追加managed測定の見積もり（2026-10-17、本測定は未実行。下記の少量pilotで停止）:

|範囲|client要求数（warmup込み）|Worker invocationの保守的上限|予定枠|
|---|---:|---:|---|
|3ケース、AA+AB、各1,000件×3run、warmup100|39,600 + readiness等、最大40,000|80,000|同時4、開始pace最大50/秒、40分|
|9ケース、同条件|118,800 + readiness等、最大120,000|240,000（JWKS用の余裕を別途確保）|同時4、合計約90〜120分、Freeでは3日以上へ分割|

originを公開HTTPで呼ぶ分もinvocationへ含めます。現行[Free上限](https://developers.cloudflare.com/workers/platform/pricing/)は100,000要求/日、CPU10ms/invocationで、超過前に停止します。実行直前に残量を確認し、他用途の余裕も確保できる場合の追加料金見積もりは$0です。全9ケースを同日にFreeで完了する計画ではありません。Paidへの変更は月額最低$5を伴い、$0.20上限に収まりません。契約を自動変更せず、枠不足・CPU上限エラー・telemetry不完全なら測定を停止して未資格を記録します。以前の2万要求・15分許可は、この追加枠の許可に読み替えません。

2026-10-17のローカル再現結果（Apple M4、macOS arm64、Node24.2.0、workerd1.20261012.1、k6 2.3.0）: 上のAAと同条件のABを各3run実行し、測定36,000件＋warmup3,600件が全件oracle一致、invalid/drop0でした。各欄はrunごとの分位点の最小〜最大で、分位点の平均ではありません。

|ケース|AAの両側 p95 ms|生成物AB p50 ms|生成物AB p95 ms|生成物AB p99 ms|
|---|---:|---:|---:|---:|
|通常通過|4.251〜5.046|2.703〜2.895|4.854〜5.243|8.243〜11.215|
|GraphQL 64KiB|8.296〜9.994|4.553〜4.750|10.738〜11.508|17.265〜18.300|
|HMAC 1MiB|12.382〜14.210|7.587〜8.048|12.926〜13.730|17.500〜19.984|

AAは集計前に指定した相対20%・HTTP絶対floor5msの変動/区間幅チェック内でした。ただし共有Mac上でブラウザ・TypeScript検証も動作した参考計測です。CPUと入口PoPがないため資格は `INCONCLUSIVE` のままで、実Edge値、CPUの改善、一定50RPS、本番SLOを証明しません。その後のmanaged pilotではPoPと照会メタデータを取得しましたが、CPUの全件取得は未達でした。次節に結果を示します。

## 追加managed枠のpilot結果 — 2026-10-17

許可された上限は40,000 client要求、同時4件、配備・削除込み40分、追加費用$0.20以内でした。実行直前のFree使用量は要求2,028/100,000、ログ2,141/200,000で、追加料金の見積もりは$0です。既存サイト・DNS・契約を変更せず、direct target 4個と合成origin 1個を配備しました。準備・認証確認を除く配備開始から削除確認までは73.267秒、client要求は245件（readiness・不正本文確認5件、pilot240件）でした。5個すべての削除後404を確認しています。負荷はpaced shared iterations、4 VU、pilotの開始paceは20/秒、各armでwarmup20件＋測定20件、1runです。

**PoP結合は解消しましたが、providerログ欠落は未解消です。** 測定120件のclient入口PoPはすべてKIXで、取得できた111件のCPUはID・version・区間・outcome・PoPが一致しました。通常no-opは14/20件、1MiB no-opは17/20件、残る4系列は各20/20件です。API検索は全6系列でCOMPLETED、ABR=1、返却件数＝検索総件数、保存時sampleInterval=1でした。前後5秒の広い検索でも欠落9件は増えず、欠落IDを直接検索しても0件でした。数分後の独立した再照会でも同じ欠落でした。これで時間範囲、通常のpage不足、観測されたquery/ingestion samplingは切り分けられましたが、provider内部で失われたのか、未返却なのかまでは確定していません。異なる照会の行を合成して完全取得にしません。

このAPI応答には、異なるclient IDの2行に同じmetadata event IDが付く例もありました。collectorは全件が返却されたpageでcursorの一意性を測定identityに使わず、追加pageが必要な場合だけcursorの進行を検証するよう修正しました。client IDの重複invocationは従来どおりErrorです。また、ABRと独立した保存時samplingをeventsのtime-series receiptで検証し、省略・非1ならUNKNOWNとします。metadata cursorは[API資料](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/)上はuniqueですが、観測した応答はその前提と異なりました。

|生成ケース（各20件、1run）|provider CPU p50 / p95 / p99 ms|client HTTP p50 / p95 / p99 ms|CPU照合|
|---|---:|---:|---:|
|通常通過|1 / 2 / 5|40.774 / 69.255 / 78.747|20/20|
|GraphQL 64KiB|2 / 4 / 4|39.116 / 45.966 / 55.473|20/20|
|HMAC 1MiB|11 / 18 / 18|139.254 / 163.667 / 185.045|20/20|

上のCPUはpublic invocationのfixture wrapper込みのprovider報告値で、元の分解能は未検証です。整数msしか観測しておらずsub-msの差を評価できません。n=20のp99は最大値で、正式なtail基準ではありません。1MiBのno-opにもCPU13/20/20ms（17件だけの部分集合）があり、生成HMACの追加CPUへの帰属や分位点の差し引きはできません。Freeの公称10ms制限を超えるCPU値が含まれるため、少量試行のHTTP成功だけでは持続負荷への適合も確定しません。

全240件はoracle一致、invalid/drop0で、短い本文400・1MiB超413の拒否も確認しました。しかしpilotの完全取得条件を満たさず、予定のAA/AB各1,000件×3runは開始していません。正式資格はINCONCLUSIVEを維持します。次の測定は、同じ小標本が全件取得できる経路と保存の完全性を先に確立し、残量・期限を再確認してから行います。3ケース本測定はwarmup込み39,600件＋readiness等、最大40,000件・最大80,000 invocation・同時4件・40分が見積もりです。Free残量が十分なら追加従量費用は$0、契約変更を要する場合は停止します。

## 保存時samplingと1MiB fixtureの再調査 — 2026-10-17

先の9件は約34分後にも欠落したままで、単純な短時間の反映待ちでは回収できませんでした。新しい配備ではobservability.logsのenabled・head_sampling_rate=1・persist・invocation_logsを設定し、providerからreadbackしました。旧配備はnested logs設定のreadbackを保持していないため、設定差が旧9件の原因だったとは断定しません。HTTP/2の少量診断40/40件、HTTP/1.1のpilot120/120件はCPU/PoP照合に成功し、HTTP/2固有の問題とも断定できません。

続くAA本測定は、1MiB no-opの1,000件中260件失敗（503が259件、502が1件）で停止しました。no-op providerログにはCPU上限超過257件を確認し、originの保存時sampleIntervalが1を超える区間もありました。5個の検証Workerは削除・404確認済みです。生成HMACを通らない経路の失敗なので、製品HMACの欠陥とは扱いません。

fixtureの共有本文検証をnative FixedLengthStreamへ変更し、対象unit、native workerdの3ケース・両経路240要求、完全検証test:ciを通過しました。本文保持・短い本文400・過大本文413・source cancellation・未知エラー伝播を維持し、専門レビューでも指摘解消を確認しました。

|1MiB no-opの診断試行|成功/送信|HTTP p50 / p95 / p99 ms|資格|
|---|---:|---:|---|
|JavaScript chunk copy|740/1,000|106.299 / 186.878 / 254.515|失敗応答を含む未資格の試行|
|native固定長pipe|1,000/1,000|71.990 / 142.601 / 172.723|1runの診断。CPU全件取得は未達|

上表は別時刻・異なる実行条件の診断で、改善率や正式な生成物比較の根拠にはしません。native pipe後の保存CPUは996/1,000件で、ABR=1でも保存時sampleInterval=1.2571428571428571の区間がありました。欠落4件のうち3件は独立したリアルタイムログに同じIDのCPU/PoP/versionが存在し、今回は実行後の保存・取得経路で欠落したと切り分けられました。旧9件まで同じ原因だとは断定しません。[API仕様](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/)でも、保存時platform samplingとquery ABRは独立しています。

生成側warmupでは100件中1件のTCP broken pipe（k6 error_code 1201）が発生し、measuredには進まず全Workerを削除しました。成功要求への差し替えや暗黙retryは行っていません。保存CPUの欠落を集計値で補わず、リアルタイム経路のcanary・完全性検証を別の少量診断として進めます。正式なAA/反復測定の資格は引き続きINCONCLUSIVEです。

リアルタイム経路も未資格でした。canaryを受信してから開始した2回の1MiB試行は、それぞれ測定400/400件がoracle一致・invalid/drop 0でした。しかし後者は全IDの到着を最大60秒待っても、CPU/PoP/version/区間が一致したlive traceは73/400件（no-op38/200、生成物35/200）でした。新しい収集経路を正式ハーネスへ採用せず、診断用artifactだけを保持しています。Node標準WebSocketの終了未完了は、既存ws依存の検証後読み込み・有界terminate・tail所有receipt・guardian共通cleanupで対処し、28 lifecycle＋11 producerチェックと専門レビューを通過しました。後者のprocessはexit 1で正常に終了し、全tailセッション2件の削除・不在、Worker5個の削除・404を確認しました。

後者を保存ログでも照会すると、no-op195/200件、生成物200/200件でした。どちらもCOMPLETED・ABR=1・sampleInterval=1で、no-op欠落5件のうち2件はlive traceにCPU/PoP/versionが存在しました。したがってsampleInterval=1も完全取得の保証には使えず、client ID単位の照合を継続します。保存・liveの部分集合を合成して合格にはしません。

生成HMAC 1MiBの200件が完全照合できた1runでは、CPU p50/p95/p99は **4/10/25ms**、client HTTPは **125.732/185.921/206.141ms**、入口PoPは全KIXでした。wrapper込みの小標本で、CPUの元分解能は未検証、p99は記述値です。対照側のCPU欠落と反復数不足のため、AA基準・性能予算には採用しません。

この60分許可枠で実送信したclient要求は合計7,924件です。作成した検証Worker20個は全削除を確認し、既存サイト・DNS・契約は変更していません。要求・ログのFree枠内で追加料金の見積もりは$0です。予定していた全3ケースのAA/AB各1,000件×3runは、完全取得の前提を満たさず未完了です。

次の選択肢は、(1) Freeで最大300要求・同時1・最大1RPS・10分程度の低頻度診断を別枠で行う、または(2) 既存のPaid検証環境でCPUTimeMs付きLogpushを新しい独立経路として先に検証することです。いずれもまだ実行しておらず、全件取得が保証されたという主張ではありません。[LogpushはPaid限定](https://developers.cloudflare.com/workers/observability/logs/logpush/)で、[CPUTimeMsが定義されています](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/workers_trace_events/)。既存Paidの残量が十分なら新規契約費は不要ですが、保存先・アクセス権・費用の事前確認が必要です。新規Paid契約は[月額最低$5](https://developers.cloudflare.com/workers/platform/pricing/)で、許可済みの追加$0.20を超えます。

経路の完全取得確認後の本測定見積もりは、3ケースのAA/AB・各1,000件×3run＋warmupで39,600要求、canary等込み最大40,000追加要求、target/origin最大80,000 invocation、同時4・新しい60分枠です。今回分との累計は最大48,000 client要求として別途許可と残量確認が必要です。Paidの含有枠が残る場合、処理・Logpushの従量部分は$0見込み。含有枠外で80,000 invocation・最大30 CPU-ms/invocationを仮定した感度見積もりは要求$0.024＋CPU$0.048＋Logpush80,000件$0.004＝$0.076に保存先費用を加えます。30msは測定条件ではなく費用仮定で、実行前にCPU上限・保存先・他用途の消費を確認して$0.20以内に収まらなければ停止します。契約の最低料金はこの従量見積もりと別です。


## Free低頻度診断の配備段階での停止 — 2026-10-17

既存Paid検証環境がないことを確認し、別途許可された最大300 client要求（準備・warmup込み）、最大1RPS、同時1件、配備から削除確認まで10分、追加費用見積もり$0で少量診断を準備しました。通常通過・GraphQL 64KiB・HMAC 1MiBを各armでwarmup2件＋測定20件、合計132件とし、caseごとに独立した保存ログとリアルタイムログの完全性を照合し、どちらかに欠落があれば次caseへ進まない計画です。k6の診断専用コピーは1 VUと対応するpaceだけを変更し、入力・oracle・生成物は維持しました。これは正式A/A本測定ではありません。

17:34 JST時点のFree使用量は要求18,007/100,000件、ログ18,182/200,000件でした。既存トークンは同じ1アカウント・Workers Observability Editのみ・18:00 JST失効を維持してrotationし、APIのactiveと空の限定CPU照会COMPLETED/ABR1を確認しました。36件のmock lifecycle検証、11件のlive producer/adapter検証、k6 oracle不変の確認が通り、専門レビューの認証契約とcleanup reserveの指摘も修正しました。親はhard deadlineの210秒前に負荷を停止し、guardianは180秒前にcleanupへ移行します。maintained sourceは直前の完全検証済みhashと一致しています。

しかし、17:34:31.967 JSTの配備開始後、最初の合成originのupload APIはHTTP200、直後のWorker metadata取得はHTTP404（code10007）となり、Wrangler 4.151.0が失敗しました。同じCLI bytesで以前の配備は成功しています。今回のcode10007は[Workerまたはworkers.dev subdomainが見つからないエラー](https://developers.cloudflare.com/workers/observability/errors/)ですが、反映遅延・provider内部状態などの正確な原因は未確定です。原因不明の状態を一時障害と決めつけて再配備は行っていません。配備試行は1 Worker、配備完了0、tail作成0、client要求0で、CPU・HTTP分位点の新しい実測値はありません。

4.446秒で停止・不在確認を完了し、対象名5件は後続の照会でもすべて404でした。契約・DNS・既存サイトは変更せず、ローカルの平文CPU照会トークンは削除しました。追加料金は$0の見積もりで、請求確定ではありません。診断記録は`reports/issue-1026-low-rate-20261017/closure.json`、実行時のbindingとreceiptは同directoryに保存しています。今回の失敗からCPUログ欠落の原因は判断できず、全件取得経路は未確立、正式資格はINCONCLUSIVEのままです。


## 費用ゼロ診断の準備と認証阻害 — 2026-10-18

既存worktreeのHEAD `944091e99266a6d69204a37088c19858f1a4d552` から引き継ぎ、開始時の9ファイルのindex版・作業版・差分を分離保存し、旧証拠2,563ファイルのhashを記録しました。旧報告、失敗ログ、承認記録は上書きしていません。hash-onlyのraw証拠はhashだけで保護し、本文の診断には既存の読み取り可能なreceiptを使いました。

18:04 JSTの読み取り確認では既存OAuthでaccountのworkers.dev状態を取得でき、以前の対象originは404/code10007でした。一方、同じaccountの対象名に限定したCPU照会は403/code10000です。既存の収集専用トークンは10月17日に失効済みで、現在の収集権限は確認できません。Free画面は当日要求294/100,000、ログ4/200,000、期間内billable usage $0.00を示しましたが、開始直前の再確認と最終的な請求確認は別です。配備操作・診断要求・CPU取得はいずれも0件で、今回の10分枠は未使用です。

ローカルでは、CPU collectorが余分なIDを黙って除外し完全取得と判定する欠陥を回帰チェックで再現・修正しました。direct topology・case/arm・client manifestの配備先・Worker roleとidentityのhashを照合し、gateway/originのCPUをtargetへ取り違えないようにします。集計/収集sourceと実行JavaScriptのhashもidentity・収集結果へ記録します。client point件数とseriesの照合、有限な区間、余分・欠落・重複・不正bindingの拒否を維持し、照合済みの各IDにCPU/PoP/version/outcomeを保存します。この修正が過去のCPU欠落や10007の原因を解消したとは主張しません。共有k6経路に `--concurrency 1` を追加し、paceも同じ同時数から決めます。中断時はSIGTERMに応答しないk6子プロセスを2秒後に強制終了し、回収後に次seriesへ進まず失敗を保存します。製品生成コード・認証・本文oracleを変更していません。

ローカルの最小確認例（実クラウドには配備しません）：

```sh
npm run build:ts
node scripts/edge-benchmark-unit-tests.js
node scripts/benchmark-edge-k6.js --output reports/edge-local-diagnostic \
  --k6 /absolute/path/to/verified/k6 --only basic,graphql,hmac \
  --samples 2 --warmup 1 --runs 1 --rate 1 --concurrency 1 \
  --model iterations --topology direct
```

実クラウドの最小案は3ケース×2arm×（warmup1＋測定2）＝18要求、readiness最大5・本文拒否最大3を加えて26 client要求、target/origin最大52 invocationです。同時1・最大1RPS・Worker最大5・配備から削除確認まで10分を維持し、cleanup時間を予約します。upload HTTP200だけでは開始せず、Worker/version readbackと実HTTP readinessを照合する必要があります。原因不明の作成結果は同名の有界readbackだけで確認し、再uploadしません。各caseの測定全IDを同じ保存経路で照合し、欠落・sampling・CPU上限・通信失敗があれば次caseへ進みません。これは準備案であり、配備経路の修正・実Edgeでの受入は未完了です。

続行には同じaccountだけの短時間有効なWorkers Observability Edit認証が必要です。権限拡大・有料化は行わず、秘密値をチャットやPRへ記載しません。新しい記録は `reports/issue-1026-zero-cost-20261018/` に保存しています。CPU全件取得は未達、正式資格は **INCONCLUSIVE**、Goalは未完了です。Draft PRの静的受入やローカル検証でこれらを置き換えません。


## 費用ゼロ診断の実行と読戻し修正 — 2026-10-18 19:07 JST

上記18:04 JST時点の認証阻害は、同じaccountだけ・Workers Observability Editだけの今回用トークン（19:30 JST失効）で解消し、既存OAuthは同じscopeのまま更新しました。開始直前のFree画面は当日要求1,056/100,000、ログ6/200,000、期間内billable usage $0.00でした。認証値は公開せず、収集トークンの平文ファイルは今回枠の終了時に削除しました。

許可されたCloud枠を1回使用しました。4 Workerへ各1回だけuploadし、origin/bare/basicの3件は設定・version/etag・100% deployment・workers.dev状態の読戻しを通過しました。GraphQLはupload HTTP200の直後の設定GETが404/code10007になり、HTTP readinessへ進む前に停止しました。同じGraphQLの設定GETは9.245秒後のcleanupでは200でした。これは今回の設定読戻しの一時的不在という観測であり、過去のCLI障害の根本原因やHTTP到達性を確定しません。根本原因はUNKNOWNです。

client要求・CPU標本は0件です。作成した4件を所有tagの照合後に削除し、未作成のhmacを含む対象5件すべての設定GETで404/code10007を確認しました。枠全体は32.228秒、最初の配備操作から最終不在確認までは32.172秒でした。guardian停止・残存Worker 0件・10分以内の終了を確認しています。追加費用は$0の見積もりで、最終請求は未確認です。

この観測から、成功したuploadと同じ名前の設定読戻しだけを、正確な404/code10007に限り最大6回・再試行間隔2秒で確認する修正を加えました。各APIの5秒上限、開始時刻基準390秒の負荷cutoff、600秒の削除期限は維持します。最終404、未知の404、403、通信失敗、所有tag・version・etag・sampling・deployment不一致はErrorで止めます。uploadやDELETEの再送、別名への切替え、CLI更新、別経路へのfallbackはありません。cleanupも同じ有界readerを使い、upload試行済み・DELETE未試行の対象が不在のままならUNKNOWNとし、削除済みとは判定しません。cleanup全体は共有80秒と600秒期限の1秒前のうち早い方までに制限し、各APIを始める前に最大6秒（pace1秒＋I/O5秒）を予約します。DELETE前には後続の不在確認を含む12秒を確保し、再試行待機も同じ予算に含めます。guardianが残した不完全receiptは親が1回だけ同じ経路で再確認し、UNKNOWNを成功へ補完しません。

修正前に「5回不在の後で同じ設定が読める」回帰チェックの失敗を確認し、修正後は有限回での成功・上限到達時の停止・他のエラーを再試行しないことを確認しました。Cloud実行時のsource/実行JavaScriptは `reports/issue-1026-zero-cost-20261018/cloud-executed-snapshot/mapping.json`、実行結果は同directoryの `cloud-closure.json` に対応します。この読戻し修正はローカル検証であり、今回のCloud実行で受入済みとは扱いません。

Cloud実行は固定account・今回の承認receipt・排他的な開始markerへ拘束し、出力directoryやreceipt名を変えて2回目を開始できません。独立guardianは親の切断時にも同じ所有・削除receiptを使って後片付けし、結果不明のDELETEを再送しません。初回枠は使用済みで、新しいCloud枠は未承認です。CPU全件取得・実HTTP readinessは未達、判定と正式資格は **INCONCLUSIVE**、Goalは未完了で、PRはDraftのままです。ローカル再現は前節のcommandと `node scripts/edge-benchmark-cloud-unit-tests.js` で行い、unit検証から実Cloudへは接続しません。


## 承認された追加1回の結果 — 2026-10-18 22:00 JST

同じaccount・追加費用見積もり$0・最大26 client要求・1RPS・同時1・最大5 Workers・配備から削除確認まで10分の追加1回が明示承認されました。実行sourceの承認IDと上限をこの追加枠へ固定し、使用済みの旧承認は拒否する回帰チェックを追加しました。新旧の排他的markerと証拠は分離しています。同じaccountのWorkers Observability Editだけ・21:45–22:45 JSTの短期トークンを用意し、OAuthはscopeを変えず更新しました。直前のFree画面は当日要求1,778/100,000、ログ15/200,000、期間内billable usage $0.00でした。

5 Workersすべてがupload後の設定・所有tag・version/etag・100% deployment・workers.devの読戻しを通過しました。実HTTPのreadiness5件とHMAC本文拒否3件（400/400/413）も成功し、basicの両armでwarmup各1件・測定各2件がoracle一致、invalid/drop 0でした。合計14 client要求です。今回の配備読戻しと実HTTP確認は成立しましたが、過去の10007の根本原因は確定しません。

最初のbasic bare測定の保存CPU照会はCOMPLETED・ABR=1・sampleInterval=1で1件を返し、期待2 IDのうち1 IDが欠落しました。取得した1件はKIX・正しいWorker/version・outcome okで、providerのCPU値は0ms、wall値は6msでした。欠落を0msへ補完していません。判定はUNKNOWNで、basic生成側のCPU照会とGraphQL/HMAC負荷へ進まず停止しました。後続の読み取り専用画面でも、今回のbare Workerは1時間の範囲で4要求に対し保存イベント3件でした。狭い照会区間だけでは欠落を説明できず、保存・取得経路の根本原因はUNKNOWNのままです。推測による時間拡張・retry・経路合成をcollectorへ追加していません。

所有を確認した5 Workersを各1回のDELETEで削除し、全5件で最終settings GET 404/code10007を確認しました。guardian停止、枠全体82.601秒、最初の配備操作から終了確認82.525秒、平文収集トークンファイル削除を確認しました。新しい記録と実行bytesのsnapshotは `reports/issue-1026-zero-cost-20261018-followup1/` に保存しています。実行前に同じsource bytesの専門レビューALLOWと `VITEST_MAX_WORKERS=2 npm run test:ci` 成功を確認しました。

追加枠は使用済みです。追加費用は$0の見積もりで、最終請求は未確認です。CPU全6母集団の完全取得は未達、正式資格は **INCONCLUSIVE**、Goalは未完了、PRはDraftを維持し、merge呼び出しは0回です。

2026-10-19の[CPU欠落診断](cloudflare-cpu-diagnosis-20261019.ja.md)で、保存証拠・実行bytesの再照合、公式仕様、3仮説とローカル失敗注入15項目の結果を整理しました。挙動欠陥は再現せず、runtimeの推測修正はありません。次は新規client要求・invocation・Workerをすべて0とする既存ログ4条件の照会案です。追加承認前のCloud操作は0件で、正式資格はINCONCLUSIVEを維持します。
