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
