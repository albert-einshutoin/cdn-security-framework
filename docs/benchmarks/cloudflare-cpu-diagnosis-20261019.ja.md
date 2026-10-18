# Issue #1026: 保存CPUログ欠落の診断 — 2026-10-19

原因は **UNKNOWN**、正式資格は **INCONCLUSIVE**、Goalは未完了です。今回の調査では実Cloud操作を行っていません。再配備より先に、保持期間内の既存ログを4条件で読み取る案を示します。これは未承認・未実施です。

## 観測と証拠の結合

10月18日の追加承認枠では5 Workersの配備readback、HTTP readiness5件、本文拒否3件、basic両armのwarmup各1件・測定各2件が成功しました。合計14 client要求です。最初のbasic bare測定では、期待する2 IDをM0/M1とすると、保存CPU照会はM1だけを返しました。COMPLETED・ABR=1・sampleInterval=1でもM0は欠落し、次のCPU照会・caseへ進まず停止しました。その後の同じbare Worker限定・1時間範囲の画面でも、readiness/warmup込み4要求に対し保存イベントは3件でした。取得済みM1のCPU 0msは正当なprovider値であり、M0のCPUを0とした値ではありません。

調査開始時に確認した挙動sourceの納品HEADは `6e1e6e750d2daf29cb547ee241be17c430477f82` です。実行時に記録されたGit HEADは親の `e487cb41d3e0b655669c9cf6337f5fd69f7c86ac` で、当時の作業treeの実行bytesは別途固定されていました。実行した13ファイルのsnapshot、専門レビュー・完全検証のhash、identity内のsource6件・実行JavaScript5件、生成module7件を再照合しました。現在の挙動sourceと実行bytesは一致します。Git HEADだけを実行bytesの証拠にしていません。

identity→client manifest、測定series→client points、CPU結果→provider captureのhash連結と、取得済みM1のWorker/version→配備結果も一致しました。必要な派生report/identityメタデータだけを読み、既存hash-onlyのraw provider・points・manifest・生成物・UI証拠・実行snapshotはhashだけで確認しました。失敗・UNKNOWN記録、旧証拠2,563件と開始時index/working保存版を保持します。非公開の再検証記録は `reports/issue-1026-cpu-hypotheses-20261019/` に分離しています。

## 公式根拠の確認

以下は2026-10-19 JSTに確認した範囲です。最大保存遅延やclient全要求の永続化完了を示すwatermarkは、確認した仕様では見つかりませんでした。完全取得の保証、またはFreeでは完全取得が不可能、のどちらも断定しません。

| 論点 | 確認した契約と今回への意味 |
| --- | --- |
| 時刻・pagination・完了 | [Telemetry query API](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/) は区間・イベント時刻をUnix msで定義し、COMPLETEDはquery runの状態としています。cursorは最後の `$metadata.id`、次pageは `offsetDirection: next` です。時系列granularityの説明から、個別eventの時刻を秒へ丸める修正は導けません。保存済み行を検索した完了と、client母集団の保存完了を分けます。 |
| sampling | 同APIのsampleIntervalは一致した保存イベントの保存時samplingを示し、query ABRとは独立です。いずれも1だった今回、返らなかったM0の存在・保存状態までは説明できません。 |
| 保持・設定・大きさ | [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/) はFreeのログ200,000件/日・保持3日、invocation logsとhead sampling、256KB超ログのtruncationを説明しています。1MiB本文そのものが1MiBログとして保存されたとの根拠はなく、今回失敗したのは本文なしbasic bareです。12月1日以降の料金変更を10月の枠へ適用しません。 |
| delivery/buffering | [Real-time logs](https://developers.cloudflare.com/workers/observability/logs/real-time-logs/) は保存しない経路で、高traffic時のsampling/dropがあります。[OpenTelemetry export](https://developers.cloudflare.com/workers/observability/opentelemetry-export/) の数分の到着遅延は外部destinationへの説明です。この遅延をWorkers Logs保存の最大待ち時間へ流用できません。 |
| Freeの取得経路 | 今回CPUを取得できた保存Logs APIを継続対象にします。real-timeの通常出力例はCPU項目の保証を示さず、既存の不完全なlive経路も採用しません。[Tail Workers](https://developers.cloudflare.com/workers/observability/logs/tail-workers/) と[Workers Logpush](https://developers.cloudflare.com/workers/observability/logs/logpush/) はPaid対象です。OTelの現行ページだけではFreeでの可用性・CPU完全取得を確認できず、新しいdestinationや収集経路は追加しません。 |

公式[TypeScript SDKの固定commit](https://github.com/cloudflare/cloudflare-typescript/blob/e00d6c475fe5a5b7fa8b08a0e36e110f8d4ed563/src/resources/workers/observability/telemetry.ts)でも、queryはPOSTとresultのunwrapで、countは検索一致件数、offsetはevent cursorとして定義されています。ingestion完了を待つ実装ではありません。公開SDKから非公開の保存基盤の配送保証は推定しません。公式docsの固定commitは `887ef7aac8cde3c0a6bb8c817aa401f3909e391a`、参照ファイルのbytes/SHAは非公開mappingに保存しました。

## 検証仮説

| 仮説 | 支持する観測 / 反証・未確認 | 保存証拠で判定できる範囲 | ローカルで確認できる範囲 | Cloudでのみ識別できる範囲 |
| --- | --- | --- | --- | --- |
| H1: providerの保存・可視化段階で未到着または欠落 | APIと後続UIの両方が不足。設定と取得済み行のsamplingは1。保存前欠落、保存後のindex遅延、長い遅延の区別は未確認。 | 当時の検索結果が不足した事実。永久欠落とは断定不可。 | 完了queryが1行だけでも、client期待2 IDに対してUNKNOWNになること。 | 同じ過去区間を今読むとM0が現れるか。現れても保存遅延とindex遅延は分離できない。 |
| H2: 時間・type・serviceの検索条件による取得漏れ | M0は区間先頭付近。ただし1時間のUIでも不足し、単なる狭い時間幅説は弱い。欠落行の本来のmetadataは不明。 | ms単位・query/series区間の一致。count1/limit2000なので、記録されたcountを信じる範囲ではpage残りの取りこぼしではない。 | subsecondの先頭event保持、区間外拒否、短いpageからのcursor継続。 | 区間だけ拡張、typeだけ除去、serviceだけ別fieldへ変更した対照で、同じIDが返るか。 |
| H3: client母集団・対象設定/Worker/versionの取り違え、または照合後の棄却 | 両IDのoracle、生成物・配備readback、M1のWorker/versionは一致。返却行を誤って黙殺した観測はなく、M0のprovider行自体がない。M0の実version/ログ状態は直接確認できない。 | 件数・ID・生成物・実行bytesの結合、取得済み行の正しいbinding。 | 欠落・誤Worker/version・type・重複・CPU欠損を成功にしないこと。 | M0が取得できた場合のID/Worker/version/outcome/CPU等。取得できなければ個別設定状態は確定できない。 |

ローカル失敗注入15項目は全PASSでした。実ネットワークは使わず、既存collector/CPU helperへ合成応答を渡しました。先頭subsecond行、正当な0ms、欠落CPU、query/保存sampling、pagination、truncation、誤binding、重複、相補的な不完全captureを確認しています。provider側欠落をローカルで再現したという意味ではありません。修正対象となる挙動欠陥は見つからず、runtime source・collectorの時間幅・待機・収集経路を変更していません。成功済み720テストや旧HEADのCIを再実行して新しいCloud証拠に見せていません。

再現は同じcheckoutで `/usr/bin/env -i PATH="$PATH" /bin/sh reports/issue-1026-cpu-hypotheses-20261019/offline-probe.sh`。実行JavaScriptは実行前に既存検証済みhashへ照合済みです。probeはraw証拠・token・OAuthを読みません。結果ファイルは排他的に作成するため、再実行時は新しい証拠directoryへコピーして出力先を明示変更します。

## 次の最小案: 既存ログ4条件の照会だけ

**追加承認が必要で、まだ実施していません。** 同じ検証account・閉じた10月18日追加枠の同一bare Workerだけを対象にします。識別子は非公開bindingへ固定し、検索結果のWorker/version/IDを照合します。新しいCloud負荷枠や旧承認markerを使いません。

| 照会 | 直前から変更する条件 | 判別できる結果 / 棄却条件 |
| --- | --- | --- |
| Q1 | 元のbasic bare測定区間、dataset/service/type、limit2000を再現 | M0が正しいbindingで現れれば、当時の永久不在説を棄却し、後発の可視化を支持。ただしどの保存段階の遅延かはUNKNOWN。 |
| Q2 | Q1の区間だけを両端60秒拡張 | Q1で不在・Q2で出現なら時間条件に依存する検索を支持。event時刻が元区間外ならclock/時刻の意味を再検討。区間内ならprovider検索の差として保管し、collectorを推測修正しない。 |
| Q3 | Q2のtype条件だけを除去 | Q2で不在・Q3で出現なら分類条件が関係。cf-worker-event以外をCPU受入へ流用しない。 |
| Q4 | Q3のservice条件だけを `$workers.scriptName` 完全一致へ変更 | Q3で不在・Q4で出現ならmetadataのservice/index対応が関係。別Workerへの検索拡大はしない。 |

Q2–Q4で返るreadiness/warmup等も全行を保管し、母集団から捨ててCAPTURE_COMPLETEを作りません。M0が全条件で不在でも、永久欠落やFreeでの取得不可能を証明しません。M0が取得でき、version/outcome/CPU/type等が不適切ならH3の情報になります。M0/M1がどちらも正しく取得できれば、この2要求の対象取り違え説は棄却できますが、未実施の他case/armや正式資格へ拡張しません。

| 制約 | 計画値 |
| --- | --- |
| case/arm・必要最小要求数 | 過去のbasic bareだけ。H1/H2/H3とも新しいclient要求0件、readiness0、warmup0。過去のM1をpositive controlにする。 |
| invocation / Workers / 配備 | target/originの追加invocation各0、作成Worker0、deploy0、削除対象0。GraphQL/HMAC・新しいlive/tail/exportは対象外。 |
| 認証 | 同じaccountだけのWorkers Observability Edit（APIのWrite権限に対応）・最長30分の専用tokenを新規作成する許可を含む。Workers編集等のscopeを足さない。期限切れtoken/OAuthの代替・権限拡大なし。平文は0700 directory内0600、終了・例外時に削除し、値を公開しない。 |
| control API上限 | 4論理query×最大3page＝最大12 query POST、token verify最大1回。query POSTは検索run metadataを生成し得るが、Worker設定や保存ログを書き換えない。pagination以外のretry・再送なし。 |
| RPS / 同時数 / 時間 | control APIも最大1RPS・同時1。各query15秒上限。最初の照会から5分以内に終了し、最後30秒は平文削除・receipt確定へ予約。Worker削除は発生しない。tokenは開始時に残り330秒超を確認。 |
| 保持・停止 | 2026-10-20 JST中に実施し、開始時に保持条件を確認。Q1/Q2の双方でM1が不在なら比較不能として停止。非2xx/API error（403を含む）、通信失敗、STARTED、sampling、不正binding、page上限、時間切れでUNKNOWN/Errorを保存して停止。未対応fieldを推測で置換せず、保持切れを再配備で補わない。 |
| $0確認 | 実行直前の同accountのFree契約・当日要求/ログ残量・他用途の消費・billable usageを読み取り確認。新しい要求/ログ書込み/外部保存先は0なので追加費用は$0見積もり。現時点の残量や請求確定は未確認。無料条件を確認できなければ開始しない。 |

いずれの結果でも元の失敗・UNKNOWN記録は置き換えず、独立した照会結果として保存します。これで識別できなければ制約を報告し、新しい少量負荷を自動で繰り返しません。Freeで全case・両armを完全取得する根拠は依然未達です。PR #1114はDraft、merge 0回、Issue/Goalの完了扱いはしません。
