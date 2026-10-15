# Cloudflare認証prefixと生成時解析の最適化

基準は `cad719946e229fc896f1bc4b589b552844b90dcd`。既存の認証、パス、生成・検証契約を保って、前回調査で優先度が中〜高だった2件だけを実装した。AWSのクエリ最適化やパスルール検査の変更は含めない。

## 変更と維持する契約

- `pathCandidates` が既に完全一致または `/` 境界のprefix一致を証明した認証ゲートでは、同じprefix一覧を再走査しない。署名URLの `exact_path` は引き続き完全一致を確認する。ゲート順序、重複除去、重なるゲートのAND、static/basic/JWT/署名の検証、monitorでも認証を通過させない契約を維持する。索引のない小規模設定は既存のprefix走査を使う。
- `CFG` / `RESPONSE_CFG` の宣言検証を、既存の `specializeWorker` の後へ移す。解析対象が小さくなるだけで、検証を削除しない。構文・変換・不正marker・重複宣言の失敗は、出力ディレクトリ作成・writeより前に伝播する。
- 生成されたCloudflare golden 8件は通常の生成コマンドで更新した。生成JSを手編集していない。新しい依存や公開APIは追加していない。

## 実装前後の測定

Apple M4 / Node v24.2.0 / workerd 1.20261012.1。同じ依存、固定入力、同一のafter側driverで、git archiveからbuildしたbeforeと実装後をA/B/B/A順に別プロセスで比較した。ネットワークはローカルloopbackのみ。

| 対象 | 変更前の平均ms | 実装後の平均ms | 平均の差 |
|---|---:|---:|---:|
| workerd HTTP・1ゲート5,000 prefix | 0.432 | 0.171 | 60.3%短縮 |
| workerd HTTP・1ゲート500 prefix | 0.188 | 0.179 | 0.009ms短縮・小差 |
| Node生成コード・5,000 prefix | 0.767 | 0.058 | 92.5%短縮 |
| Cloudflare生成・最小設定 | 31.618 | 18.641 | 41.0%短縮 |
| Cloudflare生成・500 prefix | 35.695 | 30.064 | 15.8%短縮 |

workerdの5,000 prefixでは中央値0.361→0.132ms、p95 0.830→0.387ms。各プロセス平均もbefore 0.431/0.433ms、after 0.172/0.171msだった。各負荷は1,000回warmup後に1,000件、前後それぞれ計2,000件を測定。origin到達数・応答成功・runtime/origin/tempのcleanupも照合した。

Nodeは30回warmup後、500回×5batch×2process/側。生成は3回warmup後、5回×5batch×2process/側で、書き込みと生成ファイルのreadを含む。最小設定のbatch平均範囲はbefore 19.630〜64.433ms、after 13.674〜31.760ms。500 prefixは25.315〜46.712ms→20.657〜46.550msで、ホスト負荷による幅がある。

31/32 prefixの小規模controlも保存した。Nodeでは平均0.041→0.081ms、0.034→0.098msと悪化値も出ており、実装後32 prefixのprocess平均は0.153/0.043msと変動した。別時間帯のworkerd controlは31 prefixで1.666→1.799ms、32 prefixで1.835→1.552msだった。これらから小規模設定の高速化や性能非退行は断定しない。単一のmsや統計的有意差、全設定での速度向上は主張しない。

初回のnative計測は無関係なGraphQL/origin署名を含んでいたため、専門レビューの指摘に従ってprefix専用モードから除外した。既定モードの署名・本文・query検証は維持し、330件の到達とcleanupを再確認した。初回のNode計測もcontrolの変動が大きかったため、同一source/driverで限定した再測定を実施した。初回結果は削除せずJSONに区別して保持する。

これらはローカルの経過時間であり、本番CDNのCPU時間、コールドスタート、RSS、実利用者のネットワーク遅延は未測定。Nodeの値をAWS/CloudFrontの速度とは扱わない。raw sample、両rootの入力・生成物・driver hash、source manifest、各プロセスの集計は[JSON](cloudflare-prefix-generation.json)を参照。

## テストとレビュー

- 実装前に追加した契約テスト21/21成功。性能最適化で振る舞いは変更しないため、意図した機能テストの失敗はない。
- 実装後の対象Vitestは4ファイル44/44、case-sensitiveの追加後は関連2ファイル22/22成功。31/32/500 prefix、重なるstatic/basicのANDと拒否順、署名URLのexact切替と署名検証、monitor fail-closed、大小文字・encoded/matrix pathを確認した。
- compiler unit、Cloudflare runtime、security baselineが成功。不正CFG/RESPONSE_CFG/runtime markerで既存出力が変わらないことも確認した。
- 検証位置の移動だけを分離した比較で、既存8 policyの生成物がバイト単位で一致した。
- Node→workerd→別loopback originのHTTP E2Eは46ケース、JWKS関連44ケースで成功。fixtureの認証prefixを増やして索引経路を通し、全cleanupを確認した。
- Sol mediumの専門レビューでは測定条件の中指摘1件を修正し、指摘範囲の最終レビューはALLOW。認証と生成本体に具体的な不具合指摘はなかった。
- Companion Stop Review GateはALLOW。17ファイルのhashと今回の契約・証拠の整合性を確認し、完全検証へ進めるという限定stageの判定。今回のsource/test/golden 15ファイルのhashはその後も一致している。
- ローカル完全検証はworker 2で689/692成功・既存テスト3件timeout、worker 1への限定再実行で682/692成功・10件timeoutとなった。期限は5秒（一部15秒）で、期待値・期限・製品コードを変更していない。完全検証/coverage成功とは扱わない。
- 基準commitでも、同じCLIテスト2件がcoverage下で5秒timeoutすることを確認した。他のtimeoutケースを変更前で個別再現したわけではない。タイムアウト以外のassertion差分は今回の失敗ログでは観測されなかった。
- hosted CIはこのcommitから作成するPRの独立した完全検証を正本とする。PR作成前時点では未実施で、最終結果は同じheadのPR説明・checksに記録する。merge/deployの結果ではない。

## 再実行

同じ依存を使い、beforeは上記commitのgit archiveを隔離ディレクトリへ展開する。両rootで `npm run build:ts` を実行し、同じ実装後driverを使ってA/B/B/A順に実行する。RSA fixtureは使い捨てのローカル生成物でrepoへ保存しない。

```sh
npx vitest run test/edge-followup.test.ts test/edge-runtime-optimizations.test.ts test/compiler-contract.test.ts test/compiler-write-safety.test.ts --maxWorkers=2
node scripts/cloudflare-http-e2e-tests.js --report <http-report.json>
node scripts/benchmark-edge-runtime.js --root <built-root> --output <result.json> --fixture <same-synthetic-rsa.json> --only prefixes-
node scripts/benchmark-edge-http.js --root <built-root> --output <result.json> --auth-prefix-count 5000
VITEST_MAX_WORKERS=2 EDGE_ADMIN_TOKEN=synthetic-local-full-validation npm run test:ci
```

`--auth-prefix-count` は1〜5,000に制限し、31/32/500/5,000を今回の比較条件とした。完全検証はレビュー確定後に実施した。上記ローカル失敗ログと変更前の限定再現を保持し、追加の完全再実行は行わない。
