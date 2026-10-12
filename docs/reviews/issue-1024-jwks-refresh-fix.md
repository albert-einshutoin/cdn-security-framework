# #1024 B2: JWKS refresh増幅の修正

## 範囲と開始基準

2026-10-13。対象はB2と納品に必要なHTTP E2E/B1前提差分のみ。B3以降、#1024全体、H01、RC GO、公開・実クラウド検証は未完了。

- remote main / 開始HEAD: `c5a0caa1e552e8a2b8c700a197da96672f574258`
- 開始tree: `00c0deecaf193b44c6d6d489c948f8ead01effe9`
- version: `2.0.0-rc.0`。version/schema変更なし。
- 開始時の35変更ファイルと81既存証拠を`reports/issue-1024-jwks-refresh-fix/baseline.json`へ固定し、変更ファイルの実bytesを`baseline-files/`へ保存。
- HTTP E2E/B1はmain未統合。前提commit `201eda0`で33ファイルを区別。既存監査/B1報告は未追跡のまま保護し、今回のPRへ自動追加しない。
- 関連セッション「cdn-security Astra」は読み取り確認時にidle、直近作業はB2 Goalプロンプト作成。送信・中断なし。登録外の編集者の不在までは保証しない。

## 根本原因と契約

従来はJWKS URL＋未検証kidごとのmiss cacheであり、distinct kidごとに強制fetchが走り、miss Mapも増加した。現在はper-kid Mapを削除し、設定済みJWKS URL単位へ集約した。

| 項目 | 契約 |
| --- | --- |
| 取得窓 | endpoint/isolateごとに固定5秒窓、最大2回。初回・期限切れ・force・失敗を同じ枠で数える |
| 同時実行 | cold/expired/forceの取得Promiseを共有。完了/失敗でin-flightを解放 |
| fetch期限 | body読み込みを含む2秒。タイマーとPromiseをfinallyで解放 |
| rotation | 正常endpoint、要求の継続、適時処理を前提に最大5秒＋取得期限2秒。拒否trafficは窓を移動しない |
| 障害復旧 | 実際の失敗から設定済みnegative TTLと固定窓の両方が許す時点で取得。失敗Promiseの永続保持なし |
| stale | 最後の成功取得からgate TTL＋設定stale期間内で、実際の取得失敗がある場合のみ。枠の使い切りだけでexpired鍵を許可しない |
| 状態上限 | E個の信頼済み設定URLに対し最大E cache・E negative・E refresh状態。kid/未検証issuerで状態を分割しない。各cacheは256KiB/100keys上限 |
| 限界 | isolateをまたぐ共有制限ではない。TTLが5秒未満で枠を使い切ると、一時的にfail closedする。メモリ枯渇閾値は未測定 |

HTTPS/host allowlist、algorithm・署名・issuer/audience、body/key数、有限stale/negative契約を維持。AWS RS256の新規対応、外部DB/DO、汎用rate limiterは追加していない。

## 実HTTP証拠と受入対応

通常CLI生成Worker → native workerd → 同一ローカルlistenerで分離記録するJWKS/app。合成RSA署名を実検証し、Worker/fetch/cryptoをmockしない。信頼済み合成HTTPS識別URLを固定loopback transportへ接続し、外向き通信を拒否。公開DNS/TLS/Cloudflare POPの証拠ではない。秘密鍵と完全JWTはメモリ内のみ。

最初の修正前native試行では、workerdが`redirect: error`を受け付けずJWKS受信0だった（`http-before.json`）。これはB2再現ではなく別の互換性失敗。安全な`manual`＋非2xx拒否へ変えた最小前提差分だけを適用した`http-before-enabled.json`では、**32要求・全401・JWKS33回・app0**で上限2に対しFAIL。元のstub監査を実通信の証拠へ付け替えていない。使用テンプレートを`before-enabled-template.ts`へ保存。

| 受入 | 現在の直接証拠 | 判定 |
| --- | --- | --- |
| distinct 32と128 | `http-final-reviewed.json`: 最初32で2回、続く128で0回、同一5秒内。全401/app0 | 充足 |
| cold/fresh並行 | cold 32で2回、fresh同kid32で0回 | 充足 |
| 期限切れ並行 | seed1回、TTL経過後32 missで1回。既知鍵は200 | 充足 |
| 正常/不正 | 既知署名200/app1/fetch0、同kid不正署名401/app0、issuer/audience不正401/fetch0 | 充足 |
| rotation | key B更新前401、継続miss後の境界で16並行署名200・fetch1。後続fresh取得0 | 充足 |
| 境界 | `runtime-review-fix.log`: Node生成runtimeで時計を制御し4999ms拒否、5000ms署名成功。生成Worker文字列/定数の変更なし | 充足 |
| 5xx/stale/negative | stale期間内16並行既知鍵200/fetch1。未知鍵401、期間外401。negative期間の追加受信0 | 充足 |
| 不正JSON/復旧 | 16並行401/fetch1、negative期間fetch0、復旧200/fetch1 | 充足 |
| 接続拒否/復旧 | listener閉鎖時401/受信0、再開直後negative拒否、TTL後200/fetch1 | 充足 |
| deadline/復旧 | headers前と200 headers後の未完了bodyで約2秒の401。両方とも復旧後200/fetch1 | 充足 |
| 同じURLの異なるTTL | seed後4.1秒で長TTL3s/短TTL1sを並行。stale設定2s、共通503取得1回、長200/短401 | 充足 |
| redirect | 302からmetadata URLへ追従せず401。endpoint受信1、negative期間0、app0 | 充足 |
| endpoint分離 | Aのkey B成功に対しBは同key拒否。D障害中Bの既知鍵200/fetch0 | 充足 |
| 有限状態 | sourceの3個のMapは信頼済みURLのみでkey化。per-kid保持削除。native件数を増加しても同じ取得枠 | 充足（構造根拠） |
| B1/既存E2E | 認証パス・転送・response保護・parser・origin失敗の44件PASS。全cleanup true | 充足 |

Native runtimeは`1.20261012.1`、Node24.2.0、macOS arm64、compatibility date `2026-07-20`、flags `[]`。`http-final-reviewed.json`に346 JWT要求、50 group/event、44既存ケース、受信時刻/鍵更新時刻/並行数、生成TS/module/runtime/harness/compiler/lock/configのSHA-256を保存。接続拒否では受信数をネットワークattempt数と同一視しない。上限は全fetch経路の共有budgetからも確認する。

再実行: `npm run build:ts`、`node scripts/cloudflare-http-e2e-tests.js --report <新しい保存先>`、`node scripts/cloudflare-runtime-tests.js`。起動10秒、全体120秒、HTTP5秒、終了TERM3秒→KILL3秒。使い捨てfixture/ローカルloopbackのみ。

## 検証、レビュー、納品状態

対象runtime検証・golden再生成・package smoke・diff checkを実施。専門レビュー1巡目はBLOCK（異なるgate TTLへのstale漏れ、rotationテストの時間境界、body期限の証拠不足）。最小回帰checkは短TTL側200を観測してFAIL（`ttl-red.log`）。共有Promiseをnetwork/parseだけに絞り、各callerでstaleを判定する修正で長200/短401になった。nativeでも同じTTLケース、未完了body、境界marginを追加した。指摘範囲の最終レビュー、完全検証、Companion Gate、最終PR/mergeの結果は確定後に追記する。

EN/JA auth運用ノートを新しい枠・復旧・短TTLの制約へ揃えた。`docs/reviews/`は内部監査成果物としてnpm packageから除外し、固定package inventoryと開発者パス/内部証拠の混入を防ぐ。製品docsの変更はB2の契約説明に限定し、B3のversion訂正は行っていない。

## 費用と残件

公開repo、push/PR/main workflowは標準`ubuntu-latest`。既存Actions account budgetは$0、Stop usage Yes、spent $0を読み取り確認。設定変更なし。cache開始時346,622,593 bytes。artifact retention30日、料金対象の実行/storageが生じれば既存予算で停止する。releaseは`v*` tag push/手動dispatchのみ。今回branch/PR/main操作はtag/dispatch/deployを含まない。`cost-preflight.json`に設定観測とworkflow hashesを記録。

B3以降、#1024全体、人間H01、RC GO、公開、実IdP/クラウド検証は未完了のまま。次のIssueへ継続しない。

### 確定したローカル最終結果

- Sol medium専門レビュー: 初回BLOCKの3指摘を一括是正し、同じレビューの指摘範囲最終確認でALLOW（`expert-review-final.md`）。新しい全体探索は追加していない。
- 隔離checkout `75b26234f7a7c7430dce990ebddd0483adf1116d`で`npm run test:ci` exit 0、127.25秒。Vitest 33 files/607 tests、依存監査0、coverage statements/lines81.25%、branches80.68%、functions82.95%。unit/runtime/package/migration/backup/security/drift/determinismを含むPR全入力の完全検証。
- 初回は合成env不足でbuild入口FAIL（5.8秒）。`full-test-ci-setup-failure.*`として保全し、workflowと同じ非本番fixture値2個を明示した再実行が上記成功。失敗を成功へ改名していない。
- 完全検証後の変更は本報告への結果追記のみ。npmから除外するresult Markdownと36個の実行入力を`final-binding.json`で区別する。
- この版のCompanion Gate・最終hosted CI・PR/mergeはまだ未確認。外部結果は確定後に局所的な結果追記として保存し、コード検証証拠と区別する。
