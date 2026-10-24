# Cloudflare実HTTP・Artifact Verification MVP

開発用の既存経路「Node HTTP client → native workerd → 別loopback Origin」を使い、現行compilerの生成物を独立した期待契約と照合します。正常・負例は同じworkerdプロセスの別service/portで動かし、外向きdeny-all、固定Origin、既存timeoutとfinally cleanupを維持します。実Cloud、token取得、配備、料金の発生するサービスは使いません。handler/fetchのmockや、native欠落時のNode fallbackはありません。

```sh
npm ci --ignore-scripts
npm run test:cloudflare-http-e2e
# 出力先を分ける場合（build後）
node scripts/cloudflare-http-e2e-tests.js --report reports/cloudflare-http-e2e.json
```

正本は`src/scripts/fixtures/cloudflare-http-cases.ts`の固定Policy・case表です。生成前に凍結し、既存の手書きstatus/到達先を一元化しています。生成物、compiler、handler、normalizerや実測report内のexpected値から期待値を計算しません。対象はstatic_token認証、protected応答のno-store/Vary、public非干渉と対応するstatus・Worker decision event・Origin到達数/method/path/bodyです。Path/JWKS/parser/Origin故障の既存回帰を維持し、通常の`/admin/child`の資格状態3件を追加します。

正常なTS/ESMは改変しません。別Policyからadminのstatic-token gateだけを除き、同compilerで負例TS/ESMを生成します。期待契約を固定したまま、負例serviceへの4要求で不正な認証適用を検出します。JWKS suiteの再実行はありません。要求側Policyのdigestと実際のcompiler入力Policy・生成物のdigestを分け、元生成物のdigestを改変後の証拠として使いません。

| 判定 | 意味 |
|---|---|
| VERIFIED | 非空の宣言済みlocal-artifact-fixture全caseが完全で、実bindingと期待結果に一致 |
| VIOLATED | 十分な実観測から差を示せる。例：匿名`/admin`に期待401/block/Origin0件、実測200/allow/Origin1件 |
| UNKNOWN | identity/event/caseの不足、stale/mixedや未対応条件。影響するcaseと理由を残す |
| Error | digest改変、不正・重複結合、native欠落、通信・runtime・cleanup処理失敗。成功やUNKNOWNへ隠さない |

必要な他caseが未観測でも、成立した反例があればVIOLATEDとし、未観測範囲も併記します。正常と負例はreportの`artifactVerification.normal`/`negative`で分かれます。負例を正しく検出してtestが成功しても、その生成物のsecurity verdictはVIOLATEDです。Findingのseverity/confidence、判定、終了状態を区別し、観測0件・HTTP200・finding0だけで安全としません。

compilerが実際に読んだfileとloaded CJS moduleを収集し、消費するbytesと照合します。Policy/期待case、source/実行module、TS/ESM、lock、実workerd binary/version、生成compatibility date/flags、実config・network・各観測を結合します。時刻、duration、PID、temp path、割当portと元のraw identity digestはmetadataとして分離し、bundleの資格情報は抽象状態にします。child出力をdrainし、Origin・両Worker port・tempのcleanup後に判定します。

stdoutの正常/負例bundle digestは、信頼できるcapture/manifestまたは検証済みCI artifactへ別に固定してください。内部の`replayHttpArtifact(contract, bundle, trustedDigest)`で、同じ固定契約と記録済みsnapshot/観測から同じsemantic digestを再計算できます。信頼するrootがなければUNKNOWN、固定rootの下でbundleが変わればErrorです。改変bundleから新しいrootを自己申告して元の実HTTP証拠と扱ってはいけません。再判定は過去snapshotの再現で、新たなHTTP実行ではありません。

途中失敗のcleanup確認は次の既存注入を使います。期待する結果はError・exit1で、正常testやVIOLATED負例とは別記録にします。

```sh
node scripts/cloudflare-http-e2e-tests.js --fail-after-start --fail-cleanup \
  --report reports/cloudflare-http-e2e-failure.json
```

保証は有限のlocal fixtureと記録したnative runtimeに限ります。分散cache HIT/MISS、任意入力やURL文法、実Cloudflare POP/WAF/DNS/TLS、実JWT/JWKS環境、CPU性能、実配備での防御、#534全体やv2.0/v2.1の採用・公開完了を保証しません。公開API/CLI/schemaや既存release条件は追加しません。

[既存回帰・詳細な資源管理・過去記録（English）](cloudflare-http-e2e.md)
