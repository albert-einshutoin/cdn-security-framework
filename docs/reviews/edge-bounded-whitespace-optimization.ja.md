# 生成Cloudflare Workerの空白・prefix・パス検査最適化

基準: `c83236db81ae4f1e96a28f582b69512a13e98041`（PR #1109反映後、tree `c1688bfd4d967e80894c6f0014ad92d8ae2f01da`）。生成元のTypeScriptとテンプレートを変更し、goldenは正規コマンドで再生成した。AWSの共有helper・生成物・10KiB容量契約は変更しない。

## 変更と維持する契約

1. GraphQL識別子の後のASCII空白を文字コードで判定し、読了した空白を外側のループで再走査しない。非ASCIIは従来の `/\s/` を維持し、alias/field/depth上限、診断、block/report、転送本文を保持。
2. 生成側で正規化済みindex keyの最長UTF-16長 M を算出し、既存の共有検索関数へ `matchPath.slice(0,M+1)` を渡す。+1で直後のslash境界を残す。元のURI、signed URLのexact判定・署名、転送、認証AND順序は保持。
3. 非monitorモードでrawPathnameと最終URL.pathnameが完全一致する場合だけ2回目の拒否パターン検査を省く。変更されたパスは再検査し、monitorの重複診断も保持。生成regexは従来どおりflag無し/iで、g/yのlastIndex状態を持たない。

前回調査の「検査のloaderをjsに変更する」案は、TypeScriptを含むtemplate prefixの受理を狭めるため採用しない。

## 測定方法

- Apple M4 / macOS arm64 / Node v24.2.0 / workerd 1.20261012.1、compatibility date 2026-07-20。loopback client → native workerdの生成Worker → 同じローカルHTTP origin。外部接続・デプロイなし。
- 同じworkerd process内の別isolateに前後の生成物を置き、同一入力を逐次送信。各pairの順序をbefore/after、after/beforeと交替する。isolateを分離したまま時間変動を近接pairへ分散させる。
- 各variant・各負荷で最初の1回を別記し、warmup1000回の後に1000回測定。独立したcomparison processを2回起動し、表は各variantの2000サンプルのnearest-rank median/p95。first request、全サンプル、paired delta、各runの値、client/origin CPU、event-loop interval（resolution 1ms）をJSONに保存。
- URI/本文/トークンのorigin到達、status、cache/Vary、到達数、child/origin/temp cleanupを照合。before/candidateの生成source hash、module hash、policy hash、driver hashを保存。
- 3件を統合した製品実装で比較。各案の独立した削減量ではなく、足し合わせない。pattern数256のfixtureは別に測定し、そのfixtureも同じ3件を統合した前後比較。
- HTTP全体のwall時間であり、本番CDN CPU時間やCloudFront native latencyの数値ではない。warm結果をcold-start改善へ拡張しない。低負荷の微小差やすべてのp95改善を主張しない。

## 生成edgeコードの前後比較

| 負荷 | median ms（前 → 後） | p95 ms（前 → 後） | median短縮率 |
|---|---:|---:|---:|
| control-short | 0.144167 → 0.135167 | 0.468083 → 0.387750 | 6.2% |
| canonical-deep256 | 0.291000 → 0.200042 | 0.821791 → 0.706833 | 31.3% |
| control-normalized | 0.143875 → 0.137459 | 0.550708 → 0.518959 | 4.5% |
| graphql-2048 | 0.169583 → 0.166916 | 0.592917 → 0.566583 | 1.6% |
| graphql-32768 | 0.470917 → 0.429167 | 1.362458 → 1.153292 | 8.9% |
| graphql-65536 | 0.668875 → 0.635500 | 1.568208 → 1.558416 | 5.0% |
| graphql-65536-pretty | 1.352292 → 0.649583 | 2.436583 → 1.673458 | 52.0% |
| graphql-65536-padding | 1.331458 → 0.488708 | 2.504750 → 1.474917 | 63.3% |
| response-index-short | 0.138916 → 0.140000 | 0.689667 → 0.705458 | -0.8% |
| response-index-deep256 | 0.221583 → 0.205417 | 0.614584 → 0.634250 | 7.3% |
| index-8KiB-hit | 0.653958 → 0.454542 | 1.630917 → 1.338916 | 30.5% |
| index-8KiB-miss | 0.927167 → 0.454125 | 2.053458 → 1.326416 | 51.0% |
| patterns-short | 0.159458 → 0.149958 | 0.656292 → 0.518333 | 6.0% |
| patterns-2KiB | 1.186000 → 0.690334 | 1.966916 → 1.484333 | 41.8% |
| patterns-8KiB | 4.680000 → 2.317917 | 5.936583 → 3.456334 | 50.5% |

短い認証パスはmedian 0.138916 → 0.140000ms、p95 0.689667 → 0.705458msで小幅に上振れた。約2KiBの認証済みパスもp95 0.614584 → 0.634250ms。全条件での高速化とはせず、raw値を保持する。

## 約8KiBパスのp95調査

前回の直列process比較ではslice案のB8だけが遅く、8KiB hit/missのprocess中央値は0.884375/1.247375ms、その後のA8短パスも0.271625msまで遅くなっていた。各sampleのOS/GC traceは残っていないため、過去の遅延の発生源は特定できない。コードのslice処理が原因だったとは断定しない。

直列process間の時間変動をコード差と混同しやすい測定方法を修正し、前後を同じprocess内でAB/BA交替比較した。同一の変更前codeを両isolateへ置いた対照ではmodule hashが一致し、8KiB missのp95は2.004333 / 2.005875msだった。

| run / 負荷 | p95 ms（前 → 後） | median paired delta ms（後−前） |
|---|---:|---:|
| run1 / index-8KiB-hit | 1.775875 → 1.360667 | -0.183750 |
| run2 / index-8KiB-hit | 1.543917 → 1.303708 | -0.188750 |
| run1 / index-8KiB-miss | 1.936375 → 1.150750 | -0.445999 |
| run2 / index-8KiB-miss | 2.171500 → 1.490292 | -0.456125 |

8KiB hit/missは両run、pooled値ともp95短縮。outlier除外、本文/URI上限の引き上げ、sampleの選別は行っていない。探索の末尾までのsubstring列挙を生成済みprefix上限で止め、同一パスの二重検査も省いた。今回の条件では以前のp95悪化は観測されず、対照を含めて改善を確認した。ただし、過去のOS/GC発生源や本番での性能保証を示すものではない。

## 生成側の時間・サイズ

生成側はprogrammatic compile（出力writeを含む）も同じprocess内で順序を交替して確認。各variantでwarmup10回、60回測定。CLI起動時間は含まない。

| prefix数 | median ms（前 → 後） | p95 ms（前 → 後） |
|---|---:|---:|
| prefixes-0 | 7.488750 → 7.499875 | 9.716458 → 10.267542 |
| prefixes-64 | 7.865625 → 8.007542 | 9.791666 → 9.454083 |
| prefixes-500 | 11.116500 → 11.389584 | 12.674417 → 12.456875 |

最長key計算のため64prefixで約0.142ms、500prefixで約0.273msのmedian増加がある。ビルド時に上限を一度求めることで、リクエストごとの長い探索を削減する。

64prefix fixtureの生成JS module: 36207 → 36637 bytes。256pattern fixture: 43478 → 43908 bytes。AWS容量選択の対象テストも成功し、AWS goldenの差分はない。

## 契約検証・レビュー

- 新規の契約7テストは実装前7/7成功。振る舞いを維持する最適化のため、修正前の機能失敗はない。
- 実装後の対象7ファイル62/62成功。ECMAScriptの全BMP空白、非空白U+0085/U+200B、大きい整形本文、8KiB完全転送、重複gateのcredential intersection、長いprefixとsuffix境界、cache/Vary、monitorログを確認。既存のsigned URL exact、case、root/slash、AWSサイズ選択も含む。
- build:ts成功。benchmarkのvariants配列の型不足を初回buildで検出し、型を指定して解消。成功ログと初回失敗ログを区別して保存。
- compile unit、Cloudflare runtime、security baseline、drift成功。HTTP E2Eは46ケース + JWKS50ケース成功し、runtime/origin/ports/tempのcleanupも成功。
- benchmarkの既存defaultモードと単独hot-pathモードを実行し、いずれも成功。不正なpattern数は実行前にErrorとする。
- セルフレビューと高リスク専門レビュー（gpt-5.6-sol medium）は指摘なし。専門レビューはsource・テスト・golden・計測方法と保存値を対象とした。
- このレポートはsource freeze時点の証拠。Stop Review Gate、完全検証、最終hosted CIはこの後に実施する。結果はPR本文とchecksを参照し、ここから成功を推定しない。

## 再実行

```sh
# 同じ依存を使うbaseline(c83236d)とcandidateをそれぞれbuild:ts済みにする
node scripts/benchmark-edge-http.js --root "$CANDIDATE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --output paired.json
node scripts/benchmark-edge-http.js --root "$CANDIDATE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --path-pattern-count 256 --output patterns.json
node scripts/benchmark-edge-http.js --root "$BASELINE_ROOT" --compare-root "$BASELINE_ROOT" --hot-paths --only index-8KiB-miss --output identical-code-control.json
npx vitest run test/edge-bounded-lookups.test.ts test/edge-hotpaths.test.ts test/edge-followup.test.ts test/cloudfront-size-selection.test.ts test/edge-runtime-optimizations.test.ts test/cloudflare-body-inspection.test.ts test/compiler-contract.test.ts --maxWorkers=1
node scripts/cloudflare-http-e2e-tests.js --report http-e2e.json
```

各比較を2回ずつ行い、重い検証と並行測定しない。[構造化データ](edge-bounded-whitespace-optimization.json)には全warm測定sample、first request、run別値、同一code対照、source/evidenceのSHA-256を保存した。rawコピーのroot名だけをbaseline/candidateラベルへ正規化し、元rawファイルのSHA-256も記録。性能値は丸めず保存している。
