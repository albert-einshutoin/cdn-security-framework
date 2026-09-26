# Experimental Source-aware CI接続（dev限定）

実行可能な例はrepositoryの`.github/workflows/policy-lint.yml`の
`source-aware-ci` jobです。`dev/2.1-source-aware`または
`feat/source-aware-ci/` branchを手動dispatchした場合だけ実行します。通常の
`main`向けPR、schedule、release refではskipします。合成fixture
`examples/nestjs-contract`だけを使い、権限は`contents: read`です。
標準2.0の`examples/github-actions/contract-diff.yml`とは分離しています。

```sh
gh workflow run policy-lint.yml --ref dev/2.1-source-aware
gh run list --workflow policy-lint.yml --branch dev/2.1-source-aware --limit 1
```

同じrun/attemptのsingle-pack producer候補を取得し、source/harness/tgz/lockを
照合します。consumer依存はscriptを無効にして先に導入します。合成対象を新規
workspaceへコピーし、run/attemptごとに空の`reports` directoryを用意します。
networkを切るのは解析工程です。対象のnpm script、Source、JS設定、Guardは
実行しません。内部driverはinstalled
`consumer/node_modules/cdn-security-framework`から解決し、repositoryのsourceや
global packageへfallbackせず、consumerで製品を再build/repackしません。
候補identityと解析対象のevidence digestは別に記録します。

例はOpenAPI、Policy、`--source`、target、固定日付、`--fail-on never`を
JSON設定から渡します。合成設定では同じ内部入力経路へCLIの
`sourceAuthConfig`、`exceptions`、`environment`も指定できます。実アプリの
workflowではworkspace内の入力とFinding閾値を明示して選ぶ必要があります。
`never`でも入力・内部・保存・CI失敗は成功になりません。Source省略は
omittedとして表示し、partial/unknownを安全性の証明とみなしません。

共通の検証、認証設定・例外読込み、解析、finalizerを一度だけ実行し、同じ
完全結果からSummary MarkdownとSARIFを描画します。既存の新規ファイル専用
writerでworkspace内へ保存し、入力や旧reportを上書きしません。CI記録は
候補identity、解析exit、各出力状態、相対名、byte数、SHA-256を含み、raw入力、
絶対path、stackは含みません。通常ファイル、hash、SummaryのUTF-8/上限/内容、
固定した公式SARIF schemaを検証してから、Summaryをデータとして
`GITHUB_STEP_SUMMARY`へ転記します。検証した同じSummary bytesをstageと転記に使います。
upload直前の`verify-stage`は、候補/run identity、stageの明示ファイル一覧、
通常ファイル、サイズ、hash、report形式を、実行時検証済みのCI・転送記録に照合します。
最終gateもstageを再確認します。検証済み明示リストのみを通常のActions
artifactに30日保存します。取得後は`ci-record.json`と`delivery.json`の各hashに照合します。
tgzのSHA-256とActions artifact archiveのdigestは別です。

解析exit `1`と保存可能なpartial exit `2`では診断成果物を残し、最終gateは
失敗させます。入力保護不完全、内部/render/write失敗、検証失敗では固定codeの
失敗Summaryを示し、旧reportや架空の正常0件reportを使いません。Summary転記、
stage検証、artifact upload、依存jobのskip/cancel、元の解析exitを個別に確認します。
複数ファイルの保存は原子的transactionではありません。検証済みの残存ファイル
だけを診断用に残せます。gate成功にはexit `0`、両成果物の検証、Summary転記、
artifact upload、producer/acceptanceの成功が必要です。

保存境界は信頼・排他管理されたPOSIX local workspaceを前提とします。
同権限processによる任意の並行renameや停電まで保証しません。このdev workflowは
Code Scanning upload、PRコメント、publish、release、deploy、安定した
Source-aware JSON/public APIを提供しません。Summaryを5分で理解できるかの
人間確認と実repository評価は[#611](https://github.com/albert-einshutoin/cdn-security-framework/issues/611)
に残します。
