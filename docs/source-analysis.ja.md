# Source Analysis Trust Boundary

Source Analyzerは、[ADR 0003](adr/0003-security-contract-trust-model.ja.md)の
**Implemented API / Source AST**を表す決定論的な静的解析器です。空または失敗した
解析は、Route、認証、認可、Limitが存在しない証拠にはなりません。

## 実行境界

internalな`SourceAnalyzerPlugin`契約はPluginをloadしません。呼び出し側が、信頼済み
Application codeから静的importしたAnalyzerだけをRegistryへ登録します。Frameworkは
Analyzer package、Decorator factory、Application config、build script、解析対象sourceを
探索、`require`、`import`しません。Analyzer実装はsourceをdataとしてparseし、実行しては
なりません。LLM出力を抽出値、Capability、FindingのConfidence/Severity、CI Gate、
Process exit statusの決定に使うことも禁止します。

`runSourceAnalyzer()`はAnalyzer実行前に次を行います。

- workspace rootと全entrypointのreal pathを解決する。
- 未存在入力、Directory、Traversal、root外absolute path、symlink escapeを拒否する。
- entrypointを解決済みreal pathで重複排除してから、File数、File単位bytes、合計bytesを制限する。
- timeout/cancellation signalと、固定event codeだけを受け取るLoggerを渡す。

Analyzerがentrypointから追加発見するFileにも、同じrootとlimitの検査が必要です。
Wrapperは報告metricsを検証し、宣言limit超過をfail-closedにします。Metricsはroot外の
Fileを読む許可にはなりません。

## Plugin契約

各Pluginは、小文字の安定ID、Semantic Version、対応Language/Framework、完全な
Capability map、1つのasync `analyze`関数を持ちます。次のCapabilityは、
`supported`、`partial`、`unsupported`と空でない理由を必ず保持します。

- Route pathとHTTP method。
- Controller/Router prefixとGlobal prefix/Versioning。
- Authentication/Authorization metadata。
- Request content typeとRequest/Body limit。
- Source locationとInherited metadata。
- Dynamic expression resolution。

静的に証明できない状態は明示します。Dynamic route、未対応Decorator、認識不能Guard、
Capability外のInherited metadataを推測せず、`unknown`、partial/unsupported Capability、
または安全なAnalyzer Diagnosticとして返します。

## LimitとCancellation

`SourceAnalysisLimits`はFile数、合計source bytes、File単位bytes、AST node数、
Diagnostic数、Operation数、解析depth、協調的wall-clock timeoutを制限します。Analyzerは
対応する整数metricsを返します。解析前/中のcancelとtimeout無視は、Contractを持たない
failed executionになります。同期的なAnalyzer処理がtimerを遅延させても、deadline後に
返った結果はwrapperが拒否します。このVersionはpartial contractを成功扱いしません。

このinternal object contractはhard process isolationを提供しません。信頼済みAnalyzerは
event loopへ制御を返し、cancellation signalを監視する必要があります。信頼できない、または
制御を返さない可能性があるAnalyzerには将来worker/process hostが必要です。動的plugin loadと
そのhostはこのIssueの非目標です。

## Result validationとData minimization

成功Resultに含められるのは、`SecurityContractV1`、Analyzer Diagnostic、制限済み
Metricsだけです。Wrapperは`createSecurityContract()`でContractを再構築し、
`source: source-ast`とmetric countを検証します。RouteまたはAuthenticationを`complete`と
するには対応するAnalyzer Capabilityがすべて`supported`である必要があります。このVersionでは
source parameterとrequest-body shapeの抽出を`complete`にできません。また、Operationを返すには
Route pathとHTTP methodの抽出Capabilityが`unsupported`でない必要があります。これにより未知のFramework AST fieldを
除去し、不正Route、absolute/escape provenance URI、query fragment、secret-like valueを
拒否します。

Lifecycle event（`STARTED`、`COMPLETED`、`FAILED`）はWrapperだけが発行します。Analyzerへ
渡すLoggerから早期発行または重複発行することはできず、Wrapperからasync Loggerへの書き込みは直列化されます。

Analyzer DiagnosticはSecurity Findingと分離します。安定code、Framework固定の
safe message、任意のworkspace-relative source URI、正のline/columnだけを保持します。
Plugin由来message、source snippet、literal body、token、secret、stack trace、absolute pathは
保存しません。Throwとinvalid resultは固定の安全なDiagnosticになり、Processを終了せず、
空の成功Contractにも変換されません。

## Registry境界

Internal Registryは決定論的順序を持ち、重複`id@version`とunknown Analyzerを拒否します。
この契約はPublic package APIへexportしません。外部npm Pluginの動的loadとFramework固有
解析はこのPhaseの非目標です。
