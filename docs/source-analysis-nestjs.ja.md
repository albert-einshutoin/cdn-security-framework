# NestJS Source Analysis

## 静的に抽出するもの

Analyzerは`tsconfig.json`が選択したproject-local TypeScriptを静的に読みます。
controller prefix、対応HTTP decorator、static route文字列、project-local継承、
設定済みlocal Guard mapping、明示的Public decorator、static Role labelを抽出します。
ExampleではNestJS import alias、local `extends`、TypeScript `paths` aliasも検証します。

codeをparseするだけで、application moduleのimport、decorator実行、NestJS起動、
JavaScript config評価は行いません。`security-analyzer.yml`は
`public_decorators`、`roles_decorators`、明示的`guard_mappings`だけのplain dataにし、
unknown keyと未対応auth kindはschemaで拒否します。

## Security boundaryとconfidence

GuardやRoleの検出はmetadataであり、enforcementの証明ではありません。Guard body、
暗号検証、middleware順序、DI、runtime behaviorは解析外です。local Guardがないことは
publicを意味しません。設定した明示的Public decoratorだけがpublic判定を生成できますが、
その結果もruntime/security reviewが必要です。

deterministic findingは対応済みstatic inputから証明できた結果です。heuristicは一部
capabilityがpartialであることを示します。Global Guard（`APP_GUARD`を含む）、dynamic
path、custom decorator wrapper、module graph、runtime global prefix、versioning、project
referenceはabsence判定を不完全にします。Analyzerは実行せずdiagnosticを返します。

代表的False Positiveはruntime prefixやfixture外のglobal policyです。False Negativeは
custom wrapper、generated controller、module composition、未読込project reference内の
routeです。literalまたは`const` route、NestJS decoratorのdirect import、設定済み
Public/Roleのdirect call、明示的local Guard mappingを推奨します。CIを通す目的だけで
partial diagnosticを無視しないでください。

## Contract diffとCI

`examples/nestjs-contract/run-analysis.cjs`が安全な合成例です。
`runSourceAnalyzer`でSource IR、OpenAPI normalizationでdeclared IR、Policy projectionで
allowed surfaceを作り、`compareSourceOpenApiContracts`と
`compareSourcePolicyContracts`でFindingを生成します。現在の`contract diff` CLIは
application sourceを読み込まないため、CLI source inputが追加されるまではこの
programmatic compositionを使います。warning/heuristicをreviewし、exceptionは狭く期限
付きで記録し、repositoryが選んだseverityだけをCI gateにします。

Troubleshooting:

- `SOURCE_ANALYZER_INPUT_INVALID`: TypeScript syntax/module resolutionを直し、fallbackでappを実行しない。
- `SOURCE_ANALYZER_DYNAMIC_ROUTE`: static `const`へ直すか手動reviewする。
- `SOURCE_ANALYZER_DYNAMIC_AUTH_METADATA`: 設定済みdecoratorをstatic valueでdirect callする。
- `SOURCE_ANALYZER_GLOBAL_GUARD_UNSUPPORTED`: Global Guardの手動review gateを残す。
- project-reference partial: 各referenced projectを個別に解析する。

## Benchmark

`npm run benchmark:source-analysis`を実行します。生成workloadは100 controllers、1,000
operations、path alias、repeated decorator symbol、controllerごとのdynamic diagnosticを
含みます。JSONはproject load、AST traversal、IR generation、comparison、total、heap
delta、files/nodes/operations、project loaderのcold/cached状態を分離します。IR生成は
通常のcache-free Analyzer経路を使うため、Analyzer全体のwarm測定とは主張しません。
`benchmark:source-analysis:ci`は1 sampleと寛容な60秒の暴走上限だけを検証します。
時間とheap deltaはnoiseが大きいため、Node version、architecture、電源状態、iteration
countを揃え、medianで比較してからregressionと判断します。Source変更後のcache
invalidationはintegration testで固定しています。

参考値（Node 24.2.0、macOS arm64、2026-08-25）はcold-loader pipeline total 778 ms、
cached-loader pipeline total 537/511 ms、102 files、11,641 AST nodes、1,000
operations、想定dynamic diagnostic 100件でした。これは比較点であり、環境を
またぐpass/fail上限やAnalyzer warm-cacheの値ではありません。
