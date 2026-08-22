# OpenAPI解析Threat Model

## Assets

- CIとDeveloper MachineのCPU・Memory
- Workspace FileとPathの機密性
- 解析中のNetwork Isolation
- 決定的Findingと安全なDiagnostic

## Trust boundaries

OpenAPI YAML/JSON、Local `$ref`文書、Anchor、String、Schema Graphは未信頼入力です。
後続LoaderとResolverは検証済み`OpenApiAnalysisLimits`を必ず受け取り、入力の読込・
走査時に対応する各Limitを適用します。Parser Libraryの既定値をSecurity Boundaryに
してはなりません。

`timeoutMs`は監督するWorkerまたはChild Process向けのDeadline Contractです。同期
JavaScriptはこの値だけでは強制中断できないため、経過時間Checkを終了保証として
扱ってはなりません。

## Default budget fixture

Parser選定前に、既定値を明示的なWorkload Envelopeとして固定します。

| Limit | Default | Hard maximum | Basis |
| --- | ---: | ---: | --- |
| `maxDocumentBytes` | 2 MiB | 4 MiB | Parse前の各Readを制限 |
| `maxGraphBytes` | 64 MiB | 256 MiB | 解決した全DocumentのRaw Byte合計を制限 |
| `maxResolvedDocuments` | 32 | 64 | Document Graphの幅とParser実行回数を制限 |
| `maxRefDepth` | 32 | 128 | Cycle検出とは別にLocal Ref Chainを制限 |
| `maxSchemaDepth` | 64 | 256 | Recursive Schema走査を制限 |
| `maxNodes` | 250,000 | 1,000,000 | Object種別によらない全体Traversal停止条件 |
| `maxOperations` | 2,000 | 10,000 | 大規模APIを許容しつつRoute処理を制限 |
| `maxParametersPerOperation` | 100 | 500 | 2,000 × 100で20万Parameter VisitのEnvelope |
| `maxSecuritySchemes` | 64 | 256 | Auth正規化処理を制限 |
| `maxYamlAliases` | 100 | 1,000 | Materialize前のAlias Expansionを制限 |
| `maxStringLength` | 64 KiB | 1 MiB | Scalar AllocationとDiagnostic処理を制限 |
| `timeoutMs` | 10,000 ms | 60,000 ms | Supervisor Deadline。同期処理の中断機能ではない |

これらはContract Fixtureであり、Parser Benchmarkの主張ではありません。#274で
Parser固有Costを計測するCorpusを追加します。既定値の変更にはVersion付きContract
更新とBenchmark Evidenceが必要です。

## Abuse cases and mitigations

| Abuse case | Mitigation |
| --- | --- |
| 過大なDocumentまたはString | Parse/Copy前にByte/String Limitを確認 |
| YAML Alias Expansion | ParserのAlias Limitを設定し、MaterializeしたAliasを計数 |
| 深い/循環する`$ref`またはSchema Graph | 訪問済みIdentityを追跡し、Ref・Schema・全Node Limitを適用 |
| Remote `$ref`によるSSRF | v1では`http:`と`https:`を拒否し、Network Fetchを提供しない |
| `file:`またはAbsolute PathによるHost File読込 | File System解決前に拒否 |
| Relative TraversalによるWorkspace脱出 | Lexical PathとReal PathをReal Workspace Rootに対して確認 |
| SymlinkによるWorkspace脱出 | 解決後の`realpath`を再確認 |
| ErrorによるSource TextやCredential漏えい | Stable Code、Safe Message、File名、JSON Pointerだけを出力 |
| 同期解析によるCI停止 | `timeoutMs`を使うWorker/Child Process Supervisor配下で解析 |

Limit超過は安定した`OPENAPI_*` Error Codeを使い、Syntax Errorと区別します。Errorの
Serializationに入力本文、Authorization、Cookie、Query値、Workspaceの絶対Path、
Stack Traceを含めてはなりません。

## Residual risk

- Parser固有AllocationはRaw Byte見積りを超える可能性があります。Parser選定前に
  #274 CorpusでBenchmarkします。
- `realpath`検証と後続Readの間にOS/File System Raceが起こり得ます。Loaderは検証済み
  Targetを直ちにOpen/Readし、攻撃者入力Pathを再解決しないようにします。
- 同一Workspace内の悪意あるFileは設計上読込可能です。Workspace TrustとRepository
  Reviewは引き続き必要です。
- Custom LimitはHard MaximumまでWorkloadを増やせます。未信頼解析は隔離Workerまたは
  Child Processで実行します。
