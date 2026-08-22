# ADR 0003: Security ContractのTrust Model

> **Status:** Accepted

## Context

Security Compilerは、APIに関する独立した4つの見方を比較します。それぞれが
別の問いに答えるため、食い違いは正当に発生します。どれか1つを常に正とすると、
不完全な解析や少ないトラフィックを根拠に危険なPolicy変更を行い、差分を隠す
可能性があります。

既存文書は、次の限定された範囲では引き続き有効です。

- `security.yml`はコンパイラ出力のSource of Truthであり、**Allowed API**を表します。
  Declared、Implemented、Observed APIの正しさまでは保証しません。
- Threat Modelは防御責務を割り当てますが、アプリケーションが実装するRouteを
  証明しません。
- Edge/WAF Decision Matrixは防御レイヤーを選びますが、契約入力間の優先順位を
  定義しません。

## Decision

### Four truths

| View | 意味 | 証明しないこと |
| --- | --- | --- |
| **Declared API / OpenAPI** | 提供者が公開すると宣言したAPI面 | Routeが実装済み、到達可能、またはデプロイ済みPolicyで許可されること |
| **Implemented API / Source AST** | 対応AnalyzerがSource上で静的に確認できるRouteとGuard | Runtime到達可能性、Analyzer能力外の動作、認識できないGuardが存在しないこと |
| **Allowed API / Policy** | Edge/WAF設定が許可する公開面 | 許可されたRouteが宣言済み、実装済み、必要、またはApplication層で安全であること |
| **Observed API / Runtime** | Routeに一致するトラフィックが観測されたEvidence | 未観測Routeが未使用または削除可能であること。観測はEvidenceであり権威ではない |

4つのTruthに自動的な優先順位はありません。食い違いはFindingとして返し、
コンパイラは一方の入力を他方に合わせて暗黙に書き換えてはなりません。

### Confidence and CI gating

ConfidenceはAnalyzerがFindingをどの程度強く立証できるかを表し、Severityとは
独立しています。

| Confidence | 境界 | 既定のSeverity上限 | 既定のCI動作 |
| --- | --- | --- | --- |
| `deterministic` | 宣言されたAnalyzer能力内で完全な入力から機械的に導出でき、同じ正規化入力から常に同じ結果になる | `error` | CIを失敗させられる |
| `high-confidence` | 対応Frameworkの慣習、不完全な静的到達性、または明記された別の仮定に依存する | `warning` | CIを失敗させない |
| `heuristic` | 名前、トラフィック頻度、類似性などの確率的Signalから推測する | `info` | CIを失敗させない |

既定で非0終了を発生させられるのは`deterministic` Findingだけです。利用者は、
選択した`high-confidence` Finding IDをCI Gateにする設定を明示できます。
`heuristic` FindingはCI Gateにできません。設定でGateを厳しくしてもConfidenceを
付け替えたり、LLMにSeverityや終了Statusを選ばせたりしてはなりません。

必要な全入力のParseが成功し、各Analyzerが主張に必要なCapabilityを報告した
場合だけ`deterministic`になります。Analyzerが欠けている、または未対応の場合は、
Evidence不足を不在のEvidenceに変換せずConfidenceを下げます。

### Mismatch examples

| Case | Finding | Severity | Confidence | Default gate |
| --- | --- | --- | --- | --- |
| Sourceで確認したRouteがOpenAPIにない | `undocumented-endpoint` | `error` | Source抽出が完全なら`deterministic`、それ以外は`high-confidence` | deterministicの場合だけFail |
| OpenAPI OperationがPolicyで拒否される | `declared-but-blocked` | `error` | `deterministic` | Fail |
| Policyが許可するRouteがOpenAPIにも完全なSource解析にもない | `unnecessary-exposure` | `error` | Source Capabilityが完全な場合だけ`deterministic` | deterministicの場合だけFail |
| OpenAPIはAuth必須だがSource解析でGuardを確認できない | `auth-contract-mismatch` | `warning` | `high-confidence` | Warn |
| 同じRouteについてOpenAPIとSourceが異なるHTTP Methodを示す | `method-contract-mismatch` | `error` | Source抽出が完全なら`deterministic` | deterministicの場合だけFail |
| Policyが宣言済みOperationより多くのMethodを許可する | `overbroad-method-allowance` | `error` | `deterministic` | Fail |
| RuntimeでOpenAPIにないRouteを観測する | `observed-undocumented-route` | `warning` | `high-confidence` | Warn |
| 選択したRuntime期間で宣言済みRouteが観測されない | `removal-candidate` | `info` | `heuristic` | Inform only |
| SourceにAnalyzerが解決できないDynamic Routeがある | `analysis-gap` | `warning` | `high-confidence` | Warn |
| OpenAPIとPolicyは一致するがRuntimeに拒否トラフィックがある | `runtime-policy-drift-candidate` | `warning` | 収集位置とデプロイ済みDigestの確認までは`high-confidence` | Warn |

### Automated change boundaries

コンパイラとそのIntegrationは、次を行ってはなりません。

- Runtimeで未観測という理由でMethodまたはRouteを削除する。
- Source AnalyzerがGuardを発見できないだけで認証なしと断定する。Findingには
  Analyzer CapabilityとConfidenceを含める。
- OpenAPIから生成したPolicyを本番へ直接適用する。生成Policyはレビュー候補とする。
- LLM出力をAllow/Block、FindingのConfidenceまたはSeverity、CI gating、Processの
  Exit Statusの決定に使う。

AIはdeterministicな結果の説明、Evidenceの要約、Findingのグループ化、修正案の
下書きに利用できます。出力は助言に限定し、元のFinding IDとProvenanceを保持し、
機械的な判定を変更できません。

### Provenance

全Findingと生成候補は、判定を再現できる最低限のProvenanceを持ちます。

- 入力FileのIdentityと正規化ContentのDigest。
- 該当する場合はOperationとRouteのIdentity。
- Analyzer名、Version、宣言されたCapability、Confidence。
- 該当する場合はPolicyまたはRuntime CollectionのIdentity。
- Rule/Finding IDとSecurity Contract Schema Version。

Digest、正規化Identifier、Analyzer Versionは決定的Snapshotに含めます。実時間の
生成時刻と観測時刻はSnapshot外のMetadataとして保存します。TimestampをContent
Digestの代わりにしてはなりません。

## Consequences

- 差分を暗黙に解消せず、Driftとして可視化できます。
- CI失敗は再現可能で、ツールが証明できる主張に限定されます。
- SourceとRuntime解析は曖昧な空結果ではなくCapabilityとCompletenessを公開する
  必要があります。
- 生成Policyにはレビューと既存Deployment Workflowが必要です。
- FindingとSecurity IR ContractはProvenanceと安定IDを保持する必要があります。

## Rejected alternatives

### Runtime > Source > OpenAPI > Policyのような一律の優先順位

各入力は別の問いに答えるため却下します。Runtimeは疎になり得て、Source解析は
不完全になり得ます。Policyは意図や実装ではなく防御動作を表します。

### Runtime主導のRoute自動削除

観測期間からRouteが不要とは証明できないため却下します。

### Source Guard未検出を認証なしとして扱う

Analyzerは全Framework、Wrapper、Dynamic Guardを認識できないため却下します。
Capabilityで結果を限定する必要があります。

### LLMによるSecurity判断

Allow/Block、Severity、CI gating、Exit Statusの決定論的かつ監査可能な根拠に
ならないため却下します。

### OpenAPI由来Policyの本番直接適用

宣言された契約だけでは実装の安全性や運用意図を証明できないため却下します。
生成物はレビュー候補のままとします。
