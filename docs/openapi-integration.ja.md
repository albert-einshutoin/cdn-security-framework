# OpenAPI導入ガイド

OpenAPI commandは、信頼できないlocal OpenAPI 3.0/3.1 documentをreview evidenceと
非破壊Policy Candidateへ変換します。API宣言とEdge Policy baselineの差を確認する
準備であり、Applicationが安全であることを証明する機能ではありません。

## Scope: 独立した4つのTruth

| Truth | Evidence | 証明しないこと |
| --- | --- | --- |
| Declared API | OpenAPI document | Routeが実装済み、到達可能、または許可済みであること |
| Implemented API | Source AST | Runtime到達可能性や未認識framework動作 |
| Allowed API | Edge/WAF Policy | 許可Routeが宣言済み、実装済み、またはApplicationで安全であること |
| Observed API | Runtime event | 未観測Routeが未使用または削除可能であること |

このPhase 1 workflowはDeclared APIとAllowed APIのCandidateを準備します。まだCIで
比較しません。完全なtrust modelは
[ADR 0003](adr/0003-security-contract-trust-model.ja.md)を参照してください。

## 10分Quickstart

以下はこのrepositoryのclone rootで実行します。利用側projectでは
`npm install --save-dev cdn-security-framework`でinstallし、同じ
`npx cdn-security` commandを使います。

### 1. Installと出力directoryの準備

```bash
npm ci
mkdir -p reports
```

### 2. Declared Contractをinspect

```bash
npx cdn-security openapi inspect \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --json \
  --out reports/openapi-contract.json
```

最初にtextを読む場合は`--json`と`--out`を外します。JSON reportは決定的で、
正規化Security IR、capability、安全なdiagnosticを含みます。

### 3. Policy Candidateを生成

```bash
npx cdn-security openapi generate-policy \
  --input examples/openapi/openapi.yaml \
  --workspace-root . \
  --profile balanced \
  --out policy/openapi.candidate.yml
```

`policy/openapi.candidate.yml`と`policy/openapi.candidate.meta.json`を生成します。
`policy/security.yml`の読込・merge・上書き、Policyの適用、deployは行いません。
既存出力には`--force`が必要です。使用前に出力pathを確認してください。

### 4. Candidateと省略項目をreview

```bash
git diff --no-index policy/profiles/balanced.yml policy/openapi.candidate.yml
node -e "const m=require('./policy/openapi.candidate.meta.json'); console.log(m.omittedRecommendations)"
```

`git diff --no-index`は差分があると`1`で終了しますが正常です。追加されたglobal
method/headerと、すべての`omittedRecommendations`を確認します。典型的な省略対象は、
現行Policy schemaで忠実に表現できないroute固有match、認証、content type、body
limit、parameter制約です。

このfixtureでは、global method setに次のreview対象差分が出ます。

```diff
-  allow_methods: ["GET", "HEAD", "POST"]
+  allow_methods:
+    - GET
+    - POST
```

これは変更内容を示すだけで、Candidate採用を自動承認するものではありません。

### 5. Localでvalidate・build

```bash
npm run lint:policy -- policy/openapi.candidate.yml
npx cdn-security build \
  --policy policy/openapi.candidate.yml \
  --out-dir dist/openapi-candidate
```

buildで証明できるのはCandidateがcompileできることだけです。生成fileはlocal artifact
のままで、deployされません。

## Input境界とResource Limit

- `--workspace-root`はinput、local `$ref` document、outputのfilesystem境界です。
  repository rootまたは、より狭い信頼済みrootを指定します。
- relative local `$ref`はlexical pathとreal pathの包含確認後に解決します。absolute
  path、`file:` URL、workspace外traversal、symlink escapeは拒否します。
- remote `http:`/`https:` refは既定無効です。解析中のnetwork解決はSSRF、非決定性、
  mutable input、credential漏えい、CI availability riskを増やします。
- document bytes、graph bytes、解決document数、ref/schema depth、node、operation、
  parameter、security scheme、YAML alias、stringと関連traversal workに明示limitがあります。
  `timeoutMs`は外部Supervisor向けdeadline contractにすぎず、同期CLI/loaderを中断しません。
  信頼できない解析は、そのdeadlineを強制するWorkerまたはchild-process Supervisor配下で
  実行します。現行値は[OpenAPI Threat Model](openapi-threat-model.ja.md)を参照してください。

OpenAPIと参照fileはすべて信頼できないinputとして扱います。inspect errorは安定した
`OPENAPI_*` codeを使い、raw input、credential、absolute path、request body、cookie、
query値を出しません。

## FindingとRecommendationの読み方

`security: []`はoperationを明示publicにします。security情報が欠けている、または
未対応の場合は`unknown`であり、publicではありません。Bearer/OAuth宣言は認証要件を
示しますが、JWT issuer、audience、JWKS、algorithm、environment variable名、secretを
安全には提供できません。これらをCandidateへ推測しません。

Recommendation estimateの意味は次のとおりです。

| Kind | 意味 | Candidateでの扱い |
| --- | --- | --- |
| `exact` | 解析した宣言済みinputに対する正確値 | Policy mappingも忠実な場合だけ採用 |
| `upper-bound` | 解析した宣言済みinputに対する有限の安全上限 | Policy mappingも忠実な場合だけ採用 |
| `partial` | 一部の寄与inputを完全に制限できない | profile baselineを保持し、人間がreview |
| `unknown` | 安全な上限を確定できない | profile baselineを保持し、人間がreview |

OpenAPIは未宣言query parameterを禁止しないため、宣言済みparameterが`exact`または
`upper-bound`でもquery/URI limit Recommendationは省略されます。exampleのmultipart
upload sizeは`unknown`です。

`capabilityFindings`はtarget support evidenceとして読み、未対応controlがenforce済み
という証明には使いません。review ruleとstable IDは
[Finding Reference](finding-reference.ja.md)、performance envelopeは
[OpenAPI Benchmark](benchmarks/openapi-analysis.ja.md)を参照してください。

## Review Checklist

- publicにする各operationへ明示`security: []`があることを確認する。
- 欠落・未解決・未対応の認証をunknownとして扱う。
- global allowed methodとrequired headerを全operationに照合する。
- 省略Recommendationをすべて確認し、route、auth、body、content-type制約をより広い
  Policy controlで近似しない。
- JWT/secret設定はreview済みApplication/deployment設定からのみ与える。
- 設定採用前にtarget capability Findingを確認する。
- 承認済みfieldだけをactive Policyへcopyし、その変更を別途reviewする。Candidateを
  automationで直接deployしない。

## Troubleshooting

| 症状 | 対応 |
| --- | --- |
| `OPENAPI_REMOTE_REF_DISABLED` | remote `$ref`をreview済みlocal fileへ置き換え、`--workspace-root`内へ置く。 |
| Workspace/path error | real workspace root配下のrelative input/outputを使い、absolute、`file:`、traversal、symlink escapeを除く。 |
| Resource-limit error | specを縮小・分割する。limit引上げはbenchmark evidenceと信頼済みinput境界がある場合だけ行う。 |
| Output exists | Candidateの両fileを確認し、そのregular fileに限って`--force`を使う。 |
| Candidate validation fails | active Policyを変更せず、stable errorとmetaの省略項目を確認する。 |
| Authがunknown | OpenAPI security宣言を明示する。ただしJWT/secretは意図どおり別設定とする。 |
| Multipart/body limitがunknown | 選択targetで対応する場合、review済みApplication/Edge limitを手動設定する。 |

## CI導入

Phase 1の`inspect`やCandidate生成をrequired drift checkにしません。Phase 2の
`contract diff`がstable comparison rule、exit code、exception、reportを提供してから
CI gateを導入します。それまでは必要に応じてreview evidenceを保存できますが、採用と
deployは手動のままにします。

関連資料: [Policy Candidate Mapping](openapi-policy-candidates.ja.md)、
[Threat Model](openapi-threat-model.ja.md)、[Finding Reference](finding-reference.ja.md)、
[Benchmark](benchmarks/openapi-analysis.ja.md)。
