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

このworkflowはDeclared APIの根拠とreview-onlyのAllowed API candidateを準備します。
比較は`contract diff`を使います。candidateの適用はしません。完全なtrust modelは
[ADR 0003](adr/0003-security-contract-trust-model.ja.md)を参照してください。

## 10分Quickstart

以下はこのrepositoryのclone rootで実行します。利用側projectは
[候補tarballのQuickstart](quickstart.ja.md#5-openapiからreviewへ)を使ってください。
公開1.4.0はschema2候補ではなく、以下のrepository用npm scriptはconsumerの前提ではありません。

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

## 内部の認証 × キャッシュ検証MVP（#1119）

このローカル試作は `src/contract/verification/` の内部モジュールです。
package entrypoint、CLI、Policy schema、配備association、自動Applyは追加しません。
v2.0/v2.1のEntry/Release条件を増やさず、#533全体完成とも扱いません。
Source/OpenAPIの認証メタデータは要求の宣言であり、runtime認証証拠ではありません。

判定器は検証済みconstructorが発行し再帰的に凍結したProjectionだけを受け付けます。直列化・差替え・改変したProjectionは受け付けず、再現時は元入力から再作成します。入力は既存Security IR、schema検証済みPolicyから投影したAllowed Surface、明示的な
CloudFront実行モデルです。静的IR Method/Path × 列挙Host × 抽象資格状態（なし/有効）
の全組合せを扱い、選んだ成功HTTPテストを全称証明へ置き換えません。Hostは正規化済み
合成 `.test` 名、Pathは正規化済みASCIIのリテラル（rootを含む）です。テンプレート・
符号化等の未対応PathはUNKNOWNです。既存のequal-or-prefix-plus-slashを維持し、prefix `/` は `/` だけに一致します。global Host/Methodの対象外もUNKNOWNとし、
迂回を推測しません。他の認証以外のrequest検証は対象リクエストを受理し、保護対象の
内容を生成しないという前提です。資格状態は抽象条件であり、秘密情報・暗号検証・
アプリケーション認可の証明は含みません。

Rは認証必須と宣言された受理対象リクエストと到達可能経路、Eはsupportedなblocking
認証ゲートを実行する部分集合です。両資格状態についてR ⊆ Eを検証します。有効資格の
HITでもゲートを省略すれば、この認証適用の不変条件には違反します。匿名データ漏えいの
反例とは条件を区別します。ゲートは有効資格を通し、資格なしを拒否し、書換え・例外・
副作用を持たないと仮定します。phaseはPolicy rule indexに対応する明示associationで、
Policyだけから配備状態を推定しません。

[Viewer Requestはcache lookup前、Origin Requestはoriginへ転送する場合に実行されます](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-cloudfront-trigger-events.html)。
[HITには同じkeyと有効なresident objectが必要です](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-the-cache-key.html)。
このモデルの実効keyはdistribution namespace、リテラルPath、GET/HEAD共通組
（OPTIONSは別）、明示したviewer Host/資格状態のpartitionです。それ以外のquery/
header/cookie key次元は対象外です。cacheable・TTLは実効値の入力であり、Policyの
応答headerから推測しません。fill配列は履歴ではなくresident snapshotで、同じ実効key/locationに複数あれば矛盾Errorです。先行fillは入力時刻より前に生成可能で、同じkey/location、
`nowMs - storedAtMs < ttlMs` を満たす必要があります。fillと参照のauth associationは
同じです。eviction、revalidation、origin failover、任意関数はモデル化しません。
判定器は現在時刻へ依存しません。

- **VIOLATED**：R所属・E不在の具体的なHTTP条件、資格状態、先行fill、key/TTL/location、
  保護内容へ至る実行経路を反例として示します。
- **VERIFIED（モデル内）**：全cellを認証が覆います。Viewer Requestはlookup前なので
  HIT/MISSを覆い、Origin RequestだけでもMISSしか到達できなければ覆えます。
- **UNKNOWN**：key/cacheability/TTL/residency/association/order不足、テンプレート、
  不完全IR、応答phaseの認証、範囲を明示したredirect/custom-error/bypass等です。
  lookupより前のViewer認証が証明できれば、その後のcache情報不足では覆しません。
  例外範囲の宣言自体がなければ証明しません。成立する反例が全体判定をVIOLATEDにしても、
  別cellのUNKNOWNは保持します。
- **Error**：不正・矛盾JSON/Policy/model、association重複、未来fill、認証で拒否される
  fill、資源超過、不正反例です。cache無効、TTLゼロ/失効、異なるkeyは有効なMISS設定で、
  不可能なHITを明示要求する反例を独立checkerが拒否します。

上限はJSON 1MiB・50,000 nodes・depth64・string16KiB、operation/rule/fill/effect各128、
Host16、投影auth prefix256・合計64KiB、protected cell最大4,096です。ErrorをUNKNOWNや
成功へ変換しません。verdictとFindingのseverity/confidence、process終了状態は別物です。
既存のredacted Finding builderを再利用しますが、findingゼロでVERIFIEDにはしません。
CLI終了code対応や自動修正はありません。

依存を導入したcheckoutでの再現手順です。

```sh
npm run build:ts
npx --no-install vitest run test/contract/auth-cache.test.ts
node test/fixtures/auth-cache/reproduce.cjs
```

`reports/issue-1119/reproduction/` に、Origin HITのVIOLATED、Viewer HIT/MISSと
Origin-only MISSのVERIFIED、key不足のUNKNOWN、時刻不正のErrorを保存します。
独立した具体リプレイはR所属・E不在・key各要素・fill到達性・TTL・イベント順序を検査し、
判定器やそのroute/key/reachability helperを呼びません。HTTP条件・trace・fill・時刻/
key/phaseを変えた反例、不可能なHIT/MISSを拒否するテストを含みます。生成時刻メタデータは
semantic digestから分離します。実際に消費した正規化IR・Allowed Surface・実行モデルと、投影のため実際にparseしたcanonical Policy JSONを
埋め込みhashを保持します。Policy provenanceはmaterializeした同じfile/digestを参照し、消費したPolicy validation schemaのdigestも別途保持し、実行receiptはfixture・lockfile・Node版・実際にloadしたrepo module
へ結合します。未使用の生成物・未観測Cloud状態を証拠にしません。これはモデル内の証拠で、
実AWS/Cloudflareの動作保証・性能資格・統合・release・Epic完成ではありません。

`request.block.header_present` のenforceはglobalな認証前header受理条件です。
このMVPにはheader存在の入力次元がないため、影響するcellを
`UNKNOWN`（`HEADER_ADMISSION_UNMODELED`）にし、独立checkerも反例を拒否します。
monitorのpresence ruleは拒否しないため認証適用判定を変えません。Next.jsや配備済み
header状態の推定、headerモデルや公開機能の追加は行いません。
