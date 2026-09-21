# CLI リファレンス

> **言語:** [English](./cli.md) · 日本語

`cdn-security` はポリシーのスキャフォールド、エッジランタイムへのコンパイル、インフラ設定の生成、環境診断までを担う単一のエントリーポイントです。

```bash
npx cdn-security <subcommand> [options]
```

| サブコマンド | 目的 |
| --- | --- |
| `init` | プロファイル / アーキタイプから `policy/security.yml` をスキャフォールド。 |
| `build` | ポリシー検証 + エッジランタイム + インフラ設定の生成。 |
| `playground` | ポリシーをローカルでコンパイルし、サンプルリクエストを AWS/Cloudflare ランタイムで再生して pass/block を確認。 |
| `analyze` | 監視モード JSONL を集約し、低頻度ブロック候補を抽出。 |
| `emit-waf` | インフラ設定のみ生成（エッジは生成しない）。エッジはそのままで WAF ルールだけ再デプロイしたいとき。 |
| `doctor` | 環境診断をワンショット実行。失敗チェックがあれば非ゼロ終了。 |
| `readiness` | 環境診断と policy posture を統合する本番リリースゲート。 |
| `capabilities` | target 対応状況の matrix を表示し、任意で policy control を target 別に評価。 |
| `deploy-template` | AWS / Cloudflare の artifact deployment 用 GitHub Actions workflow template を生成。 |
| `explain` | レビューやオンボーディング向けにポリシーの要点を表示。 |
| `visualize` | Mermaid/HTML のポリシー可視化を生成し、実装・監視・未対応・target別制御を明示。 |
| `diff` | 生成物の drift または policy posture の差分を比較。 |
| `migrate` | スキーマのバージョン間マイグレーション（現状 v1 のみの stub）。 |
| `openapi inspect` | Policyやbuild出力を変更せず、ローカルOpenAPIのSecurity Contractを決定的なText/JSONで確認。 |
| `openapi generate-policy` | 非破壊・review専用Policy Candidateとmeta sidecarを生成。 |
| `contract diff` | OpenAPI宣言と有効Policyを比較し、Security Findingを出力。 |

---

## `contract diff`

```bash
npx cdn-security contract diff \
  --openapi openapi.yaml --policy policy/security.yml --target aws
npx cdn-security contract diff \
  --openapi openapi.yaml --policy policy/security.yml --target cloudflare \
  --exceptions policy/finding-exceptions.yml --format json \
  --out reports/contract-diff.json --fail-on warning
npx cdn-security contract diff \
  --openapi openapi.yaml --policy policy/security.yml --target aws \
  --format sarif --out reports/cdn-security.sarif --fail-on never
```

- `--openapi`、`--policy`、`--target aws|cloudflare`は必須です。全inputとlocal refは`--workspace-root`内に限定されます。
- `--format text|json|sarif`の既定はtextです。JSONは[`contract-diff-report-v1.schema.json`](../schemas/contract-diff-report-v1.schema.json)に従います。SARIFはCI向けに決定的なSARIF 2.1.0を出力します。どちらのmachine formatにもtimestamp、absolute path、raw specification、secretを含めません。
- `--exceptions`は既存のFinding Exception契約を適用します。`selector.environment`を使う場合は`--environment <name>`を指定します。抑制件数は常に集計し、`--include-suppressed`指定時だけ抑制Finding本体を含めます。SARIFではaccepted external suppressionとして表現します。再現可能なCI reportでは`--current-date YYYY-MM-DD`で有効期限の評価日を固定します。
- `--fail-on error|warning|never`の既定は`error`です。終了コードはthreshold未満が`0`、到達時が`1`、input/config/safety errorが`2`、予期しない内部errorが`3`です。
- `--out`はworkspace内の存在するdirectoryにだけ出力します。既存regular fileの上書きには`--force`が必要で、Policy、build出力、解析したsource fileは保護されます。実行中は書込み可能なworkspaceを排他的に扱ってください。同一ユーザー権限でrename可能な別processは、検証済みでopen済みのdirectory inodeを検証後に移動できます。
- Textはsummaryから始まり、rule、route、expected/actual、evidence、remediationを表示します。色はTTYでのみ有効で、`NO_COLOR`で無効化できます。

明示的なreport出力以外は読み取り専用です。未対応・部分対応の解析項目は推測せず、omitted comparisonとして報告します。

Code Scanningのupload権限を付与せず、GitHub Actions artifactとしてSARIFを保存する例:

```yaml
- run: >-
    npx cdn-security contract diff --openapi openapi.yaml
    --policy policy/security.yml --target aws --format sarif
    --out reports/cdn-security.sarif --fail-on never
- name: Upload CDN security SARIF artifact
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
  with:
    name: cdn-security-sarif
    path: reports/cdn-security.sarif
```

これはartifact保存だけを行います。Code Scanningへの自動uploadはこのcommandの対象外です。

---

## `openapi inspect`

```bash
npx cdn-security openapi inspect --input openapi.yaml --workspace-root .
npx cdn-security openapi inspect --input openapi.yaml --workspace-root . --json
npx cdn-security openapi inspect --input openapi.yaml --workspace-root . --json --out reports/openapi-contract.json
```

- `--input <path>` は必須で、`--workspace-root` 内のOpenAPI 3.0/3.1 YAMLまたはJSONを受け付けます。
- ローカル`$ref`もworkspace内に限定され、remote refと`file:` refは無効です。
- Text出力はversion、digest、operation別のexposure/auth、content type、parameter、capability、limit warningを要約します。
- `--json`は決定的なSecurity IRと安全なanalyzer metadata/diagnosticを出力します。timestamp、absolute path、raw OpenAPIは含みません。
- `--out`には`--json`、存在する親directory、workspace内のpathが必要です。既存fileの上書きには`--force`が必要です。
- OpenAPI input、`policy/`、`dist/`は出力先にできません。inspectはPolicy生成・変更・deployを行いません。
- parse、reference、resource limitの失敗はstderrへ安定した`OPENAPI_*` codeと安全なmessageを出します。

JSON出力は[`openapi-inspection-v1.schema.json`](../schemas/openapi-inspection-v1.schema.json)に従います。未対応・部分対応の解析結果は明示され、publicとして扱われません。

## `openapi generate-policy`

```bash
npx cdn-security openapi generate-policy \
  --input openapi.yaml \
  --workspace-root . \
  --profile balanced \
  --out policy/openapi.candidate.yml
```

- `--input`、`--profile strict|balanced|permissive`、`--out`は必須です。
- `--workspace-root`はinput、local `$ref`、2つのoutput fileの境界です。
- 既存のregular Candidate/sidecar fileには`--force`が必要です。
- commandはschema-valid YAML Candidateと決定的な`.meta.json` sidecarを生成します。
  active Policyとのmergeやdeployは行いません。
- 認証詳細と未対応controlは省略として報告し、推測・近似しません。

runnable example、limit、review workflow、troubleshootingは
[OpenAPI導入ガイド](openapi-integration.ja.md)を参照してください。

---

## `init`

```bash
npx cdn-security init                                      # 対話形式
npx cdn-security init --platform aws --profile balanced    # 非対話
npx cdn-security init --platform aws --archetype rest-api  # アーキタイプ
npx cdn-security init --guided --platform cloudflare --app-shape rest-api --auth jwt --cors-origins https://app.example.com
```

- `--profile` と `--archetype` は排他指定です。スターターはセキュリティ強度（プロファイル）かアプリ形状（アーキタイプ）のいずれか。
- `--guided` はアプリ形状、CDN target、auth mode、保護 path、CORS origin、WAF posture、geo/IP 制約、deployment intent を順に尋ねます。
- guided setup は CI / scaffold script 向けに `--app-shape`、`--auth`、`--admin-paths`、`--cors-origins`、`--waf`、`--geo-block`、`--ip-allowlist`、`--deployment`、`--project` でも非対話実行できます。
- guided policy には secret 管理 docs へのコメントを入れます。secret 値は書かず、`EDGE_ADMIN_TOKEN`、`BASIC_AUTH_CREDS`、`URL_SIGNING_SECRET`、`WAF_LOG_DESTINATION_ARN` などの env var 名だけを参照します。
- `--force` で既存の `policy/security.yml` を上書きします。

## `build`

```bash
npx cdn-security build                        # AWS（デフォルト）
npx cdn-security build --target cloudflare    # Cloudflare Workers
npx cdn-security build --rule-group-only      # AWS: Web ACL を出力せず rule group のみ
npx cdn-security build --fail-on-permissive   # metadata.risk_level == permissive で非ゼロ終了
```

出力:

- `dist/edge/viewer-request.js`, `dist/edge/viewer-response.js`, `dist/edge/origin-request.js`（AWS）
- `dist/edge/cloudflare/index.ts`（Cloudflare）
- `dist/infra/*.tf.json` — WAF / geo / IP / CloudFront 設定 / origin タイムアウト

`build` では top-level の `extends` をサポートします。

- 選択したポリシーが別ポリシーを継承し、共通設定を再利用できます。
- `extends` は子ポリシーからの相対パスで解決されます。
- マージはオブジェクトは深い階層で子優先、配列は親→子の順で append です。
- スカラー置換は親サブツリーを上書きし、inheritance は `child` → `parent` → `grandparent` のような連鎖も有効です。

## `playground`

```bash
npx cdn-security playground                                      # 組み込みのサンプルケースを AWS+Cloudflare で実行
npx cdn-security playground --target aws --json                   # JSON 形式で結果を取得
npx cdn-security playground --policy policy/security.yml -f cases.json
npx cdn-security playground --allow-placeholder-token --target all  # INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN を許可
```

`playground` は指定ポリシーを一時ディレクトリへコンパイルし、生成された runtime で fixture を実行します。各 fixture ごとに `pass|block`、HTTP `status`、`block_reason`、対象 target（`aws` / `cloudflare`）を出力します。

入力形式:

- `--fixture <path>` は以下のいずれかを受け取れます。
  - `{ "fixtures": [ ... ] }`
  - `[ ... ]`
  - `{ "request": { ... } }`
- 各 fixture は以下を受け取れます。
  - `method`
  - `path`
  - `query`（文字列またはオブジェクト）
  - `headers`
  - `body`

fixture 例:

```json
{
  "fixtures": [
    { "name": "GET /", "request": { "method": "GET", "path": "/" } },
    { "name": "PATCH blocked", "request": { "method": "PATCH", "path": "/" } },
    { "name": "admin missing auth", "request": { "method": "GET", "path": "/admin", "headers": { "x-edge-token": "INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN" } } }
  ]
}
```

`--json` を指定すると、次のような machine-readable 出力になります。

```json
{
  "policyPath": "/path/to/policy/security.yml",
  "targets": [
    {
      "target": "aws",
      "fixtures": [
        {
          "name": "GET /",
          "decision": "pass",
          "status": 200,
          "block_reason": "",
          "path": "/",
          "method": "GET",
          "query": ""
        }
      ]
    }
  ]
}
```

## `analyze`

```bash
npx cdn-security analyze --input /path/to/monitor.jsonl
npx cdn-security analyze --input /path/to/monitor.jsonl --min-count 3 --top 10 --json
```

`analyze` はJSONLを変更せずに読み取り、有効recordをroute/reason別に集計して低頻度block候補を抽出します。ポリシーの安全性判定や変更の適用は行いません。

- `--input`: JSONLファイルパス（必須）。
- `--min-count`: block候補の件数の上限しきい値（以下を採用、既定`5`、小数切捨て）。
- `--top`: 候補数と候補ごとのsample数の上限（既定`20`、小数切捨て）。
- `--json`: stdoutへ末尾改行付き単一JSON文書。指定しなければtext report。

非空行は明示的なown propertyの`event`、`eventName`、`outcome`のいずれかを持つobjectである必要があります。前後空白と大文字小文字を正規化し、`allow`/`pass`/`passed`は`pass`、`block`/`blocked`は`block`、`monitor`/`monitoring`/`logged`は`monitor`として扱います。`audit`、`error`、`challenge`、`challenge_report`は意味を保持します。存在するevent aliasはすべて有効で、意味が一致する必要があります。statusだけからeventを推定せず、status 403のchallengeもblockへ変換しません。

外側にevent aliasが1つでもあれば、値が不正でも外側recordを選びます。存在しなければ、own propertyの`message`にevent aliasを持つobjectをJSON文字列で格納します。展開は1段のみで、外側metadataとの合成や別recordへのfallbackはしません。

補助文字列fieldはprivacy正規化前に空でないstringであることを検証します。存在するaliasをすべて検証後、次の順で最初の値を採用します。

| field | alias優先順位 |
| --- | --- |
| method | `method`, `httpRequest.method`, `request.method` |
| URI | `uri`, `path`, `request.uri`, `request.path`, `httpRequest.uri`, `httpRequest.path` |
| policy route | `policy_route`, `policyRoute`, `route`, `request.route`。すべて欠落時のみURI |
| target | `target`, `platform`, `provider`, `runtime` |
| reason | `block_reason`, `blockReason`, `reason` |

存在する`request`/`httpRequest`はobjectである必要があり、arrayやnullは不正です。`status`/`statusCode`は両方検証して最初を採用します。numberは安全な整数、stringは前後空白を除いた十進数字列で、値は0または100〜599です。明示0をfallbackで上書きしません。method/status/target/reasonの欠測表示は`UNKNOWN`/0/`unknown`/`unclassified`です。URI/routeの欠測と、採用値がprivacy正規化で空になった場合は内部でも実値と区別し、表示は`unknown`です。明示値`unknown`は`/unknown`になります。実routeのないblockも件数へ加算しますが、route候補には含めません。

有効eventはすべてroute/reason集計へ加算し、block/monitor件数には明示されたcanonical eventだけを加算します。候補は実routeを持つblockかつ`count <= --min-count`で、件数、routeの順に並び、同順位は入力順を維持します。credential、URL userinfo、query/fragment、危険なpath文字列は集計前に正規化します。診断にはraw recordや引数値を含めません。

| `summary.inputStatus` | 意味 | 終了コード | stderr（固定1行） |
| --- | --- | --- | --- |
| `complete` | 非空recordがすべて有効 | 0 | 空 |
| `partial` | 有効・不正が混在。有効分のreportを返す | 1 | `[WARN] ANALYZE_INPUT_PARTIAL` |
| `invalid` | 非空recordが存在し、有効recordが0件 | 1 | `[ERROR] ANALYZE_INPUT_INVALID` |
| `empty` | 非空recordが0件 | 1 | `[WARN] ANALYZE_INPUT_EMPTY` |

exit0は入力処理の完了であり、安全性の合格ではありません。非0終了でもreportは最後まで出力します。非空行の件数は`totalLines = parsedLines + unparseableLines`、有効record数は`analyzedEvents = parsedLines`です。JSONには`diagnostics`、textには`input_status`と`diagnostics`のJSON行を出力します。診断は`total`、以下の順序で0件も含む`counts`、先頭20件の`{line, code}`、残りの件数`omitted`から成ります。`line`は空行も含む1始まりの物理行番号です。

1. `ANALYZE_JSON_SYNTAX`: 外側JSON構文不正。
2. `ANALYZE_RECORD_TYPE`: 外側がobjectでない。
3. `ANALYZE_EVENT_MISSING`: event aliasもmessageもない。
4. `ANALYZE_EVENT_VALUE`: event aliasが空でないstringでない。
5. `ANALYZE_EVENT_UNKNOWN`: 未知event。
6. `ANALYZE_EVENT_ALIAS_CONFLICT`: event aliasの意味が不一致。
7. `ANALYZE_NESTED_MESSAGE`: 1段message envelopeが不正。
8. `ANALYZE_FIELD_VALUE`: 補助field/container不正。
9. `ANALYZE_STATUS_VALUE`: status不正。

1不正行につき診断は1件です。JSON/objectとrecord選択、eventの型・既知値・一致、container（`request`→`httpRequest`）、上表順の文字列field、statusの順に検証します。fatalではreportを返さずstdoutは空、exit1と固定stderrの`[ERROR] ANALYZE_INPUT_NOT_FOUND`、`[ERROR] ANALYZE_INPUT_READ_FAILED`、`[ERROR] ANALYZE_ARGUMENT_INVALID`（必須/未知optionも対象）のいずれかを返します。`analyze --help`は通常helpとexit0を維持します。

## `emit-waf`

```bash
npx cdn-security emit-waf                               # AWS WAF terraform
npx cdn-security emit-waf --target cloudflare           # Cloudflare WAF terraform
npx cdn-security emit-waf --format cloudformation       # AWS WAFv2 CloudFormation JSON
npx cdn-security emit-waf --target aws --rule-group-only
```

エッジコードは既にデプロイ済みで、ファイアウォールだけ再生成したいときに使います。フル `build` を走らせる必要がありません。`build` はデフォルトでエッジ + インフラ両方を出力するので、既存のフローは変わりません。

フラグ:

- `-p, --policy <path>` — ポリシーパス（デフォルト `policy/security.yml` → `policy/base.yml`）
- `-o, --out-dir <dir>` — 出力ディレクトリ（デフォルト `dist`）
- `-t, --target <aws|cloudflare>` — 対象プラットフォーム
- `--output-mode <full|rule-group>` — AWS のみ
- `--rule-group-only` — AWS のみ。`aws_wafv2_web_acl` を出さず rule group のみ生成
- `--format <terraform|cloudformation|cdk>` — `terraform` は AWS / Cloudflare に対応。`cloudformation` は AWS に対応し、`dist/infra/waf-cloudformation.json` を出力します。`cdk` は予約扱いのまま exit 2 を返します。

## `doctor`

```bash
npx cdn-security doctor                               # pass/fail レポートを出力、doctor-report.json を書き出し
npx cdn-security doctor --policy policy/security.yml
npx cdn-security doctor --strict                      # warn も失敗扱いにする
npx cdn-security doctor --no-report                   # JSON レポートを生成しない
```

以下のチェックを順に実行します。

| チェック | 失敗条件 |
| --- | --- |
| `node_version` | Node < 20.17.0 |
| `policy_exists` | `policy/security.yml` も `policy/base.yml` も見つからない |
| `policy_parses` | YAML パースエラー、またはトップレベルがオブジェクトでない |
| `policy_schema_version` | `version` がない、または CLI が対応するスキーマ（現状 v1）と不一致 |
| `env_vars_referenced_by_policy` | `routes[].auth_gate.{token_env,credentials_env,secret_env}` や `origin.auth.secret_env` が参照する環境変数のいずれかが未設定 / 空。CloudFront Functions はランタイムで env を読めないため、ビルド時に焼き込みます。空のまま通すと silent auth bypass の原因になります。 |
| `dist_edge_writable` | `dist/edge/` に書き込めない |
| `npm_dependencies` | `npm ls --depth=0 --json` が `problems[]` を返す。npm 自体がない環境では fail ではなく warn になります。 |

失敗チェックが 1 件もなければ exit `0`、あれば `1`。`--strict` では warn チェックも失敗扱いにします。デフォルトで `doctor-report.json` を書き出すので CI artifact にアップロードできます。

### CI 利用例

```yaml
- name: 環境診断
  run: |
    npx cdn-security doctor
- name: doctor レポートをアップロード
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: doctor-report
    path: doctor-report.json
```

## `readiness`

```bash
npx cdn-security readiness
npx cdn-security readiness --target cloudflare
npx cdn-security readiness --strict
npx cdn-security readiness --fail-on-weak-waf-baseline
npx cdn-security readiness --json
npx cdn-security readiness --report readiness-report.json
```

選択した policy に対して、本番向けのリリースゲートを実行します。環境診断と policy validation を再利用し、そのうえで risk level、enforce mode、HTTP method 制限、レスポンスヘッダー、WAF rate limit、managed rule のカバレッジ、target 固有の未対応機能を確認します。

`fail` finding が 1 件でもあれば exit `1` です。`--strict` では warning finding も失敗扱いになります。`--json` は stdout に JSON を出力し、`--report <path>` は人間向け summary を出しつつ同じ machine-readable report をファイルに書き出します。

starter policy はローカルで使えるままにしつつ、本番 CI では弱い WAF posture を止めたい場合は `--fail-on-weak-waf-baseline` を使います。この flag は WAF baseline finding を `fail` に昇格します。対象は WAF 設定なし、rate limit なし、AWS managed rule の signal coverage 不足、`firewall.waf.scope: CLOUDFRONT` で CloudFront WAF logging が無効な場合です。

readiness report には read-only の `wafRecommendations` も含まれます。この engine は policy から `spa-static-site`、`rest-api`、`admin-panel`、`microservice-origin` の posture を推定し、managed WAF rule group と関連設定を、rationale、cost notes、false-positive notes、AWS / Cloudflare target support 付きで提案します。policy は変更しません。推奨の適用は別 change として手動で行ってください。

## `capabilities`

```bash
npx cdn-security capabilities
npx cdn-security capabilities --json
npx cdn-security capabilities --policy policy/security.yml --target aws
npx cdn-security capabilities --policy policy/security.yml --target cloudflare --json
```

AWS CloudFront Functions、AWS Lambda@Edge、Cloudflare Workers、Terraform-backed WAF control の target 対応状況を表示します。status は `supported`、`partial`、`unsupported`、`warning-only` です。

`--policy` を指定すると、設定済み control を検出し、選択 target で partial / unsupported / warning-only になる項目を `policyEvaluation.findings` に出します。このコマンドは読み取り専用で、finding があっても process は失敗させません。automation では `--json` の出力を検査してください。

## `deploy-template`

```bash
npx cdn-security deploy-template
npx cdn-security deploy-template --target aws
npx cdn-security deploy-template --target cloudflare
npx cdn-security deploy-template --out-dir .github/workflows --force
```

GitHub Actions workflow starter を書き出します。AWS template は信頼済み job 内で edge code を build しますが、credential が焼き込まれる可能性があるため upload は infra と readiness 証跡だけに限定し、edge は同じ job から deploy します。Cloudflare template は固定バージョンの Wrangler で deploy し、生成 artifact を upload します。

template は `EDGE_ADMIN_TOKEN`、`BASIC_AUTH_CREDS`、`URL_SIGNING_SECRET`、`JWT_SECRET`、`ORIGIN_SECRET`、`CHALLENGE_SECRET`、`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID` などの GitHub Secrets 名だけを参照し、secret 値は含みません。Cloudflare で policy が追加の `*_env` 名を使う場合は `CDN_SECURITY_WORKER_SECRET_NAMES` を拡張してください。既存ファイルは `--force` を付けない限り上書きしません。

フラグ:

- `-o, --out-dir <dir>` — workflow の出力ディレクトリ（デフォルト `.github/workflows`）
- `-t, --target <aws|cloudflare|all>` — 生成する template（デフォルト `all`）
- `-f, --force` — 既存 workflow ファイルを上書き

出力:

- `--target` が `aws` または `all` のとき `<out-dir>/cdn-security-aws.yml`
- `--target` が `cloudflare` または `all` のとき `<out-dir>/cdn-security-cloudflare.yml`
- 書き込んだファイルごとに `[SUCCESS] Generated <path>`

成功時は exit `0` です。無効な `--target`、または `--force` なしで既存ファイルがある場合は exit `1` です。上書き拒否時は部分書き込みは行われません。

## `explain`

```bash
npx cdn-security explain
npx cdn-security explain --policy policy/security.yml
```

ポリシーのスキーマ、モード、許可メソッド、リクエスト制限、host / route の姿勢、認証ゲート、WAF 設定、レスポンスヘッダーを要約表示します。読み取り専用なので、コードレビュー、運用 Runbook、Issue 調査に使えます。

## `visualize`

```bash
npx cdn-security visualize
npx cdn-security visualize --policy policy/security.yml --target aws
npx cdn-security visualize --policy policy/security.yml --target all --format mermaid
npx cdn-security visualize --policy policy/security.yml --target cloudflare --format html --out policy-coverage.html
```

ポリシーの層、ルート、認証ゲート、WAF 対応、レスポンス設定を deterministic なフロー図として出力します。

- Edge / WAF / Origin / Response のレイヤーを可視化
- ルートと auth gate の要約
- target ごとの制御状態（enforce / monitor / target-specific / unsupported）

`--format mermaid` は標準出力へ Mermaid テキストを出すため、CI でブラウザランタイム不要です。`--format html` は同じ図を静的 HTML にし、ブラウザ閲覧時に mermaid を描画します。

フラグ:

- `-p, --policy <path>` — ポリシーパス（デフォルト `policy/security.yml` → `policy/base.yml`）
- `-t, --target <aws|cloudflare|all>` — 制御の対象 target（デフォルト `all`）
- `--format <mermaid|html>` — 出力形式（デフォルト `mermaid`）
- `-o, --out <path>` — 標準出力の代わりにファイルへ書き出す

出力:

- `--out` なし: Mermaid または HTML を標準出力へ出力
- `--out` あり: 指定パスへ artifact を書き出し、`[SUCCESS] Wrote visualization to <path>` を表示

成功時は exit `0` です。無効な `--target` / `--format`、ポリシー未存在、描画エラーは exit `1` です。

## `diff`

```bash
npx cdn-security diff
npx cdn-security diff --target cloudflare
npx cdn-security diff --out-dir dist
npx cdn-security diff --semantic --baseline policy/security.previous.yml --policy policy/security.yml --target aws
```

選択したポリシーを一時ディレクトリへコンパイルし、現在の出力ツリーと比較します。`MISSING`、`EXTRA`、`CHANGED` を表示し、生成物が古い場合は exit `1` で失敗します。

`--semantic` を付けると、2 つの policy ファイルを比較して posture 変更を表示します。PR レビュー向けに、認証ゲート削除、許可メソッド追加、CSP 弱体化、WAF ルール変更、ターゲット別の capability 差分を検知できます。

- `--policy` は比較対象（候補）policy のパスです。省略時は `policy/security.yml`（無ければ `policy/base.yml`）。
- `--baseline` は比較元 policy のパスです。省略時は `policy/base.yml` を使用します。
- `--target` は `aws` / `cloudflare` / `all` を指定し、ターゲット別の capability 変化を表示します。
- `--json` は posture diff を JSON 出力します。
- `--semantic` を付けると drift 比較ではなく posture 比較になります。

## `migrate`

```bash
npx cdn-security migrate              # ドライラン
npx cdn-security migrate --to 1       # v1 の場合は no-op
npx cdn-security migrate --policy policy/security.yml --to 1 --write
```

ポリシーファイルのスキーマバージョンを検査または移行します。現状は v1 のみが出荷されているため、v1 → v1 は将来の migration path が登録されるまで読み取り専用の no-op です。

フラグ:

- `-p, --policy <path>` — 検査対象のポリシー（デフォルト `policy/security.yml`）
- `--to <version>` — 移行先スキーマバージョン（デフォルト `1`）
- `--write` — migration path が存在するとき、移行結果をその場で書き戻す

出力:

- ポリシーパスと現在/移行先スキーマバージョンを示す `[INFO]` 行
- 移行不要時は `[OK] Already at target version — no migration needed.`

移行先に既に到達している場合は exit `0` です。パースエラー、`version` 欠落、ダウングレード、その他の検証失敗は exit `1` です。この CLI に未登録の前方 migration は exit `2`（CLI のアップグレードが必要なケース用の予約コード）です。

スキーマの SemVer 契約と非推奨ウィンドウについては [schema-migration.ja.md](./schema-migration.ja.md) を参照してください。
