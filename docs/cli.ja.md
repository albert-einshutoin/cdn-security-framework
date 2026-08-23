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
```

- `--openapi`、`--policy`、`--target aws|cloudflare`は必須です。全inputとlocal refは`--workspace-root`内に限定されます。
- `--format text|json`の既定はtextです。JSONは[`contract-diff-report-v1.schema.json`](../schemas/contract-diff-report-v1.schema.json)に従い、timestamp、absolute path、raw specification、secretを含みません。
- `--exceptions`は既存のFinding Exception契約を適用します。`selector.environment`を使う場合は`--environment <name>`を指定します。抑制件数は常に集計し、`--include-suppressed`指定時だけ抑制Finding本体を含めます。再現可能なCI reportでは`--current-date YYYY-MM-DD`で有効期限の評価日を固定します。
- `--fail-on error|warning|never`の既定は`error`です。終了コードはthreshold未満が`0`、到達時が`1`、input/config/safety errorが`2`、予期しない内部errorが`3`です。
- `--out`はworkspace内の存在するdirectoryにだけ出力します。既存regular fileの上書きには`--force`が必要で、Policy、build出力、解析したsource fileは保護されます。
- Textはsummaryから始まり、rule、route、expected/actual、evidence、remediationを表示します。色はTTYでのみ有効で、`NO_COLOR`で無効化できます。

明示的なreport出力以外は読み取り専用です。未対応・部分対応の解析項目は推測せず、omitted comparisonとして報告します。

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

`analyze` は監視モードの構造化ログ（JSONL）を受け取り、`block` / `monitor` / `pass` を集約して低頻度な block の候補を抽出し、監視から enforce への移行判断を支援します。

対応オプション:

- `--input`: `JSONL` のログファイルパス（必須）
- `--min-count`: `block` 判定の低頻度しきい値（デフォルト `5`）
- `--top`: ルート/サンプルの最大表示件数（デフォルト `20`）
- `--json`: 機械可読 JSON を標準出力

出力:

- 全体サマリ（総行数 / パース可能行 / ブロック / monitor）
- `block_reason` ごとの集計（対象 target / route）
- `policy route` ごとの集計（`block_reason` / target）
- `count <= --min-count` の低頻度 block候補（サンプルイベント付き）

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
