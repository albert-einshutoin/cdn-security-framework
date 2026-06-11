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
| `diff` | 生成物の drift または policy posture の差分を比較。 |
| `migrate` | スキーマのバージョン間マイグレーション（現状 v1 のみの stub）。 |

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

生成された edge / infra artifact のための GitHub Actions workflow starter を書き出します。AWS template は `dist/edge/` と `dist/infra/` を build して upload し、後続の Terraform / CDK / CloudFront release flow に渡せる形にします。Cloudflare template は Worker を build し、`wrangler deploy --secrets-file` で設定済み runtime secret を code と一緒に渡して artifact も upload します。

template は `EDGE_ADMIN_TOKEN`、`BASIC_AUTH_CREDS`、`URL_SIGNING_SECRET`、`JWT_SECRET`、`ORIGIN_SECRET`、`CHALLENGE_SECRET`、`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID` などの GitHub Secrets 名だけを参照し、secret 値は含みません。Cloudflare で policy が追加の `*_env` 名を使う場合は `CDN_SECURITY_WORKER_SECRET_NAMES` を拡張してください。既存ファイルは `--force` を付けない限り上書きしません。

## `explain`

```bash
npx cdn-security explain
npx cdn-security explain --policy policy/security.yml
```

ポリシーのスキーマ、モード、許可メソッド、リクエスト制限、host / route の姿勢、認証ゲート、WAF 設定、レスポンスヘッダーを要約表示します。読み取り専用なので、コードレビュー、運用 Runbook、Issue 調査に使えます。

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
```

スキーマの SemVer 契約と非推奨ウィンドウについては [schema-migration.ja.md](./schema-migration.ja.md) を参照してください。
