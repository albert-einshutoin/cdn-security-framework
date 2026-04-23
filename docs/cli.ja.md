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
| `emit-waf` | インフラ設定のみ生成（エッジは生成しない）。エッジはそのままで WAF ルールだけ再デプロイしたいとき。 |
| `doctor` | 環境診断をワンショット実行。失敗チェックがあれば非ゼロ終了。 |
| `migrate` | スキーマのバージョン間マイグレーション（現状 v1 のみの stub）。 |

---

## `init`

```bash
npx cdn-security init                                      # 対話形式
npx cdn-security init --platform aws --profile balanced    # 非対話
npx cdn-security init --platform aws --archetype rest-api  # アーキタイプ
```

- `--profile` と `--archetype` は排他指定です。スターターはセキュリティ強度（プロファイル）かアプリ形状（アーキタイプ）のいずれか。
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

## `emit-waf`

```bash
npx cdn-security emit-waf                               # AWS WAF terraform
npx cdn-security emit-waf --target cloudflare           # Cloudflare WAF terraform
npx cdn-security emit-waf --target aws --rule-group-only
```

エッジコードは既にデプロイ済みで、ファイアウォールだけ再生成したいときに使います。フル `build` を走らせる必要がありません。`build` はデフォルトでエッジ + インフラ両方を出力するので、既存のフローは変わりません。

フラグ:

- `-p, --policy <path>` — ポリシーパス（デフォルト `policy/security.yml` → `policy/base.yml`）
- `-o, --out-dir <dir>` — 出力ディレクトリ（デフォルト `dist`）
- `-t, --target <aws|cloudflare>` — 対象プラットフォーム
- `--output-mode <full|rule-group>` — AWS のみ
- `--rule-group-only` — AWS のみ。`aws_wafv2_web_acl` を出さず rule group のみ生成
- `--format <terraform|cloudformation|cdk>` — 現状 `terraform` のみ生成。`cloudformation`・`cdk` は stub で exit 2 を返します（パイプラインで静かに誤フォールバックしないように意図的にエラーで止めています）。

## `doctor`

```bash
npx cdn-security doctor                               # pass/fail レポートを出力、doctor-report.json を書き出し
npx cdn-security doctor --policy policy/security.yml
npx cdn-security doctor --no-report                   # JSON レポートを生成しない
```

以下のチェックを順に実行します。

| チェック | 失敗条件 |
| --- | --- |
| `node_version` | Node < 20 |
| `policy_exists` | `policy/security.yml` も `policy/base.yml` も見つからない |
| `policy_parses` | YAML パースエラー、またはトップレベルがオブジェクトでない |
| `policy_schema_version` | `version` がない、または CLI が対応するスキーマ（現状 v1）と不一致 |
| `env_vars_referenced_by_policy` | `routes[].auth_gate.{token_env,credentials_env,secret_env}` や `origin.auth.secret_env` が参照する環境変数のいずれかが未設定 / 空。CloudFront Functions はランタイムで env を読めないため、ビルド時に焼き込みます。空のまま通すと silent auth bypass の原因になります。 |
| `dist_edge_writable` | `dist/edge/` に書き込めない |
| `npm_dependencies` | `npm ls --depth=0 --json` が `problems[]` を返す。npm 自体がない環境では fail ではなく warn になります。 |

失敗チェックが 1 件もなければ exit `0`、あれば `1`。デフォルトで `doctor-report.json` を書き出すので CI artifact にアップロードできます。

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

## `migrate`

```bash
npx cdn-security migrate              # ドライラン
npx cdn-security migrate --to 1       # v1 の場合は no-op
```

スキーマの SemVer 契約と非推奨ウィンドウについては [schema-migration.ja.md](./schema-migration.ja.md) を参照してください。
