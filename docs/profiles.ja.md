# セキュリティプロファイル

本フレームワークは `policy/profiles/` に 3 つのビルトインプロファイルを同梱しています。それぞれが完結した `security.yml` の出発点であり、コピーしてからカスタマイズする前提です。

| プロファイル | `metadata.risk_level` | 想定用途 |
|--------------|-----------------------|----------|
| `strict` | `strict` | 高セキュリティが必要な公開サイト、管理画面、信頼できないクライアント向け。レガシークライアントや過激なスクレイパーが壊れる可能性あり。 |
| `balanced` | `balanced` | 一般的な Web + API トラフィックに対する推奨デフォルト。誤検知を抑えつつ現実的なブロック姿勢。 |
| `permissive` | `permissive` | API 専用エッジや互換性重視の用途。**意図的にゆるいため、本番環境には推奨しません。** |

`risk_level` フィールドは宣言的なタグです。ビルドツールはこれを読んで挙動を調整しますが、タグ自体で生成物が変わるわけではありません。実際の挙動を決めるのは policy 本体（allow_methods, limits, block ルールなど）です。

---

## プロファイルの選択

特別な理由がない限り、まずは **`balanced`** から始めてください。本フレームワークが基準としてチューニングしている設定です。

- 公開管理画面や決済フロー、高価値な標的の保護で、クライアント側調整も可能なら **`strict`** を選択してください。
- 上流で WAF 付き API ゲートウェイなど別のフィルタ層が効いていて、互換性のために広めの入力を許容する必要がある場合のみ **`permissive`** を選んでください（例: RPC 風 API で全 HTTP メソッドを許可する）。

判断に迷うなら `balanced` から出発し、丸ごと `strict` に切り替えるのではなく個別フィールドを締める方針を推奨します。

---

## `permissive` 警告

`permissive` は意図的にゆるいため、`metadata.risk_level: permissive` が付いた policy をビルドするたびに警告を表示します:

```
[WARN] metadata.risk_level is "permissive" — this profile is intentionally loose and NOT recommended for production. See docs/profiles.md. Pass --fail-on-permissive in CI to hard-fail.
```

これは `stderr` に出るため生成物は汚しませんが、CI ログには残ります。

### 本番 CI でハードフェイルする

本番パイプラインでは `--fail-on-permissive` でゲートしてください。permissive タグが付いていればビルドが非 0 で終了します:

```bash
# strict / balanced は通過、permissive は失敗
cdn-security build --fail-on-permissive
# 直接叩く場合:
node scripts/compile.js --policy policy/security.yml --fail-on-permissive
```

推奨運用:

- **開発 / ステージング**: `cdn-security build`（警告のみ）
- **本番リリース**: `cdn-security build --fail-on-permissive`

これで permissive policy を本番 CDN に誤って投入する事故を構造的に防げます。

### タグは任意

このタグは任意です。`policy/base.yml` や手書き policy はデフォルトではタグ付けされておらず、警告も出ません。

`policy/profiles/permissive.yml` を `policy/security.yml` の出発点としてコピーすると、`metadata.risk_level: permissive` タグも一緒に付いてきます。タグは残したままにして本番 CI ゲートで検出できるようにしてください。policy を十分に締めて permissive ではなくなったと判断したときだけ削除／変更し、その時は `balanced` か `strict` を使ってください。

---

## プロファイルのカスタマイズ

出発点にしたいプロファイルをコピーして編集します:

```bash
cp policy/profiles/balanced.yml policy/security.yml
$EDITOR policy/security.yml
npm run lint:policy
npm run build
```

オンボーディングの全体像は [quickstart.ja.md](quickstart.ja.md) を、コンパイル／デプロイのループは [policy-runtime-sync.ja.md](policy-runtime-sync.ja.md) を参照してください。
