# ポリシーアーキタイプ

> **言語:** [English](./archetypes.md) · 日本語

アーキタイプは、よくあるアプリケーション形態に合わせて整えられたポリシーのプリセットです。プロファイル（`strict` / `balanced` / `permissive`）が**セキュリティ強度**を表すのに対し、アーキタイプは**アプリの形**を表します。オリジンが想定しているメソッド、認証の配置、レンダリング出力に合う CSP 戦略、といった観点です。

自分のアプリに近いアーキタイプを選び、そのうえでポリシーを調整してください。すべてのアーキタイプは `metadata.risk_level` を設定しているため、既存の CI ゲート（permissive 警告、ドリフトチェック）はそのまま効きます。

---

## 用意されているアーキタイプ

### `spa-static-site`
**用途**：CloudFront/Cloudflare 上の SPA（React/Vue/Svelte）や静的マーケティングサイト。
**メソッド**：`GET`・`HEAD` のみ（書き込みなし）。
**認証**：エッジでは無し（オリジンは不変アセット）。
**ヘッダ**：インラインシェルスクリプト用の nonce ベース CSP、HSTS preload、厳格な Referrer-Policy。
**防御**：`/../`・`.git/`・`.env` の経路ブロック、スキャナ UA ブロックリスト。

### `rest-api`
**用途**：JSON API オリジン。HTML を返さない。
**メソッド**：REST フルセット（CORS プリフライト用に `OPTIONS` を含む）。
**認証**：`/api/*` に RS256 JWT（JWKS の SSRF ガード + stale-if-error キャッシュ付き）。
**ヘッダ**：`default-src 'none'; frame-ancestors 'none';`（誤って HTML を返してしまった場合の多層防御）。
**CORS**：許可 Origin + credentials + 10 分のプリフライトキャッシュ。
**レートリミット**：`/api/auth` に強め（200/IP/5 分）。

### `admin-panel`
**用途**：社内向け管理画面。
**メソッド**：`GET`・`HEAD`・`POST`。
**認証**：サイトルートで `static_token` ゲート（L7 IP 許可 / VPN / WAF geo-block と組み合わせる）。
**ヘッダ**：厳格 CSP + COOP + COEP、すべて no-store、狭い Permissions-Policy。
**防御**：UA ブロックリストを拡張（curl/wget/python-requests を不許可）。

### `microservice-origin`
**用途**：CDN 背後のバックエンドマイクロサービス。オリジンはエッジ経由のリクエスト以外を拒否したい。
**メソッド**：REST フルセット（`OPTIONS` は除外）。
**認証**：エッジが `X-Edge-Secret: $ORIGIN_SECRET` を注入し、オリジンはそれで直接アクセスを拒否。
**ヘッダ**：`default-src 'none'; frame-ancestors 'none';`、HSTS。
**タイムアウト**：connect 5 秒、read 30 秒。

---

## アーキタイプの使い方

### 対話形式スキャフォールド

```bash
npx cdn-security init
```

スターター選択で **Archetype** を選ぶと、上記 4 種類から選択できます。

### 非対話形式

```bash
npx cdn-security init --platform aws --archetype rest-api
```

`policy/archetypes/rest-api.yml` から `policy/security.yml` をスキャフォールドし、リファレンス用に同内容を `policy/archetypes/rest-api.yml` にも配置します。必要に応じて `policy/security.yml` を編集し、`npm run build` を実行してください。

### 排他指定

`--profile` と `--archetype` は併用できません。スターター形は 1 つだけ選んでください。途中で切り替える場合は、対象のアーキタイプまたはプロファイルで `policy/security.yml` を上書きし、`npm run build` と `npm run test:drift` を走らせてください。

---

## アーキタイプ vs プロファイル

| | プロファイル | アーキタイプ |
| --- | --- | --- |
| 目的 | セキュリティ強度の設定 | アプリ形態のプリセット |
| 選択肢 | strict / balanced / permissive | spa-static-site / rest-api / admin-panel / microservice-origin |
| 決めるもの | セキュリティ vs 互換性の balance | 認証・メソッド・CSP・CORS の出発点 |
| `risk_level` | プロファイル名と一致 | アーキタイプごとに設定（balanced または strict） |

プロファイルから始めて調整する、あるいはアーキタイプから始めて `risk_level` を調整する、どちらでも OK です。コンパイラはすべてのポリシーを同じ YAML として扱い、アーキタイプ専用コードパスはありません。

---

## CI カバレッジ

各アーキタイプには対応する golden fixture が `tests/golden/archetypes/<name>/` にあり、`npm run test:drift` で実行されます。コンパイラの変更がアーキタイプ出力に影響する場合、リリース前にここで検出されます。

新しいアーキタイプを追加したい場合は下記の手順を参照してください。

---

## アーキタイプの追加手順

1. `policy/archetypes/<name>.yml` を作成。必須項目：`version: 1`、`metadata.risk_level`、`metadata.description`。ユースケースガイダンスは `description` にまとめてください。
2. lint：`npm run lint:policy -- policy/archetypes/<name>.yml`
3. golden fixture を生成：
   ```bash
   mkdir -p tests/golden/archetypes/<name>
   EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy \
     node scripts/compile.js --policy policy/archetypes/<name>.yml --out-dir tests/golden/archetypes/<name>
   # その他 compile-cloudflare.js / compile-infra.js / compile-cloudflare-waf.js も同様に
   ```
4. `scripts/check-drift.js` の scenarios にアーキタイプを追加。
5. `bin/cli.js` の `init` ウィザードに選択肢を追加。
6. 本ドキュメント（EN + JA）に説明を追記。
