# ポリシー

このディレクトリには、**セキュリティポリシー**（正）と、`security.yml` または `base.yml` にコピーして使う **プロファイル** を置きます。

---

## 推奨: init と build

**推奨フロー:** CLI でポリシーを作成し、ランタイムを生成します。

```bash
npx cdn-security init    # policy/security.yml と policy/profiles/<profile>.yml を作成
npx cdn-security build   # policy/security.yml（なければ policy/base.yml）を読み、dist/edge/ と dist/infra/ を生成
```

build は `policy/security.yml` を優先して参照し、なければ `policy/base.yml` を使います。どちらを有効ポリシーとして使っても構いません。

---

## ファイル

| ファイル | 役割 |
|----------|------|
| `security.yml` | `npx cdn-security init` で作成。存在する場合は有効なポリシー。 |
| `base.yml` | `security.yml` がないときに build が参照。有効ポリシーとして編集するか、プロファイルで上書き（下記参照）。 |
| `profiles/balanced.yml` | デフォルト。セキュリティと互換性のバランス。 |
| `profiles/strict.yml` | 制限を強め、ブロックを増やす。クライアントを制御できる場合向け。 |
| `profiles/permissive.yml` | 制限を緩め、ブロックを減らす。API・スクリプト・レガシークライアント向け。 |

---

## プロファイルの選び方（base.yml を使う場合）

`init` ではなく `base.yml` を使う場合は、プロファイルを選んで `base.yml` にコピーします。

| プロファイル | 使いどころ |
|--------------|------------|
| **balanced** | デフォルト。多くのサイト・API（ブラウザ＋一般的なクライアント）に適している。 |
| **strict** | エッジで最大限のセキュリティ。クエリ/URI 制限を厳しく、UA ブロックを増やす（curl/wget 等）、パスパターン・CSP を厳格に。汎用スクリプトやレガシークライアントを許可しない場合向け。 |
| **permissive** | ブロックを減らし、制限を緩める。API や、User-Agent を付けないクライアント、PUT/DELETE/OPTIONS を使う場合向け。 |

```bash
cp policy/profiles/balanced.yml policy/base.yml
# または
cp policy/profiles/strict.yml policy/base.yml
cp policy/profiles/permissive.yml policy/base.yml
```

その後 **build** でランタイムを生成します（[ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md) 参照）。デプロイ前にポリシー Lint を実行することを推奨します。

```bash
npx cdn-security build
# または
node scripts/policy-lint.js policy/base.yml
```

---

## プロファイル比較（概要）

| 設定 | balanced | strict | permissive |
|------|----------|--------|------------|
| `max_query_length` | 1024 | 512 | 2048 |
| `max_query_params` | 30 | 20 | 50 |
| `max_uri_length` | 2048 | 1024 | 4096 |
| UA ブロック | スキャナ系 | スキャナ＋curl, wget 等 | スキャナのみ |
| User-Agent 欠落でブロック | する | する | しない |
| 許可メソッド（デフォルト） | GET, HEAD, POST | GET, HEAD, POST | + PUT, PATCH, DELETE, OPTIONS |
| 管理パスプレフィックス | /admin, /docs, /swagger | + /api/admin, /internal | /admin, /docs, /swagger |
| CSP | 標準 | 厳格（script-src, form-action） | 標準 |

---

## 数値フィールドの上下限

`npm run lint:policy` は以下のレンジ外の値を拒否します。0 や負値、過大なキャッシュ、WAF 非互換の rate ceiling を早期に検出するためです。業務要件で上下限を超える必要がある場合はユースケースを添えて Issue を立ててください。

| フィールド | 最小 | 最大 | 備考 |
|------|------|------|------|
| `request.limits.max_query_length` | 1 | 65,536 | バイト |
| `request.limits.max_query_params` | 1 | 1,024 | キー数 |
| `request.limits.max_uri_length` | 1 | 8,192 | バイト |
| `request.limits.max_header_size` | 1 | 65,536 | バイト |
| `routes[].auth_gate.clock_skew_sec` | 0 | 600 | 秒 |
| `routes[].auth_gate.cache_ttl_sec` | 0 | 86,400 | 秒（1 日） |
| `response_headers.cors.max_age` | 0 | 86,400 | 秒（ブラウザ CORS 上限） |
| `firewall.waf.rate_limit` | 100 | 2,000,000,000 | AWS WAFv2 の 5 分レートウィンドウ |
| `origin.timeout.connect` | 1 | 10 | CloudFront 上限 |
| `origin.timeout.read` | 1 | 60 | CloudFront 上限 |

---

## permissive プロファイル警告

`permissive` プロファイルには `metadata.risk_level: permissive` タグが付いています。コンパイラはこのタグを検出するたびに stderr に警告を出し、`--fail-on-permissive` が付いていれば非 0 終了します。本番 CI では必ず次のようにゲートしてください:

```bash
npx cdn-security build --fail-on-permissive
```

プロファイル比較と、推奨される dev/prod ゲート運用の詳細は [docs/profiles.ja.md](../docs/profiles.ja.md) を参照してください。

---

## 関連

* [プロファイル](../docs/profiles.ja.md) — プロファイル選択と本番 CI の permissive ゲート。
* [ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md) — ポリシーとランタイムの同期方法。
* [アーキテクチャ](../docs/architecture.ja.md) — ポリシー駆動の設計。

---

## WAF フィンガープリント制御（任意）

TLS フィンガープリントルールを policy に追加できます。

```yaml
firewall:
  waf:
    fingerprint_action: count   # count | block
    ja3_fingerprints:
      - "0123456789abcdef0123456789abcdef"
    ja4_fingerprints:
      - "t13d1516h2_8daaf6152771_02713d6af862"
```

推奨運用: まず `count` で投入し、ログ/メトリクス評価後に `block` へ切り替える。
