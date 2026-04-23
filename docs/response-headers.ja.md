# レスポンスセキュリティヘッダー

`policy/security.yml` の `response_headers` は、viewer-response（AWS CloudFront Functions）と Cloudflare Worker がクライアントに返すヘッダーを制御する。本ドキュメントは HSTS/X-Content-Type-Options/Referrer-Policy/Permissions-Policy 以外で本フレームワークが担当する領域——特に、認証済みパスの保護、クロスオリジン分離のオプトイン、CSP の安全なロールアウト——を記す。

## フィールド

| キー | 型 | 既定値 | 備考 |
|---|---|---|---|
| `force_vary_auth` | boolean | `true` | `true` のとき、いずれかの `auth_gate.match.path_prefixes` にヒットするパスへ `Cache-Control: no-store, no-cache, must-revalidate, private` と `Vary: Authorization, Cookie` を強制付与する。異なる利用者間での共有キャッシュ汚染を防ぐ。ダウンストリームがユーザー単位でキーを切っていることが明らかな場合のみ無効化する。 |
| `csp_public` / `csp_admin` | string | 安全な既定値 | 非 admin / admin パスに発行する CSP 文字列。`csp_nonce` 有効時、文字列中の `'nonce-PLACEHOLDER'` はレスポンス生成時に per-response nonce へ置換される。 |
| `csp_nonce` | boolean | `false` | `true` のとき、per-response nonce を `csp_public`/`csp_admin`/`csp_report_only` の `'nonce-PLACEHOLDER'` に注入し、`X-CSP-Nonce` ヘッダーでオリジンへ共有する。AWS は `Math.random`（暗号学的 PRNG ではない。「制限」節参照）、Cloudflare は `crypto.getRandomValues` を使う。 |
| `csp_report_only` | string | `""` | 設定すると、通常の CSP と並行して `Content-Security-Policy-Report-Only` を返す。新しい CSP を破綻なく試すのに使う。 |
| `csp_report_uri` | string | `""` | ポリシー文字列中の `report-uri` / `report-to` の先として記載する URL。フレームワークは内容を検証しない。 |
| `coop` | `same-origin` / `same-origin-allow-popups` / `unsafe-none` | 未設定 | `Cross-Origin-Opener-Policy`。 |
| `coep` | `require-corp` / `credentialless` / `unsafe-none` | 未設定 | `Cross-Origin-Embedder-Policy`。 |
| `corp` | `same-site` / `same-origin` / `cross-origin` | 未設定 | `Cross-Origin-Resource-Policy`。 |
| `reporting_endpoints` | string | `""` | `Reporting-Endpoints`（`Report-To` の後継 RFC）へそのまま載せる値。 |
| `clear_site_data_paths` | string[] | `[]` | 前方一致でマッチしたパスに対し 2xx/3xx 時に `Clear-Site-Data` と `Cache-Control: no-store` を付与する。ログアウト／セッション終了エンドポイント向け。 |
| `clear_site_data_types` | string[] | `["cache","cookies","storage"]` | 発行する `Clear-Site-Data` ディレクティブ。許可値: `cache`, `cookies`, `storage`, `executionContexts`, `*`。 |

## 挙動

### 認証済みパスのキャッシュ安全性 (`force_vary_auth`)

従来は admin 形状の最初のルートだけが `Cache-Control: no-store` を受け取っていた。`/api` や `/download` の JWT / signed-URL ゲートは既定のキャッシュ挙動を引き継いでしまい、認証済みエンドポイントで足を撃ち抜きかねなかった。

`force_vary_auth: true`（既定）の場合:

1. ビルド時: コンパイラが全 `auth_gate` の `match.path_prefixes` の和集合を `authProtectedPrefixes` として埋め込む。
2. レスポンス時: リクエスト URI がいずれかのプレフィックスに一致すると以下を付与する。
   - `Cache-Control: no-store, no-cache, must-revalidate, private`
   - `Pragma: no-cache`
   - `Vary: Authorization, Cookie`（既存の `Vary` とマージ）

### CSP nonce の導入

1. `csp_nonce: true` に設定。
2. オリジン側で `<script>` のブートストラップを `<script nonce="{{NONCE}}">...</script>` に書き換え、フレームワークが返す `X-CSP-Nonce` ヘッダーから nonce を読み取る。
3. `csp_public` と `csp_admin` の中で `'nonce-PLACEHOLDER'` を使う。エッジがレスポンスごとに新しい nonce を代入する。

### Report-Only 運用

`csp_report_only` に新しい CSP を入れる。強制適用される `csp_public`/`csp_admin` はそのままで、`Report-Only` 側が違反を `report-uri`/`report-to` に送る——画面は壊れない。

### クロスオリジン分離

`coop` + `coep` + `corp` で crossOriginIsolated（SharedArrayBuffer、高精度タイマー）を有効化できる。`require-corp` は `Cross-Origin-Resource-Policy` を返さない埋め込みサードパーティアセットを壊すので、opt-in。事前にサードパーティの連鎖を確認すること。

## プラットフォーム上の制限

### CloudFront Functions (AWS)

- 複数 `Set-Cookie` は CFF からは 1 本の結合文字列として見える。属性を安全に追加するには文字列レベルのガードが必要で、複数 Cookie を独立に書き換えるユースケースは Lambda@Edge (`origin-response`) か Cloudflare Worker ターゲットで扱うべき。
- Web Crypto API は使えない。CSP nonce は `Math.random` にフォールバックする。ロールアウトの利便と割り切ること——暗号学的な防御が求められる場面では Cloudflare ターゲットを使う。もしくは AWS 側では `csp_nonce` を無効にし nonce 管理をオリジンに寄せる。

### Cloudflare Workers

- CSP nonce は `crypto.getRandomValues`（CS-PRNG）。
- 複数 `Set-Cookie` は可能な限り `Headers#getSetCookie()` で取り出し、旧ランタイムでは `Headers#get('set-cookie')` にフォールバックする。属性検査は `(?:^|; *)Secure(?:;|$)` のように境界アンカー付き正規表現で行い、Cookie 値の部分一致を拾わない。

## 例

```yaml
response_headers:
  hsts: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "camera=(), microphone=(), geolocation=()"

  force_vary_auth: true

  coop: same-origin
  coep: require-corp
  corp: same-origin
  reporting_endpoints: 'csp="https://reports.example.com/csp", default="https://reports.example.com/default"'

  csp_public: "default-src 'self'; script-src 'self' 'nonce-PLACEHOLDER'; report-to csp"
  csp_admin:  "default-src 'self'; script-src 'self' 'nonce-PLACEHOLDER'; frame-ancestors 'none'"
  csp_nonce: true
  csp_report_only: "default-src 'self'; script-src 'self'; report-to csp"
```

### ログアウト時の Clear-Site-Data

セッション終了エンドポイントを明示する:

```yaml
response_headers:
  clear_site_data_paths:
    - /auth/logout
    - /session/end
  # 任意の上書き。既定は ["cache","cookies","storage"]。
  # clear_site_data_types: ["cache", "cookies", "storage", "executionContexts"]
```

エッジは `Clear-Site-Data` を 2xx/3xx のレスポンスに限って発行し、ログアウト失敗時にローカル状態を巻き戻してしまうのを防ぐ。同じレスポンスに `Cache-Control: no-store` を強制付与し、下流キャッシュが別ユーザーへディレクティブを使い回すのも防ぐ。

## 脅威対応

- Issue #8 — `force_vary_auth` により、認証ユーザー間の共有キャッシュ汚染を防ぐ。
- Issue #20 — `clear_site_data_paths` により、ログアウトエンドポイントで `Clear-Site-Data` と `no-store` を発行し、中間装置によるキャッシュ再生を防ぐ。
- Issue #10 — COOP/COEP/CORP によりクロスオリジン分離を有効にし、フレーミング/埋め込みリスクを下げる。
- Issue #11 — per-response CSP nonce により `'unsafe-inline'` を不要にする。
- Issue #13 — Cloudflare ターゲットが複数 `Set-Cookie` を壊さずに属性を書き換える。AWS ターゲットは単一 Cookie 前提を明示する。
- Issue #19 — `csp_report_only` を強制 CSP と並行で返し、安全に反復できる。
