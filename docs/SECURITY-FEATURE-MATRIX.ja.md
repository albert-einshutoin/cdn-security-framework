# セキュリティ機能の対応状況（日本語）

「セキュリティ関連のどんな YAML にも対応しているか」を、カテゴリ別に **対応済み / 部分対応 / 未対応** で整理しました。

---

## 結論

**YAML による一元管理が可能な包括的セキュリティフレームワーク** として、主要なセキュリティ機能を網羅しています。

- **対応済み**: Request Hygiene（メソッド・URI・クエリ・ヘッダー制限、正規化、UA ブロック）、Response Security（セキュリティヘッダー、CORS、Cookie 属性）、Authentication（トークン、Basic、JWT、署名付き URL）、WAF（レート制限、マネージドルール、Geo、IP）、Transport（TLS/HTTP 版）、Origin（認証、タイムアウト）
- **部分対応**: 指紋（JA3）は WAF/Shield Advanced 依存

---

## 1. Transport（通信の保護）

| 項目 | 対応 | 備考 |
|------|------|------|
| **TLS バージョン (1.2 / 1.3)** | ✅ 対応 | `transport.tls.minimum_version` / `security_policy` → `dist/infra/cloudfront-settings.tf.json` |
| **HTTP バージョン (H2 / H3)** | ✅ 対応 | `transport.http.versions` → `dist/infra/cloudfront-settings.tf.json` |
| **HSTS (HTTPS 強制)** | ✅ 対応 | `response_headers.hsts` で定義し、viewer-response / Cloudflare で注入。 |

---

## 2. Firewall / Access（誰を通すか）

| 項目 | 対応 | 備考 |
|------|------|------|
| **Geo ブロック（国・地域制限）** | ✅ 対応 | `firewall.geo.block_countries` / `allow_countries` → `dist/infra/geo-restriction.tf.json` |
| **IP 制限（許可リスト / 拒否リスト）** | ✅ 対応 | `firewall.ip.allowlist` / `blocklist` → `dist/infra/ip-sets.tf.json` |
| **レート制限（DDoS 対策）** | ✅ 対応 | `firewall.waf.rate_limit` で `dist/infra/waf-rules.tf.json` にレートベースルールを出力。 |
| **WAF マネージドルール（SQLi, XSS, OWASP Top 10）** | ✅ 対応 | `firewall.waf.managed_rules` 配列 → `dist/infra/waf-rules.tf.json` (aws_wafv2_web_acl)。 |

---

## 3. Authentication（認証）

| 項目 | 対応 | 備考 |
|------|------|------|
| **Basic 認証** | ✅ 対応 | `routes[].auth_gate.type: basic_auth` と `credentials_env` で設定。viewer-request で検証。 |
| **トークン認証** | ✅ 対応 | `routes[].auth_gate.type: static_token` と `header`, `token_env` でパス別トークンゲート。 |
| **署名付き URL** | ✅ 対応 | `routes[].auth_gate.type: signed_url` と `algorithm`, `secret_env`, `expires_param`, `signature_param`。Lambda@Edge 必須。 |
| **JWT 検証** | ✅ 対応 | `routes[].auth_gate.type: jwt` と `algorithm` (RS256/HS256), `jwks_url`, `issuer`, `audience`。Lambda@Edge 必須。 |

---

## 4. Request Hygiene（リクエストの健全化）

| 項目 | 対応 | 備考 |
|------|------|------|
| **HTTP メソッド制限** | ✅ 対応 | `request.allow_methods` で viewer-request / Cloudflare に注入。 |
| **URI 長制限** | ✅ 対応 | `request.limits.max_uri_length` → 超過時 414。 |
| **クエリ長制限** | ✅ 対応 | `request.limits.max_query_length` → 超過時 414。 |
| **クエリパラム数制限** | ✅ 対応 | `request.limits.max_query_params` → 超過時 400。 |
| **ヘッダーサイズ制限** | ✅ 対応 | `request.limits.max_header_size` → 超過時 431。Lambda@Edge / Cloudflare 限定。 |
| **パス正規化** | ✅ 対応 | `request.normalize.path.collapse_slashes`, `remove_dot_segments` で URI をクリーンアップ。 |
| **クエリ正規化** | ✅ 対応 | `request.normalize.drop_query_keys` でトラッキングパラメータ（utm_*、gclid 等）を除去。 |
| **必須ヘッダー** | ✅ 対応 | `request.block.header_missing` で必須ヘッダーをチェック（UA 以外も対応）。 |
| **Bot/スキャナ対策（User-Agent）** | ✅ 対応 | `request.block.ua_contains` で既知スキャナをブロック。 |
| **指紋（JA3 等）** | △ 部分対応 | WAF/Shield Advanced 依存。フレームワークのスコープ外。 |

---

## 5. Response Security（ブラウザ保護）

| 項目 | 対応 | 備考 |
|------|------|------|
| **セキュリティヘッダー** | ✅ 対応 | `response_headers` の hsts, x_content_type_options, referrer_policy, permissions_policy, csp_public, csp_admin。 |
| **CORS（Cross-Origin Resource Sharing）** | ✅ 対応 | `response_headers.cors` で allow_origins, allow_methods, allow_headers, expose_headers, allow_credentials, max_age を設定。 |
| **Cookie 属性（Secure, HttpOnly, SameSite）** | ✅ 対応 | `response_headers.cookie_attributes` で secure, http_only, same_site (Strict/Lax/None) を設定。 |

---

## 6. Origin Security（オリジン保護）

| 項目 | 対応 | 備考 |
|------|------|------|
| **オリジンへの認証（カスタムヘッダー）** | ✅ 対応 | `origin.auth.type: custom_header` と `header`, `secret_env`。Lambda@Edge で秘密ヘッダーを注入。 |
| **タイムアウト設定** | ✅ 対応 | `origin.timeout.connect` / `read` → `dist/infra/cloudfront-origin.tf.json` |

---

## 対応状況サマリ

| カテゴリ | 対応済み | 部分対応 | 未対応 |
|----------|----------|----------|--------|
| **Transport** | HSTS, TLS 版, HTTP 版 | — | — |
| **Firewall / Access** | レート制限, Geo, IP, WAF マネージド | — | — |
| **Authentication** | トークン, Basic, JWT, 署名付き URL | — | — |
| **Request Hygiene** | メソッド, URI/クエリ/ヘッダー制限, 正規化, UA ブロック, 必須ヘッダー | 指紋（JA3） | — |
| **Response Security** | セキュリティヘッダー, CORS, Cookie 属性 | — | — |
| **Origin Security** | オリジン認証, タイムアウト | — | — |

---

## ランタイム対応表

| 機能 | CloudFront Functions | Lambda@Edge | Cloudflare Workers | Terraform |
|------|---------------------|-------------|-------------------|-----------|
| URI/クエリ制限 | ✓ | ✓ | ✓ | — |
| パス正規化 | ✓ | ✓ | ✓ | — |
| 必須ヘッダー | ✓ | ✓ | ✓ | — |
| ヘッダーサイズ | — | ✓ | ✓ | — |
| CORS | ✓ | ✓ | ✓ | — |
| Basic 認証 | ✓ | ✓ | ✓ | — |
| Cookie 属性 | ✓ | ✓ | ✓ | — |
| Geo ブロック | — | — | — | ✓ |
| IP 制限 | — | — | — | ✓ |
| WAF マネージド | — | — | — | ✓ |
| TLS/HTTP 版 | — | — | — | ✓ |
| JWT 検証 | — | ✓ | ✓ | — |
| 署名付き URL | — | ✓ | ✓ | — |
| オリジン認証 | — | ✓ | ✓ | — |
| タイムアウト | — | — | — | ✓ |

---

## 使用例

### JWT 認証

```yaml
routes:
  - name: api
    match:
      path_prefixes: ["/api"]
    auth_gate:
      type: jwt
      algorithm: RS256
      jwks_url: "https://cognito-idp.region.amazonaws.com/xxx/.well-known/jwks.json"
      issuer: "https://cognito-idp.region.amazonaws.com/xxx"
      audience: "api-client-id"
```

### CORS 設定

```yaml
response_headers:
  cors:
    allow_origins: ["https://example.com"]
    allow_methods: ["GET", "POST", "OPTIONS"]
    allow_headers: ["Content-Type", "Authorization"]
    allow_credentials: true
    max_age: 86400
```

### Geo ブロック

```yaml
firewall:
  geo:
    block_countries: ["CN", "RU"]
```

このドキュメントは、現行実装の「どこまでが YAML で制御されているか」を整理したものです。新規項目を足す場合は、上記マトリクスとスキーマ・コンパイラの対応を合わせて更新してください。
