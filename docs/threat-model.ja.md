# 脅威モデル

本ドキュメントは、本 Edge セキュリティフレームワークが対象とする脅威を整理し、
Edge / WAF / Origin のどのレイヤーが担当するかを明確にします。

---

## スコープ

* **対象**: CDN エッジに到達するトラフィック（Viewer Request / Origin Request / Workers fetch）。
* **対象外**: 内部 DB 不正利用、業務ロジックの欠陥、認証後の不正（アプリケーションで対応）。

---

## 脅威カテゴリ

### 1. パストラバーサル / LFI

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| URI 内の明らかな `../`、`%2e%2e`、エンコードされたパス操作 | 早期ブロック (400) | WAF マネージドルールで広いパターン対応；Origin でパス解決を検証 |

**フレームワーク**: Edge で粗いパターン（`..\/`、`%2e%2e` 等）をブロック。網羅は WAF/Origin。

---

### 2. 不要な HTTP メソッド

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| TRACE, CONNECT、公開パスへの任意メソッド | ブロック (405) | — |

**フレームワーク**: ポリシーの `allow_methods`；リスト外は Edge で拒否。

---

### 3. スキャナ / 自動化 (UA ベース)

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| 既知スキャナ UA（sqlmap, nikto, acunetix, masscan 等） | ブロック (403) | Bot 管理、レート制限、CAPTCHA |

**フレームワーク**: Edge で UA 拒否リストによる粗い遮断。高度な Bot 検知は WAF。

---

### 4. クエリ文字列の悪用 (DoS / キャッシュ汚染)

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| 過剰なクエリ長・パラメータ数 | ブロック (414 / 400) | — |
| utm_*, gclid, fbclid によるキャッシュキー汚染 | 正規化（キー除去） | — |

**フレームワーク**: `max_query_length`、`max_query_params`、`drop_query_keys`。

---

### 5. ヘッダー欠落・不正

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| User-Agent 欠落（自動化の可能性） | ポリシーに応じてブロック (400) または許可 | — |

**フレームワーク**: 任意の `header_missing` ブロック（例: User-Agent）。プロファイルで設定可能。

---

### 6. 管理・内部パスの露出

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| /admin, /docs, /swagger への未認証アクセス | 簡易トークンゲート (401) | 機密操作はアプリで認証 |

**フレームワーク**: Edge の auth_gate（静的トークン）。強固な認証は Origin または Lambda@Edge（JWT 等）。

---

### 7. セキュリティヘッダー欠落

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| HSTS, X-Content-Type-Options, CSP 等の欠落 | レスポンスに付与 | — |

**フレームワーク**: Viewer Response / Worker がポリシーに従いヘッダーを付与。

---

### 8. 情報漏洩

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| X-Powered-By、Server バージョン等のレスポンス | 除去または上書き | — |

**フレームワーク**: レスポンスハンドラで該当ヘッダーを除去・正規化可能。

---

### 9. JWKS SSRF（JWT ゲート経由のサーバーサイドリクエストフォージェリ）

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| クラウドメタデータ（`169.254.169.254`）、ループバック、RFC1918、リンクローカルを指す悪意ある／誤った `jwks_url` | ビルド時に拒否、ランタイムで再検証 | — |
| JWKS ホストから内部エンドポイントへの攻撃者制御リダイレクト | 3xx レスポンスを拒否（Workers: `redirect: 'error'`、Lambda@Edge: 明示的な 3xx 拒否） | — |
| ポリシーに明示的な allowlist がある場合、範囲外の IdP ホスト | ビルド時に `firewall.jwks.allowed_hosts` で拒否 | — |

**フレームワーク**:
- ビルド時バリデータ（`validateJwksUrl`）が `https://` 必須、userinfo / loopback / RFC1918 / リンクローカル / IPv4-mapped IPv6 を拒否し、任意で `firewall.jwks.allowed_hosts` メンバーシップを強制。
- ランタイムの `fetchJwks` が URL を再チェックし、3xx レスポンスを拒否。
- 運用推奨: 本番環境では `firewall.jwks.allowed_hosts` を必ず設定し IdP ホスト名を固定する。

---

### 10. HTTP Request Smuggling / Desync

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| クライアント由来の `Transfer-Encoding: chunked` による CloudFront/Worker ↔ Origin フレーミングのデシンク（CL.TE / TE.CL / H2.TE） | Origin 転送前に hop-by-hop ヘッダーを除去 | — |
| クライアント由来の `Connection`、`Upgrade`、`TE`、`Keep-Alive`、`Proxy-*`、`Trailer` | Origin 転送前に除去 | — |

**フレームワーク**: AWS origin-request Lambda と Cloudflare Worker の両方で、転送前に `transfer-encoding`、`connection`、`keep-alive`、`te`、`upgrade`、`proxy-connection`、`proxy-authenticate`、`proxy-authorization`、`trailer` を削除。CDN 自身がリクエストを再フレーム化するため、これらのヘッダーに正当なビューワー意図は存在しない。

### 11. 署名付き URL のリプレイ

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| `/download/a.pdf` の署名 URL が兄弟パス `/download/b.pdf` に再利用される | `exact_path: true` で 1 パスに束ねる | — |
| 1 本の署名 URL が TTL 内で繰り返し使われる | `nonce_param` で HMAC 入力にノンスを束ね、エッジが `X-Signed-URL-Nonce` を転送 | オリジンで単回利用を強制（例: Redis `SET NX`） |
| ノンスを書き換えて他セッションと衝突させる | ノンスは HMAC 入力 (`uri + exp + '|' + nonce`) に含まれ、改ざんで署名が失敗 | — |
| 書き込み系（POST/PUT/DELETE）を長寿命の署名 URL で保護 | `signed_url` が書き込み系プレフィックスに適用され、`nonce_param` 未設定のときはビルド時に警告 | — |

**フレームワーク**: 署名ルール、ノンス書式（16〜256 文字、URL セーフ unreserved）、オリジン側のパターンは `docs/signed-urls.ja.md` を参照。エッジは署名とノンス束縛を検証するが、単回利用はエッジ関数がステートレスであるためオリジン側との協調が必須。

### 12. 管理トークンのタイミングオラクル

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| トラフィックを観測できる攻撃者が、前方/後方不一致の応答時間差分から管理トークンをバイト単位で推測 | 入力長にかかわらず少なくとも 64 ポジションを走査する定時間比較。長さ不一致で短絡しない | — |
| `a.length !== b.length` の短絡により長さが漏えいする | 固定パッド走査 + 長さをアキュムレータに XOR | — |

**フレームワーク**: CloudFront Functions（`viewer-request.js`）と Cloudflare Workers（`index.ts`）の双方で、`static_token` と `basic_auth` は 64 ポジションパディングの定時間比較を使う。特性と制限は `docs/auth.ja.md` を参照。

### 13. 認証済みパスにおける共有キャッシュ汚染

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| 認証ゲート配下でオリジンがキャッシュ可能なレスポンスを返したとき、下流の共有キャッシュが利用者 A のレスポンスを利用者 B に返す | すべての auth-gate プレフィックスに対し `Cache-Control: no-store, no-cache, must-revalidate, private` と `Vary: Authorization, Cookie` を強制 | — |
| Cloudflare Worker 経路で `Set-Cookie` 属性を書き換える際に複数 Cookie レスポンスを壊す | `Headers#getSetCookie()` を使い、Cookie 単位で正規表現アンカー付きの属性判定をする | — |
| nonce 伝達手段がないためインライン `<script>` が `'unsafe-inline'` を要求する | per-response nonce（Cloudflare は `crypto.getRandomValues`、AWS は `Math.random`）を生成し、`'nonce-PLACEHOLDER'` を置換して `X-CSP-Nonce` で共有する | — |
| CSP を本番展開する前に違反を観測できず、リリースが止まる | `csp_report_only` により強制 CSP と並行して `Content-Security-Policy-Report-Only` を返す | — |

**フレームワーク**: `response_headers.force_vary_auth`（既定 on）が全 `auth_gate.match.path_prefixes` の和集合を `authProtectedPrefixes` にまとめ、ヒット時に no-store + Vary を強制する。CSP nonce、COOP/COEP/CORP、Reporting-Endpoints、Report-Only CSP はすべて `response_headers` から生成される。プラットフォーム上の制限とフィールド一覧: `docs/response-headers.ja.md`。

### 14. JWKS 障害 / キー回転の可用性

| 脅威 | Edge の責務 | WAF / Origin |
|------|-------------|--------------|
| IdP 障害により、エッジ isolate が再生成されるまで 100% 401 | Stale-if-error キャッシュ（`firewall.jwks.stale_if_error_sec`、既定 3600 秒）で直近の正常キーを返し続ける | — |
| 壊れた IdP をリクエスト毎に叩き続ける | Negative cache（`firewall.jwks.negative_cache_sec`、既定 60 秒）で失敗直後の再取得をスキップ | — |
| IdP 側でキー回転済みなのにエッジが旧 JWKS を使い続ける | `kid` ミス時に一度だけ無効化＋再取得 | — |

**フレームワーク**: AWS（`templates/aws/origin-request.js`）と Cloudflare（`templates/cloudflare/index.ts`）の両方で 3 ウィンドウすべてを実装済み。挙動マトリクスは `docs/auth.ja.md` を参照。

---

## 本フレームワークが対象としないもの

* **高度な Bot 挙動**（WAF / Bot Management）。
* **ボディに対する OWASP Top 10**（WAF / アプリケーション）。
* **レート制限**（WAF / API ゲートウェイ）。
* **DDoS**（CDN + Shield / WAF）。
* **内部 / DB 不正**（アプリケーション）。

Edge と WAF の切り分けは `decision-matrix.ja.md` を参照してください。

---

## OWASP マッピング（2026 ベースライン）

本フレームワークは、次の基準を参照して運用する前提です。

- **OWASP Top 10:2025**
- **OWASP API Security Top 10 (2023)**

実運用での解釈:

| OWASP 領域 | フレームワークの役割 | 補足 |
|------------|----------------------|------|
| 入力・リクエスト悪用 | Edge + WAF | メソッド/パス/クエリ/ヘッダーは Edge、深い検査は WAF/アプリ。 |
| 認証・セッション弱点 | Edge + Origin | Edge gate は粗い前段フィルタ。厳密な認証/認可はアプリ/Origin で実施。 |
| セキュリティ設定不備 | CI + policy | policy lint/build/runtime/unit/drift を CI で必須化。 |
| サプライチェーンリスク | CI + 依存管理 | lockfile を維持し、依存更新を監視し、生成物再現性を担保。 |
| API 悪用パターン | WAF + アプリ制御 | API スキーマ検証/レート制限は Edge 外で実施。 |
