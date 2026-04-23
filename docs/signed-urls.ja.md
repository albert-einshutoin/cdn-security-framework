# 署名付き URL のハードニング

## 目的

`signed_url` 認証ゲートは HMAC-SHA256 署名で URL と期限を束ねて、保護リソースへの一時的アクセスを与える。追加の制約がなければ、同じプレフィックス配下の別パスで再利用されたり、有効期限まで何度もリプレイされたりする余地が残る。本ドキュメントでは、フレームワーク側の 2 つの緩和策を整理する。

- **`exact_path`** — 署名を 1 つのパスだけに束ねる（既定はゲートプレフィックス配下のパス全体にマッチ）。
- **`nonce_param`** — HMAC 入力にリクエスト毎のノンスを組み込み、エッジ → オリジンへワンタイム識別子を転送する。

## 脅威モデル

| 攻撃 | 緩和策 |
|---|---|
| 同じ署名鍵とプレフィックスを共有する `/download/a.pdf` の署名 URL が、兄弟パス `/download/b.pdf` に再利用される | `exact_path: true` |
| 漏洩・ブラウザ戻るなどで 1 本の署名 URL が複数クライアントから使われる | `nonce_param` + オリジン側の単回利用ストア（エッジ単体ではワンタイム化できない） |
| 署名 URL のノンスを書き換えて他ユーザのセッションを乗っ取る | ノンスは HMAC 入力 (`uri + exp + '|' + nonce`) に含まれるため、書き換えると署名が壊れて失敗 |

## ポリシー設定

```yaml
routes:
  - name: one-time-download
    match:
      path_prefixes: ["/download/"]
    auth_gate:
      type: signed_url
      algorithm: HMAC-SHA256
      secret_env: URL_SIGNING_SECRET
      expires_param: exp
      signature_param: sig
      exact_path: true        # 署名を 1 パスに束ねる
      nonce_param: nonce      # URL ごとのノンスをオリジンへ X-Signed-URL-Nonce で転送
```

- `exact_path` の既定は `false`（従来のプレフィックス一致）。
- `nonce_param` の既定は `""`（ノンスなし。署名対象は `uri + exp` のみ）。
- `exact_path` と `nonce_param` は独立しており、片方だけでも有効。

## 署名ルール

HMAC 入力は以下の通り。

```
signData = uri + exp + ( nonce ? '|' + nonce : '' )
signature = HMAC-SHA256-Hex(secret, signData)
```

`nonce_param` が設定されているときだけノンスを連結する。ノンス無しで発行済みの既存 URL は従来どおり通過する。

### ノンス書式

エッジランタイムはノンスの書式を厳格に検証し、単回利用ストアや下流ログへの任意文字列注入を防ぐ。

- 長さ: 16〜256 文字
- 使用可能文字: `A-Z a-z 0-9 . _ ~ -`（URL セーフ unreserved 文字）

書式不正は署名検証前に `403 Malformed nonce` で拒否する。

## オリジン側での単回利用の強制

エッジは署名を検証し、設定があればノンスを `X-Signed-URL-Nonce` ヘッダとしてオリジンへ転送する。エッジは単回利用を保証できない（CloudFront Functions / Worker の呼び出しはステートレス）。オリジン側で原子的な単回利用を実装する必要がある。

```ts
// オリジンエンドポイントの擬似コード
const nonce = req.headers['x-signed-url-nonce'];
if (!nonce) return reject(403, 'Nonce required');

// 署名 URL の有効期限より長い TTL で Redis SET NX
const acquired = await redis.set(`nonce:${nonce}`, '1', 'EX', 3600, 'NX');
if (!acquired) return reject(409, 'URL already used');
```

TTL は署名 URL の最大有効期限以上を指定する。

## 書き込み系パスでノンスが未設定な場合の警告

`signed_url` ゲートが書き込み系の匂いを含むプレフィックス (`/api/`, `/write`, `/admin`, `/upload`, `/delete`) を保護しているのに `nonce_param` が未設定のとき、コンパイラは非致死の警告を出す。

```
[WARN] Route "admin-upload" uses signed_url on a write-like path ("/admin/upload") without nonce_param.
       Signed URLs can be replayed on write endpoints. Set nonce_param and enforce single-use at origin.
```

対応策は `nonce_param` を設定するか、JWT や静的トークンなど別の認証ゲートへ切り替えること。

## ランタイム挙動のまとめ

| 入力 | エッジのレスポンス |
|---|---|
| 署名 OK + ノンス OK + パス一致 | 200（通過、`X-Signed-URL-Nonce` をオリジンへ転送） |
| 署名 OK、ノンス未設定（ポリシーも未設定） | 200（通過） |
| `nonce_param` 設定ありでノンス欠落 | 403 Missing nonce |
| ノンスの長さ/文字種が不正 | 403 Malformed nonce |
| 署名不一致（ノンス改ざん含む） | 403 Invalid signature |
| `exact_path: true` でゲートプレフィックスとパスが異なる | ゲート非適用 → 通常ルーティング |
| 期限切れ（`exp < now`） | 403 URL expired |

## 関連ドキュメント

- 脅威モデル: `docs/threat-model.ja.md` §5（Auth Gate）
- ポリシースキーマ: `policy/schema.json` — `routes[].auth_gate`
- ランタイム参照実装: `runtimes/aws/origin-request.js`, `runtimes/cloudflare/index.ts`
