# AWS CloudFront Functions Runtime

このディレクトリは CloudFront Functions で使う **Viewer Request / Viewer Response** のランタイムです。

## 何を守る？
- 入口で「攻撃面を削る」（不要メソッド / traversal / 異常UA / 過剰クエリ）
- クエリ正規化（utm 等を落としてキャッシュキー汚染を防ぐ）
- セキュリティヘッダーをCDNで強制（複数オリジンでも統一）

## どこにアタッチする？
- `viewer-request.js` → **Viewer Request**
- `viewer-response.js` → **Viewer Response**

## 設定（最小）
### 1) admin token
`viewer-request.js` の以下を置換してください。

- `CFG.adminGate.token = "REPLACE_ME_WITH_EDGE_ADMIN_TOKEN"`

> CloudFront Functions は外部シークレット参照が前提になりにくいので、まずは「ビルド時差し込み」で運用するのが安全です。
> 後で compiler を入れると `policy/base.yml` から自動生成できます。

## 動作確認（例）
### admin gate
```bash
curl -i https://YOUR_DOMAIN/admin
curl -i -H "x-edge-token: REPLACE_ME_WITH_EDGE_ADMIN_TOKEN" https://YOUR_DOMAIN/admin
```

query normalize
curl -i "https://YOUR_DOMAIN/?utm_source=x&foo=1"
何が他にできる？
/api/* 用に別 Behavior を作り、allowMethods を拡張する（PUT/DELETE等）

露骨な攻撃だけ Functions で落とし、レート制限やOWASPは AWS WAF へ


---