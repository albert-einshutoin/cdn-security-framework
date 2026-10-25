# Auth Gates — 運用ノート

4 種類の認証ゲート（`static_token`、`basic_auth`、`jwt`、`signed_url`）のランタイム挙動を、キャッシュライフサイクルとタイミングオラクル耐性を中心にまとめる。


## AWSの認証対応範囲と移行

AWSでは `jwt` / `signed_url` のbuildを拒否します。monitor modeや
`--allow-placeholder-token` でも回避できません。origin-requestでの検証は
CloudFrontのキャッシュヒット時には実行されません。viewer-responseの
`no-store` / `Vary` ではCloudFront内部のキャッシュを無効にできず、最小TTLが正の
cache policyはoriginの `no-store` より優先される場合もあります。このcompilerは
配信のcache behaviorを管理・検証しないため、利用者の自己申告では安全性を保証できません。

これらのゲートにはCloudflare Workersを使用するか、旧ゲートを外す前に、各viewer
requestを認証する独立した仕組みへ移行してください。移行中は保護対象へのアクセスを
遮断し、配信設定の修正後に過去の保護対象キャッシュを無効化します。再buildだけでは
既存の配信は修復されません。buildを通すためだけに認証を削除しないでください。
AWSの `static_token` / `basic_auth` は引き続きキャッシュ参照前に認証し、originへの
アクセス制御用認証ヘッダーも利用できます。

次期2.0向けの破壊的な制限です。この修正ではpackage/schema versionを変更しません。
AWSのJWT/署名URL対応を再開するには、viewerごとの認証と配信設定を検証できる契約が
必要です。回避flagはありません。AWS生成テンプレートからJWT/JWKSと署名URLの実装を削除しました。
以下のJWT/JWKSの説明はCloudflare Workersを対象とします。

根拠: [AWSのtrigger順序](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-cloudfront-trigger-events.html)、
[cache policy](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-cache-policies.html)。

## AWS monitorの応答pathが解析不能な場合

`defaults.mode: monitor`では、有界の正規化モデルで解釈できないpathも元の要求のまま
originへ届く場合があります。認証保護prefixが設定されていないとき、応答関数はoriginのstatusと内容、global headerとbaseline
CSPを維持し、route固有のadmin判定と`Clear-Site-Data`を省略します。
選択したJSON/textログで`response_path_unknown`を記録し、この診断へraw path、body、
資格情報を追加しません。

path固有の応答制御が不明なため、`force_vary_auth`が無効でも`no-store`、`Pragma: no-cache`、
`Vary: Authorization, Cookie`を付けます。enforce、または認証保護prefixが1つでもある場合は
応答path解析不能のErrorを維持します。この挙動を使うために必要な認証ゲートを削除しないでください。
これらのviewer向けheaderはCloudFront内部cacheの検証・無効化を意味しません。
ローカルの生成関数チェックは実CloudFront配備の証拠ではありません。

## 管理トークン / Basic 認証の比較

`static_token` と `basic_auth` は、CloudFront Functions と Cloudflare Workers の両方で定時間比較を実装している。

特性:
- 認証情報の長さにかかわらず少なくとも 64 ポジションを走査する。短いトークン（よくあるケース）は常に同じ時間で比較できる
- 64 文字を超えるトークンは、反復回数が `max(|a|, |b|)` に比例する（Go の `hmac.Equal` と同じ挙動）
- 長さ不一致で短絡しない。長さはアキュムレータに含める
- 両プラットフォームで同一挙動

これにより、脅威モデル §12 に記した管理プレフィックスのバイト単位タイミングオラクルを封じる。

## JWKS キャッシュのライフサイクル

`algorithm: RS256` の `jwt` ゲートは `jwks_url` から JWKS を取得する。3 つのキャッシュウィンドウを保持する。

| ウィンドウ | デフォルト | 範囲 | 意味 |
|---|---|---|---|
| Fresh（フレッシュ） | `cache_ttl_sec`（Cloudflare） | — | フェッチせずキャッシュを返す |
| Stale-if-error（障害時スタレ） | 3600 秒 | 0..86400 | リフレッシュ失敗時、直近の正常キーを返し続ける |
| Negative cache（陰性キャッシュ） | 60 秒 | 0..600 | リフレッシュ失敗時、このウィンドウ内は再取得しない |

`firewall.jwks` でグローバルに設定する。

```yaml
firewall:
  jwks:
    allowed_hosts:
      - idp.example.com
    stale_if_error_sec: 3600
    negative_cache_sec: 60
```

Cloudflare Workers 向け build では、RS256 JWT ゲートがある場合
`firewall.jwks.allowed_hosts` が必須。Workers は `fetch` 前に DNS
解決先を検査できないため、コンパイラが JWKS ホストを build 時に固定する。

JWKS レスポンスは parse / cache の前に 256 KiB、100 keys で上限をかける。
RS256 では Cloudflare Workers runtime が `kid` 一致、`kty: RSA` 必須、かつ JWK の
`alg` が省略または `RS256` の key を選択する。矛盾する `alg` を持つ
JWK は無視する。受け入れる token algorithm の権威は JWT header の
algorithm allowlist のまま。

### 挙動マトリクス

| 状態 | ネットワーク呼び出し | 結果 |
|---|---|---|
| Fresh キャッシュヒット | なし | キャッシュのキーを返す |
| Fresh 期限切れ + IdP 正常 | あり | リフレッシュ後、新しいキーを返す |
| Fresh 期限切れ + IdP 失敗 + stale-if-error 内 | あり（1 回） | スタレなキャッシュキーを返す。警告ログ |
| Fresh 期限切れ + IdP 失敗 + stale-if-error 外 | あり（1 回） | JWT 検証を拒否 |
| 陰性キャッシュ内 + スタレ利用可 | なし | スタレなキャッシュキーを返す。フェッチスキップ |
| 陰性キャッシュ内 + キャッシュなし | なし | JWT 検証を拒否 |
| `kid` がキャッシュに無い | endpointの取得枠がある場合 | キャッシュを消さず再取得。取得枠がなければ未知鍵を拒否 |

### 運用上の含意

- **IdP 障害時**でも、障害前の `stale_if_error_sec` 内で検証済みのトークンがあり、isolate / コンテナがキャッシュを保持していれば、100% 401 は回避できる。
- **取得上限:** 設定済みJWKS URLごと、Worker isolateごとに固定5秒窓で最大2回。初回取得と失敗も数え、cold・期限切れ・強制更新の同時取得を共有する。未知kidの状態は保持せず、拒否された要求で窓を先送りしない。
- **キー回転:** endpointが正常で要求と処理が継続する場合、新鍵の認識まで最大5秒＋fetch/bodyの2秒期限を要する。redirectは`manual`で追従せず、すべての非2xxを拒否する。
- **壊れたIdP:** `negative_cache_sec`も再試行を抑制する。復旧後はこのTTLと固定取得枠の両方が許す時点で再取得できる。stale鍵は実際の取得失敗があり、最後の成功取得から`cache_ttl_sec + stale_if_error_sec`内の場合のみ利用できる。取得枠の使い切りだけでは期限切れ鍵を許可しない。gate TTLが5秒未満の場合、2回の取得枠を使うと一時的に認証を拒否する場合がある。

### カバレッジの限界

- エッジ関数は最悪ケースで呼び出し単位のステートレスになる（新コールドスタート、isolate 再生成）。キャッシュヒット率はトラフィック量と CDN アフィニティ依存。
- 陰性キャッシュは isolate / コンテナごと。障害中に 2 つの isolate が IdP を 1 度ずつ叩く可能性がある。この保護は best-effort。

## 署名付き URL ゲート

`exact_path`、`nonce_param`、オリジン側単回利用強制の詳細は `docs/signed-urls.ja.md` を参照。
