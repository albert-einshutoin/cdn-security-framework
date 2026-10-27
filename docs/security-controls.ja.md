# PolicyのSecurity Controls

> **言語:** [English](./security-controls.md) · 日本語

[Quickstart](quickstart.ja.md)に従って導入したschema2候補を使う例です。別の空のconsumerディレクトリでlocal binaryを実行してください。artifactをコンパイルするだけで、deployは行いません。[認証の運用ノート](auth.ja.md)と[anomaly guard参照](request-anomaly-guards.ja.md)も併せて参照してください。

## Host・転送元IP・path・認証header名

次の完全なpolicyを`http-controls.yml`として保存します。

```yaml
version: 2
request:
  allow_methods: [GET, HEAD, OPTIONS]
  allowed_hosts: [API.example.test, '*.edge.example.test']
  trust_forwarded_for: false
  block:
    path_patterns:
      contains: ['/.env', '/../', '%2e%2e', '%2f..', '..%2f', '%5c']
      regex: ['^/internal(?:/|$)']
  anomaly_guards:
    enabled: true
    crlf: true
    malformed_cookie: true
    double_encoded_traversal: true
    max_cookie_bytes: 4096
    max_cookie_pairs: 80
response_headers: {}
routes:
  - name: admin
    match: { path_prefixes: ['/admin'] }
    auth_gate:
      type: static_token
      header: X-Admin-Token
      token_env: EDGE_ADMIN_TOKEN
```

```bash
EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy node node_modules/cdn-security-framework/scripts/policy-lint.js http-controls.yml
EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy ./node_modules/.bin/cdn-security build -p http-controls.yml --target aws --out-dir out-http-aws
EDGE_ADMIN_TOKEN=docs-fixture-token-not-for-deploy ./node_modules/.bin/cdn-security build -p http-controls.yml --target cloudflare --out-dir out-http-cf
```

ここでのtokenは公開された合成fixtureで、本番認証情報として使えません。buildはWorkerの実行時secretを登録しないため、deploy時には対応するsecret bindingを別途設定する必要があります。

| 設定 | 動作と注意点 |
| --- | --- |
| `request.allowed_hosts` | 完全一致と`*.`接尾辞wildcardを大文字小文字を区別せず照合します。受信Hostのport部分は無視され、`API.example.test:8443`も一致するためport制限にはなりません。`*.edge.example.test`はsubdomainに一致し、`edge.example.test`自体には一致しません。enforce時の不一致は400です。省略・空配列ではHost allowlistは無効で、DNS/TLSの所有確認にはなりません。 |
| `request.trust_forwarded_for` | 既定は`false`で、origin転送前に受信`x-forwarded-for`を削除します。管理下の上流proxyがheaderを除去・置換し、clientがproxyを迂回できないingressを確保した場合だけ`true`にします。この設定自体はproxyの認証をせず、clientが送ったIPを信頼可能にはしません。偽装値はoriginのIP判定や監査データを汚染します。 |
| `request.block.path_patterns` | typed objectの`contains`にliteralな部分文字列、`regex`にbuild時にコンパイルするJavaScript RegExp sourceを書きます。globではありません。空でないcustom listは組み込みpath-patternの既定値を置き換えるため、この例は既定のtraversal用literalを残しています。単純で処理量を抑えた式を使ってください。不正な式と`(a+)+`等の検出できた入れ子quantifier形状は拒否されます。すべてのregex性能問題を解析するものではありません。edge runtimeの制御であり、provider WAFでも同じ式を実行するという保証ではありません。 |
| `routes[].auth_gate.header` | `static_token`では、`X-Admin-Token`とHTTP上の`x-admin-token`は同じheaderです。AWSは設定されたlookup名を正規化し、Workersは大文字小文字を区別しないHeaders APIを使います。認証情報の値を小文字にする処理ではありません。Basic/JWTは`Authorization`を使い、必要な`Basic ` / `Bearer ` prefixや認証情報のbyte列まで大文字小文字を無視する設定にはなりません。 |

上記のpass/block動作にはenforce modeを使います。monitor modeは本来blockするrequestを転送し得るため、同じ防御にはなりません。

## JWT verifierと時刻許容幅（Cloudflare）

`jwt-controls.yml`として保存します。

```yaml
version: 2
request:
  allow_methods: [GET]
response_headers: {}
routes:
  - name: api
    match: { path_prefixes: ['/api'] }
    auth_gate:
      type: jwt
      algorithm: HS256
      allowed_algorithms: [HS256]
      clock_skew_sec: 30
      secret_env: EDGE_JWT_SECRET
      issuer: https://idp.example.test
      audience: example-api
```

```bash
EDGE_JWT_SECRET=docs-fixture-secret-not-for-deploy node node_modules/cdn-security-framework/scripts/policy-lint.js jwt-controls.yml
EDGE_JWT_SECRET=docs-fixture-secret-not-for-deploy ./node_modules/.bin/cdn-security build -p jwt-controls.yml --target cloudflare --out-dir out-jwt
```

- `auth_gate.clock_skew_sec`は`exp`・`nbf`判定の時計差を許容します。既定30秒で、policy入力は0〜600の整数です。幅を増やすと時刻境界付近の受入範囲が広がります。issuer・audience・署名の誤りを解消するものではありません。
- `auth_gate.allowed_algorithms`の既定はgateの`algorithm`です。JWT headerの`alg`を制限し、別verifierを選ぶ機能ではありません。例えば`algorithm: RS256`と`allowed_algorithms: [HS256]`の組合せはbuild時に失敗します。鍵のrotation目的でHMACと公開鍵方式を混在させないでください。`none`は拒否され、別algorithmや`none`の追加で代替検証経路が有効になることはありません。
- この例はCloudflare専用です。AWSは、旧origin-request検証がcache hit時に省略される問題によりJWT・signed URL gateをbuild時に拒否します。AWS buildを通すために認証を外さず、[移行手順](auth.ja.md)に従ってください。
- 公開した合成secretはlocalコンパイル専用です。本番runtime secretは別途設定します。コンパイル成功はtoken検証やdeployの証拠ではありません。RS256ではさらに`firewall.jwks.allowed_hosts`の固定と[JWKSの制約](auth.ja.md)が必要です。

## Raw anomaly check

`http-controls.yml`の`anomaly_guards` blockは既存の正規化前チェックを有効にします。`enabled: true`でなければ無効で、有効時の個別チェックは既定trueです。enforce時は次を検査します。

- `crlf`はURI・query・header値の生CR/LFと`%0d` / `%0a` indicatorを拒否します。CloudFrontのquery objectの値やheaderの`multiValue`要素も対象です。
- `double_encoded_traversal`は`%252e%252e`等の二重encode indicatorを制限付きで検出します。`%25`がある場合だけ最大1回の追加decodeを行います。
- `malformed_cookie`はdelimiter構造・制御文字・size/pair上限を検査します。CloudFrontのcookie mapも平坦化前に対象とします。上限の既定は4096 byte・80 pairです。

対象はCDN eventやFetch Headers APIがframeworkへ実際に渡したデータです。clientやCDNが既に正規化したbyte列を復元せず、広範なSQLi/XSS scanや配備済みWAFの実効防御を証明しません。CloudFront viewer-requestとWorkersに対応し、Lambda@Edge origin-requestでは同じ検査を重複実装しません。[runtimeの詳細とrollout](request-anomaly-guards.ja.md)も確認してください。
