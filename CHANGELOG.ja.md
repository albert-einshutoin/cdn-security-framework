# 変更履歴

このプロジェクトの主な変更をこのファイルに記録します。

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に基づき、
バージョン付け後は [Semantic Versioning](https://semver.org/lang/ja/) に従います。

---

## [Unreleased]

## [1.1.0] - 2026-04-23

### セキュリティ / 破壊的変更

- `request.block.path_patterns` を型付け: 従来のリテラル文字列配列（レガシー互換）に加え、`contains:` / `regex:` を持つオブジェクト形式を正式サポート。配列中に正規表現らしきエントリが混入した場合は、substring マッチへの暗黙フォールバックをせずビルド失敗とする。`strict` プロファイルはオブジェクト形式に移行済み。
- `static_token` / `basic_auth` ゲートはビルド時に対応する環境変数を必須化した。従来の `BUILD_TIME_INJECTION` サイレントフォールバックは廃止。環境変数未設定のままビルドすると失敗し、`--allow-placeholder-token` 指定時のみ `INSECURE_PLACEHOLDER__REBUILD_WITH_REAL_TOKEN` を明示的に埋め込み、警告を出力する。
- CloudFront Functions / Cloudflare Workers の `static_token` および `basic_auth` 照合を constant-time 比較に置き換え、タイミング攻撃耐性を確保。
- レガシーの `CFG.adminGate` 二重評価経路を削除。認証は `CFG.authGates` に一本化。
- `policy-lint` は `policy/schema.json` を ajv で強制するようになり、従来のクロスフィールド検証（JWT / 署名付き URL など）と併用する。
- **edge-auth マーカーのスプーフィング対策**: AWS CloudFront Functions ハンドラおよび Cloudflare Workers ハンドラの双方で、クライアントから送られてきた `x-edge-authenticated` ヘッダをリクエスト入口 / オリジン転送前に必ず剥ぎ取るようにした。従来はクライアントが未認証リクエストにこのヘッダを付与するだけで、下流が認証済みと誤認する余地があった。
- **`path_patterns.contains` の大文字小文字正規化**: `contains` エントリをビルド時に小文字化するようにした。ランタイム側は URI を `toLowerCase()` してから `includes()` で比較するため、ポリシーに `%2E%2E` のような大文字エントリを書いても絶対にマッチしない silent downgrade が発生していた。regex 拒否と同種の silent-downgrade を両形式で塞ぐ。
- **`auth_gate.header` の小文字化**: CloudFront Functions ではヘッダキーが小文字でしか見えないため、生成コードの `tokenHeaderName` を強制的に小文字化する。ポリシーで `header: X-Edge-Token` と書かれていた場合、従来は `req.headers[...]` のルックアップが常に undefined となり、正規リクエストまで拒否される不具合があった。
- **JWT alg 混同攻撃対策**: `verifyJwtRS256` / `verifyJwtHS256`（AWS）および `verifyJwt`（Cloudflare）は、署名検証を走らせる前に JWT の `header.alg` をゲートごとのホワイトリストと照合するようにした。`alg=none` は常に拒否し、デフォルトではそのゲートに設定された `algorithm` のみを受け付ける。`auth_gate.allowed_algorithms: [...]` は、すべてのエントリが `auth_gate.algorithm` で選ばれる単一の verifier と一致する場合のみ受け付ける。`algorithm: RS256` + `allowed_algorithms: ["HS256"]` のように verifier が検証できないアルゴリズムを混ぜるとビルドを明示的にエラーで落とす（silent に誤った verifier に流れて全リクエストが認証失敗する事故を防ぐ）。従来は偽造された `alg=none` や、RS256 → HS256 への alg 差し替え（公開鍵を HMAC 秘密鍵として扱わせるクラシックな攻撃）で署名検証を迂回できる余地があった。
- **JWT clock skew 許容幅**: `exp` / `nbf` チェックで許容する時刻ずれを `auth_gate.clock_skew_sec` で設定可能にした（デフォルト 30 秒、0〜600 秒にクランプ）。従来は数秒のずれで有効トークンが境界上で弾かれる余地があった。
- **X-Forwarded-For スプーフィング対策**: CloudFront Functions、Lambda@Edge origin-request、Cloudflare Workers のいずれも、クライアント由来の `x-forwarded-for` ヘッダをデフォルトで剥ぎ取るようにした。実際のクライアント IP は CDN が付与するヘッダ（`cloudfront-viewer-address` / `cf-connecting-ip`）から取得できるため、入力値を信頼すると下流のレートリミット、IP allowlist、監査ログを汚染される。信頼できるリバースプロキシ配下で運用する場合は `request.trust_forwarded_for: true` で明示的にオプトインする。
- **Host ヘッダ allowlist（オプション）**: `request.allowed_hosts: [...]` により、エッジで Host ヘッダの allowlist を強制できる。完全一致および `*.example.com` の wildcard prefix をサポートし、大文字小文字を区別せず、ポート番号は無視する。未設定時は従来通り Host をチェックしない。

### 追加

- Edge と WAF の切り分けのための脅威モデル（`docs/threat-model.md`）と判断マトリクス（`docs/decision-matrix.md`）。
- ポリシープロファイル `policy/profiles/balanced.yml`。クイックスタートでは `cp policy/profiles/balanced.yml policy/base.yml` を使用。
- デプロイ例: `examples/aws-cloudfront/`, `examples/cloudflare/` と README（英語 + 日本語）。
- CONTRIBUTING.md, CODE_OF_CONDUCT.md、および `.github` の Issue/PR テンプレート。
- OSS 公開準備の監査: `docs/OSS-READINESS-AUDIT.ja.md`（日本語）。
- Lambda@Edge origin-request のランタイム対応を追加（JWT 認証: RS256/HS256、署名付き URL 検証、origin auth 注入）。
- `scripts/compile.js` の主要ロジック（`parsePathPatterns`, `regexesLiteralCode`, `getAuthGates`, `validateAuthGates`）に単体テストを追加。
- Cloudflare Workers で JWT（`HS256`/`RS256`）・署名付き URL・origin custom header 認証をポリシー生成で利用可能にした。
- コミット済み golden 生成物（`tests/golden/base/*`）とのドリフト検知（`npm run test:drift`）を追加し、CI に統合。
- `firewall.waf.ja3_fingerprints` から JA3 フィンガープリント WAF ブロックルールを生成する機能を追加。
- `firewall.waf.ja4_fingerprints` と `firewall.waf.fingerprint_action`（`count`/`block`）による JA4 対応と段階導入モードを追加。
- `scripts/fingerprint-candidates.js` を追加（WAF JSONL ログから JA3/JA4 候補を抽出）。
- `scripts/security-baseline-check.js` を追加し、`npm run test:security-baseline` として CI に統合。

### 変更

- README のリポジトリ構成を実態に合わせて更新（`base.yml`, `profiles/`, `docs/quickstart.md`, `examples/`）。
- クイックスタートの手順を既存パスに統一: `policy/base.yml`, `policy/profiles/balanced.yml`、デプロイは `runtimes/` または `examples/` を参照。
- 全ランタイムのコード・コメント（CloudFront Functions, Lambda@Edge, Cloudflare Workers）を英語に統一。
- ポリシー `policy/base.yml` のコメントおよび `.ja` ファイル: `.ja` ファイルにのみ日本語；それ以外のファイルとコードは英語のみ。
- CI の品質ゲートにコンパイラ単体テストを追加（policy lint / build / runtime test に加えて実行）。
- ランタイムテストに Cloudflare ターゲット検証を追加し、CI ゲートを runtime + unit + drift に拡張。

### 修正

- README から存在しないファイル（`base.yaml`, `threat-model.md`, `decision-matrix.md`、空の `examples/`）への参照を削除・修正。
- `package.json` のリポジトリ情報（`repository`, `homepage`, `bugs`）を実際の GitHub リポジトリに修正。

---

## [0.1.0] – 初回（テンプレート）

- CloudFront Functions: Viewer Request / Viewer Response。
- Lambda@Edge: Origin Request（テンプレート；JWT/署名は TODO）。
- Cloudflare Workers: 入口遮断・正規化・ヘッダー付与の fetch ハンドラ。
- ポリシー: `policy/base.yml`（人間が読める形式；コンパイラ導入まではランタイムは手動同期）。
- ドキュメント: README, architecture, quick start（英語 + 日本語）；SECURITY（英語 + 日本語）。

---

[Unreleased]: https://github.com/albert-einshutoin/cdn-security-framework/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/albert-einshutoin/cdn-security-framework/compare/v1.0.0...v1.1.0
[0.1.0]: https://github.com/albert-einshutoin/cdn-security-framework/releases/tag/v0.1.0
