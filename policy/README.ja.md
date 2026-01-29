# ポリシー

このディレクトリには、**セキュリティポリシー**（正）と、`base.yml` にコピーして使う **プロファイル** を置きます。

---

## ファイル

| ファイル | 役割 |
|----------|------|
| `base.yml` | 有効なポリシー。これを編集するか、プロファイルで上書きする（下記参照）。 |
| `profiles/balanced.yml` | デフォルト。セキュリティと互換性のバランス。 |
| `profiles/strict.yml` | 制限を強め、ブロックを増やす。クライアントを制御できる場合向け。 |
| `profiles/permissive.yml` | 制限を緩め、ブロックを減らす。API・スクリプト・レガシークライアント向け。 |

---

## プロファイルの選び方

| プロファイル | 使いどころ |
|--------------|------------|
| **balanced** | デフォルト。多くのサイト・API（ブラウザ＋一般的なクライアント）に適している。 |
| **strict** | エッジで最大限のセキュリティ。クエリ/URI 制限を厳しく、UA ブロックを増やす（curl/wget 等）、パスパターン・CSP を厳格に。汎用スクリプトやレガシークライアントを許可しない場合向け。 |
| **permissive** | ブロックを減らし、制限を緩める。API や、User-Agent を付けないクライアント、PUT/DELETE/OPTIONS を使う場合向け。 |

選んだら、そのプロファイルを `base.yml` にコピーします。

```bash
cp policy/profiles/balanced.yml policy/base.yml
# または
cp policy/profiles/strict.yml policy/base.yml
cp policy/profiles/permissive.yml policy/base.yml
```

その後、**ランタイムを手動で同期**してください（[ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md) 参照）。デプロイ前にポリシー Lint を実行することを推奨します。

```bash
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

## 関連

* [ポリシーとランタイムの同期](../docs/policy-runtime-sync.ja.md) — ポリシーとランタイムの同期方法。
* [アーキテクチャ](../docs/architecture.ja.md) — ポリシー駆動の設計。
