# ポリシースキーマ移行ガイド

> **言語:** [English](./schema-migration.md) · 日本語

本ドキュメントは、`policy/schema.json` がバージョン間でどのように進化するか、そして利用者がポリシーをどのように移行するかを定義します。

---

## 現在のバージョン：`1`

すべてのポリシーファイルは先頭で `version: 1` を宣言する必要があります。それ以外の値は lint 時点で拒否されます。

---

## スキーマの SemVer 契約

`policy.version` は **npm パッケージバージョンとは別物**です。両者は独立して進化します。

- **追加的変更**（新しい任意キー、新しい enum 値）: **minor** リリースで公開。`version: 1` は引き続き lint・ビルドが通ります。
- **破壊的変更**（キー改名、フィールド削除、既存ポリシーを拒否し得るバリデータ強化）: スキーマを `version: 2` に上げ、**major** リリースで公開。

スキーマ bump と npm の major bump は同時にリリースされます。

### 破壊的変更の範囲

| 変更 | 破壊的？ |
| --- | --- |
| 任意の新キー追加 | No |
| enum に新しい値を追加 | No |
| 既存バリデータを厳格化（例：max を下げる）し、過去に有効だった値が拒否される | **Yes** |
| キー改名 | **Yes** |
| キー削除 | **Yes** |
| 既存キーの意味を変更 | **Yes** |

---

## 非推奨ウィンドウ

キーを削除予定にする場合：

1. 代替キーを導入するリリースで `lint:policy` の **warning**（error ではない）として非推奨キーと代替キーを通知。
2. 非推奨警告は破壊的変更の前に**最低 1 つの minor リリース**は残します。
3. 破壊的変更は次の major リリースで、`version: 2` スキーマおよび CLI への登録済みマイグレーションと一緒に公開します（下記）。

---

## `migrate` CLI

```bash
npx cdn-security migrate --policy policy/security.yml --to 2
```

- 現在とターゲットのスキーマバージョンを表示。
- 登録済みのマイグレーションがあれば、メモリ上（`--write` 指定時はファイル上）でポリシーを書き換え。
- 登録済みマイグレーションが無ければ非 0 終了し、本ドキュメントを参照するよう誘導。

現在（v1 のみ）の出力：

```
[INFO] Current schema version: 1
[INFO] Target schema version:  1
[OK] Already at target version — no migration needed.
```

### マイグレーション作者向け契約

各マイグレーションは `bin/cli.js` に登録された純粋関数 `(v_n policy) → (v_n+1 policy)` です。連鎖は自動で、v1 ポリシーに `--to 3` を指定すれば `v1→v2` → `v2→v3` が順に走ります。

マイグレーションは：
- ユーザー設定を失わないこと。非推奨キーは黙って捨てず、翻訳すること。
- 適用した変換ごとに 1 行のサマリを出すこと。差分レビューが簡単になります。
- `scripts/compile-unit-tests.js` に対応する単体テストケースを必ず追加すること。

---

## 仮想例：v1 → v2 マイグレーション

将来のリリースで、`request.block.ua_contains` を `request.block.user_agent.contains` に改名し、メソッド許可を `request.methods.allow` に移したとします。

### v1 入力

```yaml
version: 1
request:
  allow_methods: [GET, HEAD]
  block:
    ua_contains: [sqlmap, nikto]
```

### v2 出力

```yaml
version: 2
request:
  methods:
    allow: [GET, HEAD]
  block:
    user_agent:
      contains: [sqlmap, nikto]
```

### マイグレーションの実行

```bash
npx cdn-security migrate --policy policy/security.yml --to 2 --write
```

期待されるログ：

```
[INFO] Policy: policy/security.yml
[INFO] Current schema version: 1
[INFO] Target schema version:  2
[MIGRATE v1→v2] Renamed request.allow_methods → request.methods.allow
[MIGRATE v1→v2] Renamed request.block.ua_contains → request.block.user_agent.contains
[SUCCESS] Wrote migrated policy to policy/security.yml
```

---

## ロールバック

v2 ポリシーが本番でリグレッションを起こした場合：

1. npm 依存を直前の v1 対応 major バージョンへピン留め。
2. git からマイグレーション前のポリシーを復元（オリジナルが真実の source）。
3. Issue を起票。情報を欠落させるマイグレーションは bug です。

---

## リリース連動

- スキーマファイル：`policy/schema.json`
- CLI バリデータ：`scripts/policy-lint.js`
- マイグレーションレジストリ：`bin/cli.js` の `migrate` コマンド
- リリースノート：`CHANGELOG.md`

スキーマバージョンを上げる際は、この 4 つを同時に更新します。
