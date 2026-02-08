# ロードマップ

このドキュメントは、Phase 3 完了後の作業を独立トラックとして管理するためのものです。

---

## Track A: Cloudflare Workers の JWT / 署名付き URL / Origin Auth

ステータス: 完了（2026-02-08）
優先度: 中

実装済み内容:

- `npx cdn-security build --target cloudflare` で JWT / 署名付き URL / origin auth 設定を注入可能にした。
- Worker テンプレートで JWT（`HS256` / `RS256`）・署名付き URL・origin custom header 認証を実装した。
- ランタイムテストに Cloudflare 認証の検証ケースを追加した。
- `SECURITY-FEATURE-MATRIX` と DOs/DON'Ts の記述を実装に合わせて更新した。

---

## Track B: コンパイラテストの深掘り

ステータス: 完了（2026-02-08）
優先度: 高

実装済み内容:

- auth/path ロジック向けのコンパイラ単体テスト。
- `build()` の生成出力を検証する単体テスト。
- JA3 を含む infra コンパイラ単体テスト。
- コミット済み golden 生成物との CI ドリフト検知。
