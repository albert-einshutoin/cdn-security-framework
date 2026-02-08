# ロードマップ

このドキュメントは、Phase 3 完了後の作業を独立トラックとして管理するためのものです。

---

## Track A: Cloudflare Workers の JWT / 署名付き URL / Origin Auth

ステータス: 計画中（別トラック）
優先度: 中

### スコープ

- Cloudflare Workers ランタイムに JWT auth gate（`RS256` / `HS256`）を追加。
- Cloudflare Workers ランタイムに署名付き URL 検証を追加。
- 可能な範囲で Lambda@Edge 相当の origin auth を設計・実装。

### 制約

- Workers の CPU / メモリ制約を満たす。
- リクエスト毎の重い JWKS 取得を避け、キャッシュ戦略を設計する。
- ポリシースキーマと Lambda@Edge の意味論との整合を維持する。

### 受け入れ条件

1. `npx cdn-security build --target cloudflare` の出力コードで、設定済み JWT / 署名付き URL gate を強制できる。
2. Cloudflare ターゲット向けランタイムテストに、JWT / 署名付き URL の成功・失敗ケースが追加される。
3. `SECURITY-FEATURE-MATRIX` の該当項目が `—` から `✓` に更新される。
4. 機能差分が残る場合、ドキュメントに明記される。

---

## Track B: コンパイラテストの深掘り

ステータス: 進行中
優先度: 高

- コア auth/path ロジック向けのコンパイラ単体テストを追加済み。
- 次段階として、生成出力の境界ケースとインフラコンパイラ補助関数のテストを追加する。
