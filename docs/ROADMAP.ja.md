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

---

## Track C: Issue と実装状況の整合

ステータス: 完了（2026-06-11）
優先度: 中

実装実績の整合:

- #128 はローカルのランタイムプレイグラウンドとして実装済みで、CLI と docs、テストに反映済み。
- #103 と #105 は `docs/SECURITY-FEATURE-MATRIX.md` で実装済みとして明記され、サポート範囲と target 制約（未対応/部分対応）を記録済み。
- 未解決チケットとして残ることで発生する重複作業を避けるため、Issue トラッカーを実装実績に合わせて更新する。

---

## Track D: 運用ハードニングと観測性（進行中）

ステータス: 進行中（2026-06-11）
優先度: 高

進行中作業:

- monitor モードのシグナル品質と可視性の改善（`cdn-security capabilities` と運用手順）。
- 配置監査時の false positive 切り分けガイダンスの整備。
- 複数サービス展開を想定した運用 runbook 拡充。

---

## Track E: マルチ CDNs の整合性（進行中）

ステータス: 進行中（2026-06-11）
優先度: 中

進行中作業:

- Cloudflare / AWS の差分を継続的に追跡し、警告仕様の一貫性を高める。
- 未対応 target / target 固有フォールバックの検証を強化する。

---

## Track F: 今後の実装トラック

ステータス: 計画中
優先度: 中

- dual-secret 認証ローテーションモデル。
- 大規模組織向けに安全性を担保したオーバーレイ（継承）対応。
- monitor→enforce へ移行判断を支援する、ログベースの検証支援。

---

## Track G: 戦略的調査

ステータス: 調査
優先度: 低

- Rust/WASM コンパイラ化の実現可能性（ベンチ、配布、開発体験）。
- 追加 CDN target のコンパイラ追加と長期アーキテクチャ方針。
