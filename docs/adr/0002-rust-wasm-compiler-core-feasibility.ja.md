# ADR 0002: コンパイラのRust/WASM化検討

> **ステータス:** v1.4.x での提案

## 背景

TypeScript のコンパイラ基盤は現在、次の責務を担っています。

- ポリシーの読み込み・検証
- ReDoS 安全性チェック
- テンプレートへの設定注入と出力生成
- スキーマ準拠の lint 挙動
- ランタイム別のコンパイル分岐
- パッケージング検証と drift チェック

長期的には Rust/WASM 化で性能や安全性が向上する可能性がありますが、導入前に
リリース・運用への影響を測定し、根拠に基づく判断が必要です。

この issue では、先に現状ベースラインを計測し、ネイティブ依存を入れずに判断することを目標とします。

## 計測内容

- `scripts/benchmark-compiler.js` を追加し、以下を測定可能にしました。
  - コンパイラの起動/コンパイル時間（cold+warm）
  - `/usr/bin/time` 利用時のコンパイラ RSS（利用可能時）
  - 任意の `npm ci --ignore-scripts --no-audit --no-fund` 計測
- Node v24.2.0（darwin/arm64）のベースライン結果:
  - `docs/benchmarks/compiler-baseline.json`
  - 実行コマンド:
    - `node scripts/benchmark-compiler.js --iterations 5 --warmup 1 --policy policy/base.yml --allow-placeholder-token --output docs/benchmarks/compiler-baseline.json`
  - cold start: `50.0ms`
  - warm p50/p95: `48.0ms` / `53.1ms`
  - コンパイル RSS（MiB, min/p50/max）: `56.3 / 56.4 / 56.8`
- 任意の install ベースライン:
  - `docs/benchmarks/compiler-baseline-with-install.json`
  - 実行コマンド:
    - `node scripts/benchmark-compiler.js --iterations 3 --warmup 1 --policy policy/base.yml --allow-placeholder-token --measure-install --install-iterations 1 --output docs/benchmarks/compiler-baseline-with-install.json`
  - `npm ci` 中央値: `1,025.8ms`

## 選択肢

### 選択肢A: TypeScript を現状運用し続ける（推奨）

長所:

- 既存のリリース/依存関係・スクリプト構成を変更しない
- TypeScript 前提の開発体験を維持でき、導入障壁が低い
- リリースが既存フローのため巻き戻しが容易
- 既存の脆弱性スキャンと supply-chain 管理を継続できる

短所:
- ネイティブ移行が前提の一部性能改善は将来課題のまま
- 言語実行環境の制約で得られる安全性は限定的

### 選択肢B: Rust/WASM を1モジュールに限定して隔離導入

長所:
- 正規表現検証など、影響範囲を限定して検証可能
- 残りは現状維持し、比較対象が明確

短所:
- CI でのツールチェイン増設とアーティファクトの扱いが必要
- OS/CPU/CI 環境ごとの配布判断が追加
- rustup/npm 併用の開発導線が増える

### 選択肢C: コンパイラ全体をRust/WASM化

長所:
- 完了時には一気に性能・配布の見直し余地が生まれる

短所:
- 変更範囲が大きくリリースリスクが高い
- テスト・Golden・CLI/ドキュメント移植コストが高く、長期の再設計が必要
- 運用中の互換性問題が出る可能性

## 決定

v1.4.x では、**本番のコンパイラ基盤は TypeScript 維持**とし、まず
Node20/22/24 でのベースライン取得を最低1リリース分実施してから判断する。

## 追従アクション

1. Node20/22/24 の3環境で新規ベンチを定期収集
2. 必要なら1モジュール限定で Rust/WASM PoC を別途検討
3. ベンチ差分と保守性が確認できた上で次のADRで採否を確定

## リリース/保守観点

### 直近の採用判断（次の1〜2リリース）

- **リリースリスク:** 現状低い。ネイティブ依存を増やさないため既存フローは維持。
- **CIリスク:** 小。ベンチ追加は任意実行で既存ゲートに影響しにくい。
- **品質リスク:** 小。業務ロジック未変更で運用影響は限定的。

### 将来ネイティブ採用時の中期リスク

- **ツールチェインリスク:** rustup の導入とキャッシュ戦略が必要。
- **サプライチェーンリスク:** バイナリアセット運用が追加され監査領域が拡大。
- **貢献者リスク:** 初期参入時の開発環境準備コストが上がる。
- **プラットフォームリスク:** OS/ABI 差分（glibc/musl、x64/arm64）へ対応。
