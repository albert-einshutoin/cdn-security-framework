## アーキテクチャ概要

Release scope と capability status の正本は[version roadmap](./ROADMAP.ja.md)です。

本フレームワークは **"Policy → Compile → Runtime"** の三層構造で設計されています。

## プロダクト境界と Evidence

本プロダクトは **Application-aware Edge Security Compiler** です。
アプリケーションが宣言した意図とレビュー済み policy を provider 別の Edge / WAF
artifact に変換します。CDN / WAF の動作やアプリケーション認証認可を再実装しません。
運用の流れは **Generate → Diff → Review → Apply** です。

4つの独立した Truth を分離して扱います。

| Truth | Evidence | 何を示せるか |
| --- | --- | --- |
| Declared | OpenAPI | contract が公開すると宣言したもの |
| Implemented | Source AST / Source IR | 対応済み source syntax が宣言するもの |
| Allowed | Policy と CDN/WAF 設定 | security policy が許可するもの |
| Observed | Runtime evidence | deploy 済み system が実際に出力・受理したもの |

どの Truth も別の Truth の証明とは扱いません。未対応・partial な解析は推測で
補完せず、review 用 finding として報告します。

公開済みは **1.4.0 / Policy schema 1**。2026-10-26に照合したmain `31975ebcf9862ba040905c1a693fe17714b5a5fd`の技術基準は、明示migrationを持つ**未公開2.0.0-rc.0 / Policy schema 2**です。[候補の証拠](https://github.com/albert-einshutoin/cdn-security-framework/issues/1024)。H01 EN/JAは未実施で、RC GOと公開は未達です。

### Capability status

| Capability | Status | Interface | Limit |
| --- | --- | --- | --- |
| OpenAPI inspect | Implemented | CLI/API | local refs only |
| OpenAPI policy candidate | Implemented | CLI/API | review-only; never auto-applied |
| OpenAPI↔Policy drift | Implemented | CLI/JSON/SARIF/GHA | no source needed |
| NestJS Source Analyzer core | Experimental/Implemented core | Programmatic | no app execution; metadata is not enforcement proof |
| Source-aware contract diff CLI | Planned v2.1 | — | — |
| Auth/cache model verification (#1119) | Implemented bounded core | Internal harness | model-only; no deployed authentication proof |
| Cloudflare artifact HTTP verification (#1123) | Implemented local MVP | Internal native HTTP harness | bound artifact/runtime; no live Cloud or AWS cache proof |
| Runtime / Deployment Evidence (#534) | Planned beyond the local MVP | — | Phase B; release version not adopted |
| Policy Composition / Regression Guard (#536) | Planned | — | Phase D; release version not adopted |
| LSP/VS Code (#539) | Optional after GA | — | release version not adopted |

有界model coreとlocal artifact MVPはinternal・未公開の実装であり、public verifier APIやPhase A/B全体の完了ではありません。Deployment検証とprovider同値性はPlannedです。[#1119](https://github.com/albert-einshutoin/cdn-security-framework/issues/1119)と[#1123](https://github.com/albert-einshutoin/cdn-security-framework/issues/1123)に受入範囲を記録し、[#533 → #534 → #1118 → #536](ROADMAP.ja.md#4-version-release-train)で製品採用を判断します。

対応済み interface は [OpenAPI 導入ガイド](openapi-integration.ja.md)、
[NestJS Source Analysis](source-analysis-nestjs.ja.md)、[CLI リファレンス](cli.ja.md)、
[プログラマティック API](programmatic-api.ja.md) を参照してください。
Source-aware contract diff CLI は v2.1 planned のままで、現行 NestJS analyzer は
programmatic かつ static のみです。

---

## 全体フロー

```mermaid
flowchart LR
  U[User]
  CDN[CDN Edge]
  SEC[Edge Security Layer]
  WAF[AWS WAF / CF Security]
  ORI[Origin / App]

  U --> CDN
  CDN --> SEC
  SEC -->|block| U
  SEC -->|allow| WAF
  WAF -->|block| U
  WAF -->|allow| ORI
  ORI --> CDN --> U
```

---

## レイヤー別責務

### Edge Security Layer

対象:

* CloudFront Functions
* Cloudflare Workers

責務:

* Method / Path / UA の粗い検査
* クエリ正規化・削除
* 早期遮断（403/400）
* セキュリティヘッダー付与

特徴:

* 超低レイテンシ
* ステートレス

---

### WAF Layer

対象:

* AWS WAF
* Cloudflare WAF

責務:

* レート制限
* OWASP Managed Rules
* Bot / CAPTCHA
* Body 検査

特徴:

* ステートフル
* 高精度

---

### Origin / Application

責務:

* 認証 / 認可
* 業務ロジック
* データ整合性

> 「Edge が壊れても App が最後の砦になる」前提を維持する

---

## ポリシー駆動設計

```mermaid
flowchart TB
  P["Security Policy (YAML)"] --> C[Compiler]
  C --> CF[CloudFront Functions]
  C --> LAM["Lambda@Edge"]
  C --> CW[Cloudflare Workers]
```

### ポリシーの役割

* 人がレビューできる
* PR で差分が分かる
* CDN 依存を排除

---

## CDN別実装マッピング

| 概念     | CloudFront Functions | Lambda@Edge     | Cloudflare Workers |
| ------ | -------------------- | --------------- | ------------------ |
| 入口遮断   | Viewer Request       | Origin Request  | fetch()            |
| ヘッダー付与 | Viewer Response      | Origin Response | Response headers   |
| 高度検証   | 不可                   | 可能              | 可能                 |
| 状態管理   | 不可                   | 一部可             | KV / DO            |

---

## セキュリティ設計原則

1. **Fail Fast** – 早く落とす
2. **Least Privilege** – 通さない前提
3. **Defense in Depth** – Edge + WAF + App
4. **Portable Security** – CDN に依存しない

将来の Security Compiler 比較（段階的提供を計画中）は Declared、Implemented、
Allowed、Observed API を対象とし、いずれか1つを常に正とは扱いません。詳細は
[ADR 0003: Security ContractのTrust Model](adr/0003-security-contract-trust-model.ja.md)を参照してください。

---

## よくあるアンチパターン

* Edge だけで全てを守ろうとする
* WAF ルールと Functions が重複
* CSP をいきなり厳格化
* 例外ルールが増殖

---

## この設計が向いているケース

* グローバル配信
* API + 管理画面
* マルチテナント
* OSS / テンプレ配布

---

## 次のステップ

* [threat-model.ja.md](threat-model.ja.md) で攻撃整理
* [decision-matrix.ja.md](decision-matrix.ja.md) で Edge / WAF 判断
* ポリシーとランタイムの同期: [policy-runtime-sync.ja.md](policy-runtime-sync.ja.md)
* 観測: [observability.ja.md](observability.ja.md) でログ・メトリクス仕様
* CI 品質ゲート（policy lint + build + runtime + unit + drift + security-baseline）: `.github/workflows/policy-lint.yml`

## 保存Deployment fixtureのbinding（内部）

`bindHttpArtifactDeployment(snapshot, input)`は既存の内部artifact HTTP
verifierを拡張します。`snapshot`は`captureHttpArtifactSnapshot`が発行した
凍結objectである必要があり、deserializeしたcopyは拒否します。`input`は
保存fixtureのJSON text、receipt未取得なら`undefined`です。配備設定の取得や
providerへの接続は行いません。

入力の正本は`src/contract/verification/artifact-http.ts`の
`HttpDeploymentFixtureInput`です。version 1の形は次のとおりです。

```ts
const input: HttpDeploymentFixtureInput = {
  version: 1,
  scope: 'saved-deployment-fixture',
  expected: {
    resourceIdSha256, deploymentVersionSha256,
    referenceTimeMs: 1000, maxAgeMs: 100,
  },
  receipts: [{
    resourceIdSha256, deploymentVersionSha256,
    artifactId: snapshot.artifactId, capturedAtMs: 950,
  }],
};
const binding = bindHttpArtifactDeployment(snapshot, JSON.stringify(input));
```

2つのidentity変数には生のresource IDでなく小文字SHA-256 hexを渡します。
receiptのidentityは未取得を明示する`null`を許容します。v1の全fieldは必須で、
追加fieldや不正identityは入力Errorです。credential、URL、path、query、body、
生resource IDをこの入力へ持ち込まないでください。

入力上限は8192 UTF-8 bytesとreceipt 8件です。時刻は非負の安全な整数ms、
`maxAgeMs`は最大86400000です。freshnessの両端
`referenceTimeMs - maxAgeMs`と`referenceTimeMs`を含みます。未来時刻、完全に
重複したreceipt、不正scope/JSON/type、未発行snapshotは、生入力を含まない
固定`HttpArtifactError`です。未対応の正のenvelope versionは有界の`unknown`
とし、v1へ読み替えません。

| State | 保存fixture内の意味 |
| --- | --- |
| `missing` | artifact material、receipt、またはreceipt identityが欠落。 |
| `unknown` | 異なるresourceのreceipt、または未対応envelope version。 |
| `mixed` | 対象resourceに複数のdeployment-version/artifact identityが存在。 |
| `stale` | 期待version/artifactと不一致、または取得が古すぎる。 |
| `current` | 必要なidentityと時刻条件がすべて一致。 |

該当する固定reasonはすべて保持します。v1で複数の問題があればstateの優先順は
missing、unknown、mixed、stale、currentです。receipt順や、全identityとreasonを
保つ時刻metadata差はsemantic digestを変えません。freshness境界をまたぐとstaleの
reasonが変わり、集約stateが同じ`stale`や`missing`でもdigestは変わります。
元入力のSHA-256、発行snapshot digest、参照時刻・
window・取得時刻は別metadataに保持し、結果は再帰的に凍結します。

`current`はidentity/timeのbindingだけを表します。Security verdict、実配備の
attestation、認証強制の証明は返しません。保存bindingが`current`でも、既存の
独立HTTP verifierは同じartifactを`VIOLATED`と判定できます。Phase B全体、live
readback、canonical events、readiness、製品採用・公開は別の残件です。

repoのfixtureは次のコマンドで実行します。

```sh
npx --no-install vitest run test/contract/artifact-http.test.ts test/contract/auth-cache.test.ts
```

package barrel export、CLI、workflow、legacy adapter、自動Applyは追加して
いません。この追加のrevertでfixture bindingを戻せます。
