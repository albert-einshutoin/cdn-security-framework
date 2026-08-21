# 変更影響分析に基づく選択的テスト実行 設計

## 目的

Pull Request CIで変更箇所と依存先に対応するテストを優先し、失敗検出能力を維持したまま実行時間と計算コストを削減する。影響範囲を安全に限定できない場合は必ず全テストへフォールバックし、判定処理の失敗をテスト成功として扱わない。

mainへのマージ後、release前、日次実行、手動完全検証では従来どおり全検証を行う。導入後14日以上は選択的テストと全テストを両方必須として比較し、見逃しがないことを確認してから手動で正式採用へ切り替える。

## 設計原則

- 安全に限定できる場合だけ `selective` を選ぶ。
- 限定不能、解析失敗、未分類の重要変更は `full` とする。
- 全テストコマンドすら決定できない場合は `failure` としてCIを失敗させる。
- CIサービス、テストフレームワーク、モノレポ管理ツール固有の処理をコアへ埋め込まない。
- ファイルパスは依存グラフ、テスト対応表、危険変更ルールを補完する情報として使う。
- CI設定には判定規則を散在させず、専用設定と判定ツールへ集約する。
- 外部入力をshell文字列として評価せず、検証済みの実行ファイルと引数の配列として起動する。

## アーキテクチャ

```text
ci/impact/
├── config/
│   ├── projects.json
│   ├── risk-rules.json
│   ├── module-mappings.json
│   ├── test-mappings.json
│   └── smoke-tests.json
├── schema/
│   ├── config.schema.json
│   └── result.schema.json
└── README.md

src/scripts/impact/
├── adapters/
│   ├── contract.ts
│   ├── javascript.ts
│   ├── python.ts
│   └── default.ts
├── diff.ts
├── classifier.ts
├── graph.ts
├── selector.ts
├── strategy.ts
├── runner.ts
├── reporter.ts
└── cli.ts
```

コアはGit差分、正規化済み設定、アダプターのJSON互換結果だけを扱う。アダプターはプロジェクト形式の検出、依存グラフ生成、関連テスト選択、検証コマンド、キャッシュ情報、追加の危険変更規則を提供する。

初期実装ではJavaScript/TypeScript、Python、defaultアダプターを提供する。未知のmanifestや未対応形式はdefaultアダプターが受け取り、設定済みの完全検証へフォールバックする。完全検証が未定義なら `failure` とする。

## 差分取得

PRのsynthetic merge commitではなく、対象ブランチの最新refとPR headを比較する。

1. CLI引数またはCI環境からbase refとhead revisionを受け取る。
2. 最新base refを取得する。
3. `git merge-base` で共通祖先を決定する。
4. `git diff --name-status -z --find-renames --find-copies` で差分を取得する。
5. add、modify、delete、rename、copyを構造化する。

renameとcopyは旧パスと新パスの両方を危険変更判定へ渡す。削除済みファイルは存在を前提にするアダプターへ渡さず、旧パスによる分類と依存情報だけを利用する。

shallow cloneでは段階的に履歴を取得する。base取得、merge-base、差分取得のいずれかが失敗した場合は、理由を記録して `full` とする。CI側も完全履歴をcheckoutすることで失敗率を下げるが、判定器自体もshallow cloneを安全に処理する。

## 影響範囲の判定

判定順序は固定する。

1. 危険な共通ファイルを検査する。
2. manifestと明示設定から変更プロジェクトを検出する。
3. 変更ファイルから変更モジュールを特定する。
4. import、export、require、include等の逆依存を辿る。
5. 直接参照する単体テストと変更されたテスト自身を選ぶ。
6. モジュール対応表から結合テストを追加する。
7. 機能対応表と危険度からE2Eテストを追加する。
8. 常時スモークテストを追加する。
9. 全変更が分類済みで、対象が自然で、アダプター結果が完全か検証する。

JavaScript/TypeScriptアダプターはTypeScript/JavaScriptの静的import、export、require、文字列リテラルの動的importを解析する。Pythonアダプターはmanifestと標準構文のimportを解析する。計算された動的依存や変更範囲内の未解決importがあれば `full` とする。

monorepoではプロジェクト依存グラフの逆辺を辿り、変更プロジェクトを利用する上位プロジェクトを影響対象へ加える。単一リポジトリではmodule mappingでlayerを定義し、下位layerから上位layerへ影響を伝播する。

## 危険変更

危険変更規則は `ci/impact/config/risk-rules.json` に集約し、各規則にpattern、理由、適用範囲を持たせる。

本リポジトリでは少なくとも次を完全検証対象とする。

- package manifest、lockファイル、依存更新
- TypeScript、Vitest、build、test、CI、release、container設定
- policy schema、生成型、API契約
- CLI起動、設定読込、routing、共通error
- compiler core、template injection、共通policy処理
- 認証認可、共通response header、security baseline
- impact analyzer本体、schema、adapter、判定設定
- 未対応manifest、未知のプロジェクト形式、未分類の重要ファイル

## テスト戦略

### Pull Request

常時実行するbaseline:

- `git diff --check`
- dependency security audit
- policy lint
- typecheck
- TypeScript compile/build
- 必須生成物検証
- CLI helpとdoctor
- 認証成功、未認証拒否、必須設定不足の安全な失敗を確認する限定スモーク

その後、判定結果に応じて選択された単体、結合、E2Eを実行する。既存の集約npm scriptを対象ごとに再実行せず、build後の個別テストentrypointを直接起動する。

### 完全検証

次のタイミングでは `npm run test:ci` と必要なpackage compatibility matrixを実行する。

- main push
- release前
- 毎日1回以上のschedule
- manual full validation
- dependency、schema、判定器の変更
- 判定不能または判定失敗

### package matrix

Node 20.17、22、24のpackage/API smoke matrixは、package、API、CLI、dependency変更時とmain、release、定期実行で行う。通常の内部実装PRではNode 24の限定スモークを常時実行する。

## スモークテスト

PRで常時実行できる限定スモークentrypointを追加する。

- CLI helpが成功する。
- base policyをコンパイルできる。
- AWSとCloudflareの必須生成物が存在する。
- doctorが成功する。
- 認証成功要求が通る。
- 未認証要求が拒否される。
- 必須設定不足時に明示的に失敗する。

## アダプター契約

各アダプターは次の操作を提供する。

- `detect`: manifestからproject rootと形式を検出する。
- `buildGraph`: module/project dependency graphを返す。
- `selectTests`: 変更と依存先に対応するtest targetを返す。
- `getValidationCommands`: baseline、selective、fullの実行可能コマンドを返す。
- `getCacheMetadata`: 安全なcache pathとkey inputsを返す。
- `getRiskRules`: 言語固有の危険変更規則を返す。

例外、不正JSON、不完全グラフ、unsupported結果は `full` へ遷移する。外部コマンドは `command` と `args` の配列で表し、shell評価しない。

## 機械可読出力

`reports/impact/analysis.json` に固定schemaで出力する。

```json
{
  "strategy": "selective",
  "baseRevision": "base-sha",
  "headRevision": "head-sha",
  "changedFiles": [],
  "detectedProjects": [],
  "affectedProjects": [],
  "affectedModules": [],
  "unitTestTargets": [],
  "integrationTestTargets": [],
  "e2eTestTargets": [],
  "smokeTestTargets": [],
  "fallback": false,
  "fallbackReason": null,
  "diagnostics": [],
  "executionPlan": []
}
```

実行結果は別のJSON/NDJSONへ保存し、test target単位の成功、失敗、skip、wall-clock時間、compute時間を記録する。framework reporterを利用できる場合はassertion/test case単位の件数も取り込む。

## 並列実行とキャッシュ

初期並列数は単一runner内の最大2プロセスとする。`dist`、report、container、network等の共有資源にresource lockを設定し、競合するtargetは直列化する。CI job matrixの乱立は避ける。

初期導入ではnpm download cacheと同一workflow内の検証済み生成物を対象とする。現行buildは再現性のためTypeScript incremental出力を無効化しているため、`.tsbuildinfo`はremote cache対象にしない。cache keyにはOS、CPU、Node、lock、build/test/schema設定のhashを含める。cache missや破損は通常実行へ戻し、成功判定を代替しない。

## 2週間の比較検証

導入後最低14日間は次を両方必須とする。

- 選択的テスト
- 全テスト

比較結果として実行時間、compute時間、推定コスト、選択数、全件数、削減率、fallback率、判定失敗率、flaky率、選択側だけの失敗、全テストだけの失敗を保存する。

全テストだけが失敗した場合はPRを失敗させ、risk rule、dependency mapping、test mappingの不足を修正する。14日経過だけでは自動移行せず、見逃しがなく必要なPR件数を確認したうえで設定変更PRにより正式採用する。

## CI連携

GitHub Actions固有のworkflowは次だけを担当する。

- checkoutとruntime setup
- cache復元
- analyzer実行
- JSON結果に基づくrunner起動
- main、release、schedule、manualのfull指定
- report artifactとjob summaryの保存

判定規則、依存関係、test mapping、fallback条件はworkflow YAMLへ記述しない。fork PRではread-only権限とfixture用の非機密値だけを使う。

## 自動テスト

TDDで次のfixtureを先に追加する。

- add、modify、delete、rename、copy
- multiple commits、merge commit、fork相当
- shallow clone、base取得失敗、merge-base失敗
- 危険変更、未分類変更、対象0件
- 直接test変更と逆依存伝播
- JavaScript/TypeScriptとPythonの複数project
- monorepoとsingle repository layer
- adapter例外、不正JSON、不完全graph
- shell injectionを含むpathとargument
- full/failure fallback
- result JSON Schema
- selective/full比較

## ドキュメント

英語・日本語のCI運用文書を追加し、目的、判定方法、対応形式、adapter追加方法、fallback条件、手動full、local再現、rule追加、誤判定修正、log、cache削除、定期実行、正式採用手順を記載する。

## 完了条件

- 最新baseとの安全な差分取得と全変更種別の処理
- 複数言語・複数projectの検出
- adapter切替と依存先を含む影響伝播
- 単体、結合、E2E、常時スモークの選択実行
- 危険変更と判定失敗の完全検証fallback
- main、release、schedule、manualの完全検証
- JSON Schema準拠の分析・実行・比較結果
- 安全なcacheと上限付き並列実行
- 14日間の必須比較検証
- 判定器自体の自動テスト
- adapter拡張手順と運用文書

## セルフレビュー結果

### 要件網羅性

依頼された差分取得、影響分析、fallback、monorepo/single repository、test category、cache、parallel、history、段階導入、documentation、完了条件を設計へ対応付けた。

### 失敗時安全性

差分取得失敗、未知形式、未分類変更、graph不完全、対象0件、adapter例外、全テスト未定義を成功扱いしない。削除ファイルを存在前提のselectorへ渡さず、fork PRへ特権を付与しない。

### コストと運用性

通常PRは単一runner内の上限付き並列と条件付きpackage matrixを用いる。比較期間中は意図的に全テストコストを維持し、測定結果と見逃しゼロを確認してから手動移行する。

### GO判定

実装開始を妨げる未解決の安全性・要件ブロッカーはない。TDDで判定器を実装し、完全検証とsecurity reviewを通したうえでPRを作成する。
