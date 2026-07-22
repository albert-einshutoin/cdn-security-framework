# 選択的CIテスト

Pull Request CIでは、単にテスト数を減らすのではなく、失敗検出能力を維持したままフィードバック時間を短縮するため、保守的な変更影響分析を行います。静的検証、policy lint、型チェック、コンパイル、build検証、限定スモークは常時実行し、根拠を示せる場合だけ関連する単体・結合・E2E targetを選びます。

選択が完全だと判断できない場合は `npm run test:ci` へフォールバックします。判定処理の失敗によってテスト0件のCIが成功することはありません。

## CIレーン

- **Pull Request:** baseline、常時スモーク、選択された関連テスト
- **shadow比較:** 導入後最低14日間、全Pull Requestで全検証も必須ジョブとして実行
- **`main` / `release/**`:** 全品質ゲートとNode 20.17/22/24 package matrix
- **定期CI:** 毎日02:17 UTCに全検証
- **release:** `.github/workflows/release-npm.yml`が公開前に全検証
- **手動:** `policy-lint.yml`のworkflow dispatchで全検証

14日経過だけではshadowレーンを自動削除しません。全テストだけが検出した失敗がないことを比較レポートで確認し、レビュー済み変更として正式採用します。

## 影響範囲の判定方法

`npm run impact:analyze`は次の順序で判定します。

1. 対象ブランチの最新refとheadを解決
2. Git merge-baseを特定
3. NUL区切りでadd、modify、delete、rename、copyを取得
4. 集約された危険変更規則を適用
5. manifestからprojectを検出
6. 変更moduleを特定し、module逆依存を伝播
7. sourceの逆importを辿って関連testを検出
8. 明示的な結合・E2E mappingを追加
9. 常時smoke targetを追加
10. 全重要変更が分類済みで、全targetが実行可能か検証

機械可読な判定結果は `reports/impact/analysis.json`、実行指標は `reports/impact/execution.json` と `history.ndjson` に出力します。

## 対応アダプター

| アダプター | 検出 | 依存解析 | 関連テスト選択 |
| --- | --- | --- | --- |
| JavaScript / TypeScript | `package.json` | static import、export、`require`、文字列dynamic import | TypeScript test entrypointとVitest file |
| Python | `pyproject.toml`、`requirements.txt`、`Pipfile` | Python標準ASTのimport graph | 関連Python testを検出。選択実行にはproject固有test commandの明示設定が必要 |
| default | 既知の未対応または未知manifest | なし | 全検証のみ |

このリポジトリではrootのJavaScript/TypeScript projectとexample packageを検出します。source拡張子だけではprojectとせず、manifestまたは明示設定を必要とします。

## 全テストへのフォールバック

dependency・lock、build/test/CI/container設定、公開API・schema、共通compiler/security/auth/routing、impact analyzer自身、source削除、未解決import、不完全graph、影響対象の未対応project、未分類の重要file、関連testを特定できない非document source変更では全検証を選びます。

base revision、merge-base、変更一覧、設定、adapter、出力検証が失敗した場合も全検証です。完全検証command自体を解決できない場合は `failure` としてCIを非ゼロ終了させます。

規則は次へ集約されています。

- `ci/impact/config/risk-rules.json`
- `ci/impact/config/module-mappings.json`
- `ci/impact/config/test-mappings.json`
- `ci/impact/config/smoke-tests.json`
- `ci/impact/config/project-settings.json`

workflow YAMLへ同じ規則を重複させないでください。

## ローカルで再現する

本番値ではなくfixture専用値を使います。

```bash
export EDGE_ADMIN_TOKEN=ci-build-token-not-for-deploy
export ORIGIN_SECRET=ci-origin-secret-not-for-deploy
npm ci
npm run impact:analyze -- \
  --base origin/main \
  --head HEAD \
  --output reports/impact/analysis.json
npm run impact:run -- \
  --analysis reports/impact/analysis.json \
  --output reports/impact/execution.json
```

選択を使わず完全検証を再現する場合:

```bash
npm run test:ci
```

判定器から強制full planを出すこともできます。

```bash
npm run impact:analyze -- \
  --base origin/main \
  --head HEAD \
  --force-full "manual verification"
```

## CIログの見方

analyzerはbase/head、検出adapter/project、変更fileとstatus、影響project/module、test category、選択target数/全target数、strategy、fallback理由を表示します。

runnerは各target、成功・失敗・skip件数、wall-clock時間、target compute時間合計、任意の推定costを表示します。`CI_COST_PER_MINUTE`を設定するとrunner costの概算をexecution reportへ含めます。

shadow期間の `impact-comparison-report` には選択率、wall-clock/compute削減率、fallback、`fullOnlyFailure`が入ります。fullだけが失敗した場合は正式採用せず、mappingまたは危険規則を修正します。

## 誤判定を修正する

- 逆依存の欠落: adapterのgraph logicを修正
- importで表現できないsource/test関係: `test-mappings.json`へ限定的な対応を追加
- 広範囲または動的な共通処理: 理由付きで`risk-rules.json`へ追加
- layer伝播の誤り: `module-mappings.json`のdependencyを修正
- 新しい必須smoke: `smoke-tests.json`へallowlist commandを追加し、`project-settings.json`へIDを追加

analyzerまたは判定設定の変更は意図的に全検証対象になります。

## アダプターを追加する

1. `project-settings.json`へmanifest検出を追加
2. detect、graph、test selection、validation command、cache metadata、risk rule契約を実装
3. coreとは構造化データで通信し、shell command文字列を補間しない
4. 複数project、逆依存、削除、未解決依存、adapter失敗fixtureを追加
5. 選択実行を有効化する前に明示的な完全検証commandを追加
6. 対応manifestとfallbackを英日ドキュメントへ記載

adapterの例外や不完全な結果は必ず全検証を要求します。

## キャッシュの削除

GitHub ActionsはOS、Node、`package-lock.json`に基づいてnpm download cacheを利用します。ローカル生成物は再生成できます。

```bash
rm -f .tsbuildinfo
npm cache verify
npm ci
```

remote cache破損を疑う場合はrepositoryのActions cache設定から削除します。cache missやrestore失敗は通常実行へ戻し、test skipを成功扱いにしません。

## 履歴とコスト制御

commit pair、strategy、変更file、target、結果、時間をCI artifactとして30日保存します。NDJSONは将来のflaky検出、変更/失敗相関、遅いtestの順序最適化、coverage、risk scoreへ利用できます。

選択targetは1 runner内で最大2 processとし、生成物・package・containerを共有するtargetはresource lockで直列化します。Node compatibility matrixも `max-parallel: 2` とし、速度だけのためにrunner costを無制限に増やしません。
