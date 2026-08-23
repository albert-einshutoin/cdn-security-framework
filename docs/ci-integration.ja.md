# GitHub ActionsでのContract Diff

[`examples/github-actions/contract-diff.yml`](../examples/github-actions/contract-diff.yml)を`.github/workflows/contract-diff.yml`へコピーし、例の`--openapi`と`--policy`をリポジトリ内のファイルへ変更します。`cdn-security-framework`は`package.json`で固定し、`npm ci`を使ってください。例は`./node_modules/.bin/cdn-security`を直接実行するため、依存が欠落しても未レビューのpackage versionを取得せず失敗します。

workflowはfork PRでも安全です。`pull_request`を使い、secretを読まず、権限は`contents: read`だけで、コメントを投稿せず、古いrunをcancelし、actionをcommit SHAで固定します。`$GITHUB_STEP_SUMMARY`には件数と上位findingだけを出し、`contract-diff.json`、`cdn-security.sarif`、`github-summary.md`をartifactにします。summaryへmessage、evidence、query string、request bodyは出しません。

## Gateとrequired check

`contract-diff` jobは`--fail-on error`で実行します。PRでpathを検証した後、`main`のrulesetでこのjobをrequired checkに設定してください。

- Exit `0`: 閾値を超えたfindingなし。
- Exit `1`: findingが閾値を超過。summaryとartifactを確認します。
- Exit `2`: input、設定、output pathのエラー。
- Exit `3`: 予期しないtool error。

最終gateはこの分類を保持し、tool errorをsecurity findingとして扱いません。

## 任意のSARIF upload

既定のartifact-onlyにはwrite権限が不要です。Code scanningを使う場合だけ`security-events: write`と次のstepをartifact upload後に追加します。

```yaml
permissions:
  contents: read
  security-events: write

- name: Upload SARIF to code scanning
  if: always() && github.event.pull_request.head.repo.full_name == github.repository
  uses: github/codeql-action/upload-sarif@42947a340483f03ba47bb1a039b2c519aab3df85 # v3
  with:
    sarif_file: reports/cdn-security.sarif
```

fork PRはartifact-onlyのままにします。`pull_request_target`へ変更したり、信頼していないcodeへsecretを渡したりしないでください。

## Exception

リポジトリ内のexception fileを`--exceptions`、対象scopeを`--environment`、決定的な日付を`--current-date YYYY-MM-DD`で指定します。期限切れは`SC-GOV-001`になりerror gateを失敗させます。owner、selector、reason、expiryをreviewし、広範囲または無期限のexceptionは作らないでください。[Finding exception](finding-exceptions.ja.md)も参照してください。

## Troubleshooting

- reportがない: inputが`--workspace-root`内にあり、`reports/`の親directoryが存在するか確認します。
- Exit `1`: JSON/SARIFを取得し、contractかpolicyを修正するか、review済みの一時exceptionを使います。
- Exit `2`: YAML、必須引数、target、workspace境界、既存outputを確認します。
- Exit `3`: 同じlockfileで一度再実行し、sanitized logとartifactを報告します。
- SARIF uploadが拒否される: artifact-onlyを維持するか、信頼済みupload jobだけへ`security-events: write`を与えます。

同じjob workspaceに前回reportが残る場合だけ`--force`を使います。調査時もraw secret、query値、header、request bodyを出力しないでください。
