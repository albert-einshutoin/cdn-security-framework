# Experimental Source-aware CLI（devブランチ限定）

`cdn-security contract source-diff` は `dev/2.1-source-aware` 候補packageの
**未公開Experimental**入口です。公開済み1.4.0、2.0のRC、完成した標準2.1 workflowには
含まれません。記録されたCI runの候補tarballを使い、`npm latest`で置き換えません。

対応Node.js（>=20.17.0）の空の使い捨てPOSIX consumerへ照合済み`.tgz`を置き、
PR証拠のSHA-256と一致することを確認してから導入します。offline受入では共通lockと
依存cacheを別途準備し、single-pack consumer laneを使います。

```sh
shasum -a 256 candidate.tgz
npm install --ignore-scripts ./candidate.tgz
mkdir -p workspace
cat > workspace/openapi.yaml <<'YAML'
openapi: 3.0.3
info: {title: Synthetic, version: 1.0.0}
paths:
  /users:
    get:
      responses:
        '200': {description: OK}
YAML
cat > workspace/policy.yml <<'YAML'
version: 2
defaults: {mode: enforce}
request:
  allow_methods: [GET]
  block: {header_missing: []}
routes: []
response_headers: {}
YAML
./node_modules/.bin/cdn-security contract source-diff \
  --workspace-root workspace --openapi openapi.yaml --policy policy.yml \
  --target aws --current-date 2026-09-25 --format text
```

単一workspaceを明示します。`--source tsconfig.json`を渡すと既存の静的NestJS解析を
要求します。省略時のSourceは **omitted** で、自動探索しません。
`--target aws|cloudflare`、任意のbounded `--exceptions <path>` と
`--environment <name>`、`--fail-on error|warning|never`（既定`error`）、
`--format text|json|sarif|summary`（既定`text`）を指定できます。例外ファイルがなくても
`--current-date YYYY-MM-DD`は必須です。Source認証設定は既存defaultを使い、
確認できない情報はpublic/認証済みと推定せずunknown/partialにします。
partialは安全性の証明ではありません。

`--source`とともに`--source-auth-config <path>`を指定すると、
`--workspace-root`基準で明示した単一のYAML/JSONデータファイルを読みます。
既存例の[`security-analyzer.yml`](../examples/nestjs-contract/security-analyzer.yml)は
`Public`、`Roles`、`JwtAuthGuard`を対応付けます。option省略時は既存の空の
Source認証defaultを維持します。必須の`public_decorators`、`roles_decorators`、
`guard_mappings`をすべて明示した空定義も同じ意味です。
既存例ではdefaultの`GET /users/{id}`と`POST /users`の認証はunknownです。
明示設定を読むと、GETの直接`Public`、POSTの`Roles('writer')`、
`JwtAuthGuard`のbearer対応を認識し、OpenAPI/Policyとの該当する不一致を
Findingに反映します。`UnknownGuard`を設定していないrouteはpartialのままです。
未知fieldや不正な設定は
解析前に固定診断とexit `2`で拒否し、defaultへ戻しません。`--source`なしで
このoptionだけを渡した場合は、ファイルを読まずexit `2`です。自動探索、
include、alias/mergeによる合成、環境変数展開、実行可能なJS/TS設定はありません。
CLI入力は単一の通常ファイルを最大64 KiBまで読みます。workspace内symlinkは
許容し、外へ解決されるsymlinkは拒否します。この上限はCLIのファイル入力に
適用し、Programmatic APIの全設定objectには適用しません。確認済み環境は
POSIX/local fixtureで、Windowsやnetwork filesystemは未検証です。
Guard名と認証種別の対応は利用者が与える静的な前提であり、Guard本体、token検証、
middleware順序、runtime認証の証明ではありません。未設定のGuardや他の未解決
Source事実はpartialのままです。

すべての比較対象Source routeへ同じ固定global prefixが適用されることを**利用者が確認した**
場合に限り、`--source`とともに`--source-global-prefix /api`を渡せます。
`api`と`/api`は同義です。bootstrapの`setGlobalPrefix`を製品が自動解析した
証拠ではなく、明示した比較前提です。省略時は従来のdecorator-local routeと
report identityを維持します。`--source`なしの指定は入力読込前にstdout空・
exit `2`で拒否します。空、`/`のみ、末尾/重複slash、URL、query、fragment、
backslash、制御文字、dot、percent、wildcard、動的parameter、空白を固定診断で
拒否し、defaultへ戻しません。ASCIIの`[A-Za-z0-9_-]`による1個以上のsegmentに
限定し、先頭slashは0または1個、正規化後は最大256文字です。大小文字は保持します。
provider tokenに似た値は入力読込前に拒否します。

| 入力 | 結果 |
| --- | --- |
| `api`、`/api` | ともに`/api` |
| `/API`、`/api/v1` | 大小文字と複数の固定segmentを保持 |
| 空、`/`、末尾/重複slash | 解析前にexit `2` |
| URL、符号化・動的・wildcard・dot segment、provider tokenに似た値 | 解析前にexit `2` |
| 正規化後256文字超 | 解析前にexit `2` |

local `/`は`/api`、`/articles/{slug}`は`/api/articles/{slug}`、既に
`/api/items`であるrouteは`/api/api/items`になります。

元のSource IR、入力project digest、認証設定digest、file/line、unknown/partialは
変えません。比較用コピーだけをImplemented–DeclaredとImplemented–Allowedへ
渡し、OpenAPI/Policy入力およびDeclared–Allowedは変換しません。比較する
OpenAPI/Policyも、利用者が意図する同じpath体系で用意してください。Swaggerの
servers/basePathやproxy rewriteをこのoptionで再解釈しません。routing前提と
変換済みcontractのdigestは入力・認証digestと分離し、Text/JSON preview、SARIF
properties、Summary、dev CI記録へ安全に表示します。prefixでrouteとFinding
instanceIdが変わる場合、旧exact例外selectorを自動拡大しません。exclude、URI
versioning、複数Nest app、reverse proxy rewriteは対象外です。runtime到達可能性、
middleware/Guardの強制、認証の証明にもなりません。

| 形式 | 明示前提の表示 | Findingの範囲 |
| --- | --- | --- |
| Text | 件数制限付きpreviewに安全なprefix | 件数制限付きpreview |
| JSON | 内部previewに安全なprefixとrouting/contract digest | 件数制限付きpreview |
| SARIF | 内部tool propertiesに安全なprefix/digest、Source由来結果に前提route | reporter上限内の全結果 |
| Summary | 安全なprefix表示 | 上位Findingのみ |

dev CI記録には、安全なprefixとdigestを元のSource project/認証digestと分けて
保存します。Node 24のinstalled-package consumerは、同じtgzでprefixあり・
省略・不正、4形式、`--out`を検証します。証拠が欠けるとpackage acceptance gateは
拒否します。

Text/JSONは件数上限のあるpreviewです。JSONは完全な安定公開schemaではありません。
SARIFは既存reporter制限内の完全結果、Summaryは最大10件/32KiBの表示です。
形式によって省略表示は異なります。exit `0`は処理成立・Finding閾値未到達、
`1`は処理成立・閾値到達、`2`は入力/configuration/bounded-input失敗、
`3`は内部/reporter/出力失敗です。入力stageが失敗しても、独立比較のFindingを
含むreportを出してexit `2`になる場合があります。`--fail-on never`は失敗を
成功へ変換しません。reportはstdout、固定失敗診断はstderrです。JSON/SARIFは
単一JSONと末尾改行を出します。`--out <path>`を指定すると、同じbytesを明示した
workspace内の**新規通常ファイル1件**に保存し、stdoutには出しません。上の例には、
`workspace/reports`を先に作成したうえで`--format sarif --out reports/source.sarif`
を追加できます。親directoryは既存である必要があります。directoryの作成、既存
ファイルの上書き・追記、`--out -`は行いません。保存するたびに新しい保存先名を
選んでください。保存先が既存のファイル、symlink、hardlink、directory、FIFO、
socketなら拒否します。新規ファイルはPOSIXで所有者
のみの権限（`0600`）です。保存成功後もreportのexit `0`/`1`/`2`を維持し、
不正・保護対象の保存先はexit `2`、書込み・後始末の失敗は固定診断とexit `3`
で、stdoutにreportを出しません。

保存先はworkspace内かつ`policy`、`dist`、`node_modules`、`.git`の外側に
限定し、symlink経由のaliasも検査します。明示または検出されたOpenAPI、Policy、
Source、認証設定、例外、local ref、tsconfig、package metadataの入力名には、
入力が未存在でも保存できません。内部入力stageの保護が十分に確立できない場合も
保存を拒否します。検査対象は当該実行で観測した入力であり、並行変更中のworkspace
全体を原子的にsnapshotするものではありません。directory entryを別processが
変更すると保存失敗や、回復不能なfilesystem障害では検知可能な部分的な新規
ファイルが残る場合があります。信頼できない並行writerとworkspaceを共有しないで
ください。検証済み環境はPOSIX/local fixtureで、Windowsとnetwork filesystemは
未検証です。

[dev限定CI例](source-aware-ci-dev.ja.md)は合成fixtureの検証済みStep Summaryと
通常のActions artifactを保存します。CLI自体はGitHubへ書き込まず、正式2.1
workflow、Code Scanning upload、PR投稿、apply/deployは未実装です。shellの
redirectはCLI起動前に働くため、入力ファイルへreportをredirectしないでください。

実binaryはinstalled-package smokeで検証します。[標準CLIリファレンス](cli.ja.md)は
2.0のコマンドを説明します。正式Source-aware workflowは後続工程です。
