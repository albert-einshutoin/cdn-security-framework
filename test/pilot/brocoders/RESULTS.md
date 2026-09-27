# 固定brocoders第二技術Pilot：ローカル証拠

Issue #1080 の固定入力と独立期待値は、Analyzer実行前のcommit `880bfa3` に固定した。上流は `brocoders/nestjs-boilerplate` commit `9620f159eefe38f47747d02ab162852367c5472c`、tree `64452fb291246177f50d9749fd4a2c12f521a11e`、MIT（Copyright (c) 2023 Brocoders）。取得したGitHub archive SHA-256、採用194ファイルごとのhash、privacy除外は [`source-manifest.json`](source-manifest.json) にある。上流に静的OpenAPIは見当たらず、ここにあるOpenAPIとschema 2 Policyは16件だけの独立した評価用契約である。

元lock SHA-256 `8d9f306964b994c48a5729a80b77c385ac170bc711eec37893a89873bba2bf4d` の `npm ci --ignore-scripts` は `gcp-metadata@7.0.1` 欠落でexit 1。元lockをarchive内に保持し、version/integrity変更0件・entry追加1件の派生lock SHA-256 `78f85d33ed84ad7214ea81e4996a2a3741c5670c9f199137b1e91dbc056919b6` で準備exit 0。詳細は [`dependencies.md`](dependencies.md)。対象app、DB、migration、Guard、bootstrap、targetのinstall script/hookは実行していない。

受入済みdevのmerge SHA `22a664c21d5761d3a28ea0497e544c780a1ce581` のinstalled候補では、固定snapshotの静的解析が `SOURCE_ANALYZER_INTERNAL` で失敗した。原因はProvider escape解析の初期化前参照。別Issue #1081／未マージPR #1082の1行修正により、下記の**修正候補上での**技術評価が可能になった。この結果を受入済みdevの成功とは扱わない。

## 修正候補での限定結果

ローカルsingle-packのsource/harness `b30d05efce48807c0e93e0fd082287dd7eb19abe`、tree `e8ff6051aeea3e78f81529cc8d15c3012ec85eed`、ローカルrun/attempt `1081001/1`、tgz実bytes SHA-256 `68d1c9b8bfce5b68801202eb30a52f80954621ccac377674992ebedf737fbc7a`、common consumer lock `24772c3e34667e154a56c4783f4194eefdff177c4caab03ebec9dab00633b5df`。空consumerへscript無効でinstallし、製品moduleと`cdn-security` binaryがconsumer内へ解決することを確認。`sandbox-exec`でnetworkを禁止して評価した。

- R01（URI optionなし）：無versionの16 routeへ化けず、従来のSource contractにはHomeの `GET /` 1件、未解決candidate 23件。partialのまま。
- R02（明示URI、prefixなし）：採点対象16件が `/v1/...` のmethod＋path、Source method行、Controller version `1`、local pathへ一対一対応。
- R03（明示URI＋`/api`）：採点対象16件が `/api/v1/...` へ一対一対応。full内部route集合21件のうち、OAuth/Fileの5件は採点対象外。Home `GET /` はversion未指定の未解決1件。product結果のpartial、対象外Findingを消していない。
- R04（誤ったrouting前提）：prefix省略・`/wrong`ではそれぞれ21 Source-only、16 Declared-only。誤った`v2`宣言はDeclared-only 1件と不一致を残し、自動補正しない。
- R05（意図した差分）：method不一致1、独立単一pathのSource-only 1、Declared-only 1、PolicyのDELETE拒否2、存在しないexact Policy route 1を対象method/pathとSARIFのSource/OpenAPI/Policy位置で確認。Policy routeはDeclared–Allowedの `SC-INVENTORY-002` とpartial Source側のheuristic `SC-INVENTORY-005` を分けて記録。
- R06（認証対照）：16件のSource認証はすべてunknown。`AuthGuard('jwt')`、`AuthGuard('jwt-refresh')`、`RolesGuard`、`Roles(RoleEnum.admin)`、`ApiBearerAuth` の記述を区別した。評価用OpenAPIだけにBearer宣言を追加するとOpenAPI–Policy `SC-AUTHN-001` 1件。これをSource認証の正答へ加算していない。
- R07：同じinstalled候補でtext/json/sarif/summaryと`--out`を実行。保存JSON bytesはstdout JSONと同一hash。12ケースのdriver `run`、`publish`、`verify-stage`、`gate` がすべて `CI_OK`。入力hash・Source bytes・privacyを検査し、安全な集約14,626 bytesのみstage（SHA-256 `54868731d5afb2e038e50af74c7a8f794b89ff358daa3c374ac681a69f8e13c3`）。完全内部route証拠のdigestを照合した。誤った1 routeのFinding集合と、許可外 `sourceSnippet` fieldを追加した集約はそれぞれ拒否した。詳細Summary/SARIFはupload対象外。

採点単位は固定16件のmethod＋正規化比較path。正しい明示前提でTP 16、FP 0、FN 0、分母16。意図したR05/R06 Finding対象は7件を別分母としてTP 7、FP 0、FN 0。unknown 16、未解決Home 1、評価対象外5、入力/resource/internal error 0を別掲する。変異ケースは独立した実アプリ数を増やさず、実アプリは1件。Findingの件数だけでroute抽出を採点せず、同一の内部解析結果の完全route集合とversion metadataを照合した。

1回のローカル観測で依存準備3,531 ms、無URI解析1,951 ms、URI解析1,556 ms、12ケースのdriver合計27,321 ms。TypeScript projectは2,050ファイル、11,294,872 bytes、542,406 AST nodes、Source candidate 24件。解析後のprocess RSS観測は697,516,032 bytes。p95・一般性能保証ではない。`/api`とURI方式は評価担当の明示前提であり、`src/main.ts` のbootstrap自動解釈ではない。root除外、他のrouting制約、runtime認証や到達性、公開の安全性は保証しない。H01・5分理解度・正式2.1 Entryも未実施。

再実行は `node test/pilot/brocoders/pilot.cjs prepare <empty-dependencies-dir>` と、同じsingle-pack candidate identity環境変数を与えてnetwork無効下で `node test/pilot/brocoders/pilot.cjs evaluate <candidate-dir> <dependencies-dir> <new-work-dir> <safe-output>`、続いて `verify <candidate-dir> <work-dir> <safe-output> <new-stage-dir>`。Hostedでは `.github/workflows/policy-lint.yml` の `source-brocoders-pilot` jobが既存producer／package-acceptanceに従属し、準備だけonline、評価は`unshare --net`、uploadは検証済みsafe-result.jsonのみとする。
