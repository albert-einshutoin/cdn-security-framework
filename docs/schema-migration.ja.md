# Policyスキーマ移行

> **言語:** [English](./schema-migration.md) · 日本語

## 公開済みと候補の契約

公開済み`cdn-security-framework@1.4.0`はPolicy **version 1**です。未公開main候補は**version 2**ですが、release GOまではpackage.jsonのversionを1.4.0のまま保持します。候補はcommit SHAとtarball SHA-256で識別してください。npm 2.0.0の公開済みを意味しません。

coreのlint/build/API、継承する各Policy文書、init/guided、profiles/archetypes、OpenAPI candidateはv2のみを扱い、v1を暗黙変換しません。Finding、Security IR、inspection、report、exceptionのschema versionは別契約で変更しません。

既存の有効入力を拒否する変更はPolicy schema majorとnpm majorを必要とします。任意fieldの追加だけならPolicy version変更は不要です。将来の廃止は個別の移行契約を定義します。仮想的なrenameや任意versionへの自動連鎖は実装していません。

## 明示migration

npm latestではなく、**候補tarballから導入した実行ファイル**を使用します。

```bash
./node_modules/.bin/cdn-security migrate --policy policy/security.yml
./node_modules/.bin/cdn-security migrate --policy policy/security.yml --target cloudflare
./node_modules/.bin/cdn-security migrate --policy policy/security.yml --target cloudflare --write
```

`--to`省略は**2**です。previewは入力を読み、固定summaryだけを表示し、ファイルを作りません。API `migratePolicy({ policyPath, toVersion?, target?, write?, cwd? })`は変換した`policy`も意図的なPolicy成果物として返します。このobjectは必要な秘密設定を含む場合があるため、診断として無条件にlogへ出さないでください。errors/warningsとCLI summaryは固定code・既知field名であり、元YAML、path、env値、秘密値を出しません。APIはprocess.exitしません。

| 設定・入力 | 結果 |
| --- | --- |
| 正常v1、通常設定 | versionだけ2へ変更。metadata、文字列、env参照、配列順序を保持 |
| difficulty 1〜4 | 保持 |
| difficulty 5/6 | exit2。利用者が対応値を明示選択。4へclampしない |
| AWS csp_nonce true | exit2。Cloudflare、origin管理、設定の明示変更を選択。自動disableしない |
| AWS JWT/signed_url | exit2。AWS cache hitの認証境界で未対応。削除・disableしない |
| Cloudflare nonce/JWT/signed_url | 有効設定を保持。schema妥当性だけでdeploy可能としない |
| provider依存設定があるがtarget未指定 | exit2。aws/cloudflareを明示選択 |
| 未知field・不正データ | exit1。黙って削除しない |
| extends・root $ref | exit2。graph移行は未対応。依存を読込・flattenしない |

Policy schemaにtarget欄はありません。migrationのtargetは利用者が明示し、buildのAWS既定値を流用しません。通常変換はprovider非依存です。未知target名はエラーです。migration中にJWKS、外部API、env展開は行いません。target向けbuildは別に#1017等の安全性チェックを実施します。

入力versionは数値1/2のみ。noopより先に検証し、未知version同士が等しくても成功しません。不正v2もvalidatorを回避できません。有効v2→v2、明示した有効v1→v1は`--write`でも再保存しないnoopです。downgradeは未対応です。API toVersionは既存number|string型を保持し、CLI文字列は`1`/`2`等の整数表記だけを受け、`2.0`は拒否します。

| 結果 | CLI exit / API exitCode |
| --- | --- |
| 変換preview、保存成功、検証済みnoop | 0 |
| 引数・parse・schema・downgrade・resource・I/O失敗 | 1 |
| 未対応version・手動判断必須 | 2（reservedExit2:true） |

## 設定保持と入力上限

単一v1 adapterは公開1.4.0 tarballのschema（SHA-256 `dcf963406f7afaff82edb3d8ae775de26587438d815d5bb3dbde4b57ee9ba1bd`）で検証します。coreは旧schemaを参照しません。自動変更はversionだけで、入力objectを破壊しません。

保証対象は解析後のJSON互換設定値です。YAMLコメント・整形・anchor表現・object identityは保持しません。aliasは同じ値を個別にserializeする場合があります。未対応tag/merge構造、循環、prototype特殊キー、非JSON値は黙って変更せず拒否します。入力/出力1MiB、深さ64、YAML alias50、走査値10,000件（alias再訪も加算）を上限とします。参照graphのmigrationは行いません。v2の各継承文書にもversion2を要求し、rootだけv2にしてv1依存を隠せません。

## 明示保存とrollback

`--write` / `write:true`は**変換の保存成功時だけ**選択Policyの更新を許可します。noop・手動判断必須・不正入力は保存しません。末尾symlinkは読込時に拒否し、複数hardlink入力は保存を拒否します。信頼した親directory aliasは実パスへ解決し、identityを固定します。

同directoryの`<policy>.v1.bak`が未存在であることを前提とし、既存file/symlink/hardlink/directoryは衝突として拒否します。backupは元bytesを0600で保持します。別のexclusive stagingへ検証済み・serialize/parse同値確認済みの全内容を保存し、inputのbytes/identity/link数/mode/親identityを再確認してrenameします。stagingは元のownershipと最終permission bitsを保持できる必要があります。確定点は選択Policyへのrename成功です。report用truncate writerは使用しません。

確定前の失敗は元bytes/hashを保持し、所有するtemporary/backupだけをcleanupします。確定後はPolicyが意図的に変わり、元backupを残します。確定後のcleanup失敗は固定warning付き成功であり、入力不変とは主張しません。既存の無関係fileは上書きしません。外部processが入力を変更した場合、その変更をtoolが巻き戻すことはしません。

特殊permission bitsは拒否し、ACLや拡張属性は置換時に保持しません。確定前のcleanup自体が拒否された場合は固定error `MIGRATION_SAVE_FAILED_CLEANUP_INCOMPLETE`で所有artifactが残る可能性を通知します。入力は未確定のままです。外部processが差し替えた未知fileはcleanupで削除しません。

信頼し排他的に管理するPOSIX local directoryが前提です。最終check後の任意の同権限競合、crash/power loss耐久性、Windows/network filesystemは保証しません。恒久的rollback原本はgit等へ保存し、local backupだけに依存しないでください。

使い捨てrehearsal、または別途承認したrollbackでは:

1. gitまたは`.v1.bak`からmigration前のv1 bytesを復元する。
2. rollback環境で`cdn-security-framework@1.4.0`をpinする。latestを使わない。
3. pinしたpackageで対象providerのlint/buildを行う。

公開1.4.0 tarballにはCloudflare buildに必要な`esbuild` runtime依存が同梱されていません。使い捨てrollback rehearsalでは、旧tag v1.4.0の固定値`esbuild@0.28.0`を、変更していない公開packageに追加導入しています。この前提なしの公開1.4.0 Cloudflare buildは失敗します。lint・AWS build成功だけでCloudflareのrollback成立とは扱いません。候補packageの依存追加ではありません。

v1を候補v2 coreへ戻すdowngrade adapterではありません。1.4.0へ戻すと、後から追加されたprivacy・入力保護・AWS拒否等の安全強化も失います。本番rollbackが自動的に安全とは判断しません。
