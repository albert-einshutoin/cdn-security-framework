# 対象依存の準備記録

固定snapshotの `package-lock.json` SHA-256 は `8d9f306964b994c48a5729a80b77c385ac170bc711eec37893a89873bba2bf4d`。Node 24.2.0／npm 11.3.0 の `npm ci --ignore-scripts --no-audit --no-fund` は、lockに `node_modules/mongoose/node_modules/gcp-metadata@7.0.1` が欠けるため exit 1 (`EUSAGE`) だった。これは固定上流lockの状態として残す。

同じ固定 `package.json` から `npm install --package-lock-only --ignore-scripts --no-audit --no-fund` で派生lockを作成した。SHA-256 は `78f85d33ed84ad7214ea81e4996a2a3741c5670c9f199137b1e91dbc056919b6`。元の1298 packagesに1件だけ追加して1299 packagesとした。他のpackageのversion/integrity変更は0件。追加entryは `gcp-metadata@7.0.1` のregistry tarballとintegrityを固定している。元lockはsnapshot内に保持し、派生lockを別fileに置く。

派生lockで `npm ci --ignore-scripts --no-audit --no-fund` はexit 0、1298 packagesを準備した。peer optionalの `@nestjs/mapped-types@2.1.0` 対 `class-validator@0.15.1` 警告は残る。依存準備だけnetwork可。解析工程はnetworkを無効にし、対象のscript/hook、app、migration、DB、JWT/JWKS、Guard、bootstrapを実行しない。依存versionを更新したりstubで置換したりしていない。
