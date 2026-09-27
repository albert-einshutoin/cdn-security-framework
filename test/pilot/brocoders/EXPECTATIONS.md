# 固定brocoders第二Pilot：独立期待値

この一覧は固定commit `9620f159eefe38f47747d02ab162852367c5472c` のSourceを直接読み、Analyzerの初回実行前に確定した。機械可読の対応と全file/line根拠は [`expectations.json`](expectations.json) に保存した。対象はAuthController 11件とUsersController 5件だけであり、全repo operation数ではない。

`src/main.ts:36-45` はconfig由来global prefixと `exclude: ['/']`、URI versioningを設定する。`src/config/app.config.ts:78` の既定値に基づき、評価担当が `/api` とURI方式を明示する。製品がbootstrapや環境変数を読んだとは扱わない。Controller objectの `version: '1'` はauth `:32-35` とusers `:43-46`。method-level versionはこの16件にないため、Controller versionが有効となる。比較pathは prefix → `v1` → Controller path → method path の順。`/api`を省く制御ケースも用意する。

| 固定Source | methodとlocal path | versionの根拠 | URIのみ | URI＋明示 `/api` | 静的metadata | 既存解析の認証期待 |
|---|---|---|---|---|---|---|
| src/auth/auth.controller.ts:42 | POST `/auth/email/login` | Controller `1` (method指定なし) | `/v1/auth/email/login` | `/api/v1/auth/email/login` | local guardなし | unknown |
| src/auth/auth.controller.ts:51 | POST `/auth/email/register` | Controller `1` (method指定なし) | `/v1/auth/email/register` | `/api/v1/auth/email/register` | local guardなし | unknown |
| src/auth/auth.controller.ts:57 | POST `/auth/email/confirm` | Controller `1` (method指定なし) | `/v1/auth/email/confirm` | `/api/v1/auth/email/confirm` | local guardなし | unknown |
| src/auth/auth.controller.ts:65 | POST `/auth/email/confirm/new` | Controller `1` (method指定なし) | `/v1/auth/email/confirm/new` | `/api/v1/auth/email/confirm/new` | local guardなし | unknown |
| src/auth/auth.controller.ts:73 | POST `/auth/forgot/password` | Controller `1` (method指定なし) | `/v1/auth/forgot/password` | `/api/v1/auth/forgot/password` | local guardなし | unknown |
| src/auth/auth.controller.ts:81 | POST `/auth/reset/password` | Controller `1` (method指定なし) | `/v1/auth/reset/password` | `/api/v1/auth/reset/password` | local guardなし | unknown |
| src/auth/auth.controller.ts:94 | GET `/auth/me` | Controller `1` (method指定なし) | `/v1/auth/me` | `/api/v1/auth/me` | AuthGuard('jwt'); ApiBearerAuth | unknown |
| src/auth/auth.controller.ts:113 | POST `/auth/refresh` | Controller `1` (method指定なし) | `/v1/auth/refresh` | `/api/v1/auth/refresh` | AuthGuard('jwt-refresh'); ApiBearerAuth | unknown |
| src/auth/auth.controller.ts:126 | POST `/auth/logout` | Controller `1` (method指定なし) | `/v1/auth/logout` | `/api/v1/auth/logout` | AuthGuard('jwt'); ApiBearerAuth | unknown |
| src/auth/auth.controller.ts:141 | PATCH `/auth/me` | Controller `1` (method指定なし) | `/v1/auth/me` | `/api/v1/auth/me` | AuthGuard('jwt'); ApiBearerAuth | unknown |
| src/auth/auth.controller.ts:155 | DELETE `/auth/me` | Controller `1` (method指定なし) | `/v1/auth/me` | `/api/v1/auth/me` | AuthGuard('jwt'); ApiBearerAuth | unknown |
| src/users/users.controller.ts:56 | POST `/users` | Controller `1` (method指定なし) | `/v1/users` | `/api/v1/users` | AuthGuard('jwt') + RolesGuard; Roles(admin); ApiBearerAuth | unknown |
| src/users/users.controller.ts:68 | GET `/users` | Controller `1` (method指定なし) | `/v1/users` | `/api/v1/users` | AuthGuard('jwt') + RolesGuard; Roles(admin); ApiBearerAuth | unknown |
| src/users/users.controller.ts:98 | GET `/users/:id` | Controller `1` (method指定なし) | `/v1/users/{id}` | `/api/v1/users/{id}` | AuthGuard('jwt') + RolesGuard; Roles(admin); ApiBearerAuth | unknown |
| src/users/users.controller.ts:115 | PATCH `/users/:id` | Controller `1` (method指定なし) | `/v1/users/{id}` | `/api/v1/users/{id}` | AuthGuard('jwt') + RolesGuard; Roles(admin); ApiBearerAuth | unknown |
| src/users/users.controller.ts:129 | DELETE `/users/:id` | Controller `1` (method指定なし) | `/v1/users/{id}` | `/api/v1/users/{id}` | AuthGuard('jwt') + RolesGuard; Roles(admin); ApiBearerAuth | unknown |

`AuthGuard` は `@nestjs/passport` のfactory（auth `:21`、users `:26`）で、`jwt` と `jwt-refresh` の引数は別の静的事実。usersの `RolesGuard` はローカル実装（users `:36`、`src/roles/roles.guard.ts:7-23`）、`Roles(RoleEnum.admin)` はローカルdecorator／enum（users `:24-25,40`、`src/roles/roles.enum.ts:2`）。`ApiBearerAuth` はSwagger metadataで認証強制の証拠ではない。Runtime Guardの動作・認証/認可の到達可能性は評価しない。local Guardがない6件も、global provider等を証明していないためpublicと断定しない。製品のdefault/空設定では全16件の認証はunknownとして照合し、factory引数を潰すguard mappingやRolesGuardの偽mappingは使わない。

他のControllerはarchiveから削除しない。`src/home/home.controller.ts:7,11` のGET `/` はversion未指定であり、今回の採点対象外。OAuth/File等も観測件数を別に記録する。prefix exclusion、defaultVersion、neutral、runtime routingを再現したとは主張しない。入力は評価用OpenAPI/Policyであり、元アプリの既存契約や本番Policyではない。Sourceのpartialまたは失敗があれば、未比較を確定的欠落へ置き換えない。
