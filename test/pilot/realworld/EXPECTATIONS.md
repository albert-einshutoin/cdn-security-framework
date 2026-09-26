# Fixed public NestJS Pilot expectations (pre-analysis)

Source: [lujakob/nestjs-realworld-example-app at c1c2cc4](https://github.com/lujakob/nestjs-realworld-example-app/tree/c1c2cc4e448b279ff083272df1ac50d20c3304fa). These 19 rows were read from controller and module files before any analyzer run. Paths omit runtime `api` prefix because the analyzer explicitly does not inspect global prefixes. This is an evaluation-only decorator-local comparison, not the upstream application OpenAPI. After the first local run, a privacy check found a local MySQL credential URL in upstream `prisma/.env`; the evaluation archive now omits that one non-source file. The 19 code expectations and selected commit did not change. Raw acquisition and sanitized evaluation archive hashes are separate in `expectations.json`.

| # | Method | Decorator-local path | Controller line | Swagger Bearer class line | Middleware evidence | Auth conclusion |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | GET | `/articles` | `src/article/article.controller.ts:24` | `src/article/article.controller.ts:15` | `none in module map` | unknown enforcement |
| 2 | GET | `/articles/feed` | `src/article/article.controller.ts:33` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:24` | unknown enforcement |
| 3 | GET | `/articles/{slug}` | `src/article/article.controller.ts:38` | `src/article/article.controller.ts:15` | `none in module map` | unknown enforcement |
| 4 | GET | `/articles/{slug}/comments` | `src/article/article.controller.ts:43` | `src/article/article.controller.ts:15` | `none in module map` | unknown enforcement |
| 5 | POST | `/articles` | `src/article/article.controller.ts:51` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:25` | unknown enforcement |
| 6 | PUT | `/articles/{slug}` | `src/article/article.controller.ts:59` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:27` | unknown enforcement |
| 7 | DELETE | `/articles/{slug}` | `src/article/article.controller.ts:68` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:26` | unknown enforcement |
| 8 | POST | `/articles/{slug}/comments` | `src/article/article.controller.ts:76` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:28` | unknown enforcement |
| 9 | DELETE | `/articles/{slug}/comments/{id}` | `src/article/article.controller.ts:84` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:29` | unknown enforcement |
| 10 | POST | `/articles/{slug}/favorite` | `src/article/article.controller.ts:93` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:30` | unknown enforcement |
| 11 | DELETE | `/articles/{slug}/favorite` | `src/article/article.controller.ts:101` | `src/article/article.controller.ts:15` | `src/article/article.module.ts:31` | unknown enforcement |
| 12 | GET | `/profiles/{username}` | `src/profile/profile.controller.ts:18` | `src/profile/profile.controller.ts:11` | `none in module map` | unknown enforcement |
| 13 | POST | `/profiles/{username}/follow` | `src/profile/profile.controller.ts:23` | `src/profile/profile.controller.ts:11` | `src/profile/profile.module.ts:22` | unknown enforcement |
| 14 | DELETE | `/profiles/{username}/follow` | `src/profile/profile.controller.ts:28` | `src/profile/profile.controller.ts:11` | `src/profile/profile.module.ts:22` | unknown enforcement |
| 15 | GET | `/user` | `src/user/user.controller.ts:21` | `src/user/user.controller.ts:14` | `src/user/user.module.ts:20` | unknown enforcement |
| 16 | PUT | `/user` | `src/user/user.controller.ts:26` | `src/user/user.controller.ts:14` | `src/user/user.module.ts:20` | unknown enforcement |
| 17 | POST | `/users` | `src/user/user.controller.ts:32` | `src/user/user.controller.ts:14` | `none in module map` | unknown enforcement |
| 18 | DELETE | `/users/{slug}` | `src/user/user.controller.ts:37` | `src/user/user.controller.ts:14` | `none in module map` | unknown enforcement |
| 19 | POST | `/users/login` | `src/user/user.controller.ts:43` | `src/user/user.controller.ts:14` | `none in module map` | unknown enforcement |

All 19 route/method pairs are static local decorator facts to check. Class `@ApiBearerAuth` is Swagger documentation, not a guard. None of these controllers declares `@UseGuards`, `@Public`, or `@Roles`. `src/article/article.module.ts:20-32`, `src/profile/profile.module.ts:18-23`, and `src/user/user.module.ts:16-21` install AuthMiddleware for selected routes; static middleware execution and JWT enforcement are not inferred. The explicit evaluation auth mapping is empty. Therefore authorization mismatch is **not evaluable** from this snapshot with the current analyzer; a diagnostic claiming proven anonymous access would be false.

`GET /tags` (`src/tag/tag.controller.ts:17`) and `GET /` (`src/app.controller.ts:5`) are evaluation-out by the predeclared scope. A source result may include them, but they are not counted in the 19-operation denominator. No existing static OpenAPI file is in this snapshot; runtime Swagger generation is not run. The reference/example app is not evidence of a production deployment. `package.json` declares SPDX ISC; no separate LICENSE file exists in this commit.
