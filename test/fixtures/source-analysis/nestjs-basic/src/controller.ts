import { Controller as HttpController, Get as Read } from '@nestjs/common';
import * as Nest from '@nestjs/common';

const ROOT = 'users';

abstract class BaseController {
  @Nest.Head('health') health() {}
}

@HttpController(ROOT)
class UsersController extends BaseController {
  @Read(':id') read() {}
  @Nest.Post() create() {}
}
