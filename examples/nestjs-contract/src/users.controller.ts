import {
  Controller as HttpController,
  Delete,
  Get as Read,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { BaseController } from '@app/base.controller';
import { Public, Roles } from '@app/decorators';
import { JwtAuthGuard, UnknownGuard } from '@app/guards';

const API_ROOT = 'users';
const DETAILS = 'details';
declare function runtimeRoute(): string;
const DYNAMIC_ROUTE = runtimeRoute();

@HttpController(API_ROOT)
@UseGuards(JwtAuthGuard)
export class UsersController extends BaseController {
  @Read(':id')
  @Public()
  read(): void {}

  @Post()
  @Roles('writer')
  create(): void {}

  @Patch(DETAILS)
  @UseGuards(UnknownGuard)
  update(): void {}

  @Delete(':id')
  remove(): void {}

  @Read('duplicate')
  duplicateOne(): void {}

  @Read('duplicate')
  duplicateTwo(): void {}

  @Read(DYNAMIC_ROUTE)
  dynamic(): void {}
}
