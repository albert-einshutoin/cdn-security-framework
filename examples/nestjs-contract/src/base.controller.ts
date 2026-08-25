import { Get } from '@nestjs/common';

export abstract class BaseController {
  @Get('inherited')
  inherited(): void {}
}
