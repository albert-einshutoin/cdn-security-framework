export function Controller(path?: string): ClassDecorator;
export function Get(path?: string): MethodDecorator;
export function Post(path?: string): MethodDecorator;
export function Patch(path?: string): MethodDecorator;
export function Delete(path?: string): MethodDecorator;
export function UseGuards(...guards: unknown[]): ClassDecorator & MethodDecorator;
