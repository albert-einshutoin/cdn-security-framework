import { assertSupportedNode } from '../../lib/node-engine';
assertSupportedNode(require.main === module);

export { createNestJsSourceAnalyzer, nestJsSourceAnalyzer } from './analyzer';
export {
  EMPTY_NESTJS_AUTH_CONFIG,
  NESTJS_AUTH_KINDS,
  validateNestJsAuthConfig,
  type NestJsAuthConfig,
  type NestJsAuthKind,
} from './auth-config';
