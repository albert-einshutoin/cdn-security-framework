import { type SourceAnalyzerPlugin } from '../../source-analysis';
export { validateNestJsAuthConfig } from './auth-config';
export declare function createNestJsSourceAnalyzer(config?: unknown): SourceAnalyzerPlugin;
export declare const nestJsSourceAnalyzer: SourceAnalyzerPlugin;
