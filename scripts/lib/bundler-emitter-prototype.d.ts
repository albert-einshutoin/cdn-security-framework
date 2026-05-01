export type BundlerEmitterPrototypeLoader = 'js' | 'ts';
export type BundlerEmitterPrototypeOptions = {
    source: string;
    configExports: Record<string, unknown>;
    sourcefile?: string;
    loader?: BundlerEmitterPrototypeLoader;
    configModuleName?: string;
};
export type BundlerEmitterPrototypeResult = {
    code: string;
    configNames: string[];
};
export declare function assertNoConfigBindingShadow(source: string, configNames: string[], options?: {
    loader?: BundlerEmitterPrototypeLoader;
    configModuleName?: string;
}): void;
export declare function assertBundledConfigBindings(code: string, configNames: string[]): void;
export declare function buildBundlerEmitterPrototype(options: BundlerEmitterPrototypeOptions): Promise<BundlerEmitterPrototypeResult>;
