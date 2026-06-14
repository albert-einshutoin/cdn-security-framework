export type StringCase = 'lower' | 'upper' | 'preserve';
export declare function clampNumber(raw: unknown, min: number, max: number, fallback: number): number;
export declare function numberOr(raw: unknown, fallback: number): number;
export declare function normalizeStringList(raw: unknown, casing?: StringCase): string[];
