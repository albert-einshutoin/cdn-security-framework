export type StringCase = 'lower' | 'upper' | 'preserve';

function applyStringCase(value: string, casing: StringCase): string {
  if (casing === 'lower') return value.toLowerCase();
  if (casing === 'upper') return value.toUpperCase();
  return value;
}

function toFiniteNumber(raw: unknown): number | null {
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

export function clampNumber(raw: unknown, min: number, max: number, fallback: number): number {
  const n = toFiniteNumber(raw);
  return n === null ? fallback : Math.max(min, Math.min(max, n));
}

export function numberOr(raw: unknown, fallback: number): number {
  return Number(raw) || fallback;
}

export interface NormalizeStringListOptions {
  trim?: boolean;
}

export function normalizeStringList(
  raw: unknown,
  casing: StringCase = 'preserve',
  options: NormalizeStringListOptions = {},
): string[] {
  if (!Array.isArray(raw)) return [];
  const trimOutput = options.trim !== false;

  return raw
    .filter((s): s is string => typeof s === 'string' && !!s.trim())
    .map((s) => (trimOutput ? s.trim() : s))
    .map((s) => applyStringCase(s, casing))
    .filter(Boolean);
}
