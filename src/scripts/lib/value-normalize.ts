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

export function normalizeStringList(raw: unknown, casing: StringCase = 'preserve'): string[] {
  if (!Array.isArray(raw)) return [];

  return raw
    .map((s) => (typeof s === 'string' ? s.trim() : ''))
    .map((s) => applyStringCase(s, casing))
    .filter(Boolean);
}
