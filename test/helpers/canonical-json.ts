const MAX_CANONICAL_DEPTH = 256;
const MAX_CANONICAL_NODES = 1_000_000;
const MAX_CANONICAL_STRING_LENGTH = 1024 * 1024;

interface CanonicalState { nodes: number }

function normalize(
  value: unknown,
  ancestors: Set<object>,
  setKeys: ReadonlySet<string>,
  state: CanonicalState,
  depth: number,
  propertyKey?: string,
): unknown {
  state.nodes += 1;
  if (state.nodes > MAX_CANONICAL_NODES) throw new Error('canonical JSON exceeds node limit');
  if (depth > MAX_CANONICAL_DEPTH) throw new Error('canonical JSON exceeds depth limit');
  if (typeof value === 'string') {
    if (value.length > MAX_CANONICAL_STRING_LENGTH) throw new Error('canonical JSON exceeds string limit');
    return value.replace(/\r\n?/g, '\n');
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical JSON requires finite numbers');
    return value;
  }
  if (typeof value !== 'object') throw new Error('canonical JSON contains unsupported value');
  if (ancestors.has(value)) throw new Error('canonical JSON contains circular value');

  ancestors.add(value);
  let output: unknown;
  if (Array.isArray(value)) {
    if (value.length > MAX_CANONICAL_NODES - state.nodes) {
      throw new Error('canonical JSON exceeds node limit');
    }
    const items = Array.from({ length: value.length }, (_, index) => {
      if (!Object.prototype.hasOwnProperty.call(value, index)) {
        throw new Error('canonical JSON rejects sparse arrays');
      }
      return normalize(value[index], ancestors, setKeys, state, depth + 1);
    });
    output = setKeys.has(propertyKey ?? '')
      ? [...new Map(items.map((item) => [JSON.stringify(item), item])).entries()]
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([, item]) => item)
      : items;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error('canonical JSON requires plain objects');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    output = Object.fromEntries(Object.keys(descriptors).sort().map((key) => {
      if (key.length > MAX_CANONICAL_STRING_LENGTH) throw new Error('canonical JSON exceeds string limit');
      const descriptor = descriptors[key];
      if (!('value' in descriptor)) throw new Error('canonical JSON rejects accessors');
      return [key, normalize(descriptor.value, ancestors, setKeys, state, depth + 1, key)];
    }));
  }
  ancestors.delete(value);
  return output;
}

export interface CanonicalJsonOptions {
  setKeys?: readonly string[];
}

export function canonicalJson(value: unknown, options: CanonicalJsonOptions = {}): string {
  return `${JSON.stringify(normalize(
    value,
    new Set<object>(),
    new Set(options.setKeys ?? []),
    { nodes: 0 },
    0,
  ), null, 2)}\n`;
}
