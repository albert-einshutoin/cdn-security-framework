type PathRegexGroup = { required: string; sources: string[] };

function requiredLiteral(source: string): string {
  // Only a plain, case-sensitive leading literal is proven here. Alternatives
  // and flags keep the same regex evaluation without a precondition.
  if (source.startsWith('(?i)') || source.includes('|')) return '';
  const start = source.startsWith('^') ? 1 : 0;
  let end = start;
  while (end < source.length && /[A-Za-z0-9_/-]/.test(source[end])) end++;
  let prefix = source.slice(start, end);
  // A quantifier can make the final literal optional; the preceding bytes remain required.
  if (['?', '*', '{'].includes(source[end])) prefix = prefix.slice(0, -1);
  return prefix;
}

export function groupPathRegexes(sources: string[]): PathRegexGroup[] {
  const groups: PathRegexGroup[] = [];
  for (const source of sources) {
    const required = requiredLiteral(source), previous = groups.at(-1);
    let common = 0;
    if (previous) while (common < previous.required.length && common < required.length && previous.required[common] === required[common]) common++;
    if (previous && (common >= 3 || (!previous.required && !required))) {
      previous.required = required.slice(0, common); previous.sources.push(source);
    } else groups.push({ required: required.length >= 3 ? required : '', sources: [source] });
  }
  return groups;
}
