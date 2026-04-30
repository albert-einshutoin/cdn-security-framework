type RuntimeLiteral = { __runtimeCode: string };

function runtimeCode(code: string): RuntimeLiteral {
  return { __runtimeCode: code };
}

function isRuntimeLiteral(value: unknown): value is RuntimeLiteral {
  return Boolean(
    value &&
      typeof value === 'object' &&
      typeof (value as RuntimeLiteral).__runtimeCode === 'string',
  );
}

function renderValue(value: unknown): string {
  if (isRuntimeLiteral(value)) return value.__runtimeCode;
  return JSON.stringify(value);
}

function renderConstObject(name: string, value: Record<string, unknown>): string {
  const lines = [`const ${name} = {`];
  for (const [key, entryValue] of Object.entries(value)) {
    lines.push(`  ${key}: ${renderValue(entryValue)},`);
  }
  lines.push('};');
  return lines.join('\n');
}

function injectTemplateCode(template: string, marker: string, code: string): string {
  const count = template.split(marker).length - 1;
  if (count !== 1) {
    throw new Error(`Template marker ${marker} must appear exactly once, found ${count}`);
  }
  return template.replace(marker, code);
}

module.exports = {
  injectTemplateCode,
  renderConstObject,
  runtimeCode,
};
