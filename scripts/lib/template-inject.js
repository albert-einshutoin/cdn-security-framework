"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function runtimeCode(code) {
    return { __runtimeCode: code };
}
function isRuntimeLiteral(value) {
    return Boolean(value &&
        typeof value === 'object' &&
        typeof value.__runtimeCode === 'string');
}
function renderValue(value) {
    if (isRuntimeLiteral(value))
        return value.__runtimeCode;
    return JSON.stringify(value);
}
function renderConstObject(name, value) {
    const lines = [`const ${name} = {`];
    for (const [key, entryValue] of Object.entries(value)) {
        lines.push(`  ${key}: ${renderValue(entryValue)},`);
    }
    lines.push('};');
    return lines.join('\n');
}
function injectTemplateCode(template, marker, code) {
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
