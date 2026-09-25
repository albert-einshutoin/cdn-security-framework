import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import Ajv from 'ajv';
import * as yaml from 'js-yaml';

import { validateNestJsAuthConfig, type NestJsAuthConfig } from '../../source/nestjs/auth-config';

const MAX_FILE_BYTES = 64 * 1024;
const INVALID = 'invalid Source auth config';

export interface LoadedSourceAuthConfig {
  config: Readonly<NestJsAuthConfig>;
  rawDigest: string;
  textDigest: string;
}

function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative);
}

function sameFile(left: fs.BigIntStats, right: fs.BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function readSnapshot(workspaceRoot: string, inputPath: string): Buffer {
  const workspacePath = path.resolve(workspaceRoot);
  const candidate = path.resolve(workspacePath, inputPath);
  if (!within(workspacePath, candidate)) throw new Error(INVALID);
  const root = fs.realpathSync(workspacePath);
  if (!fs.statSync(root).isDirectory()) throw new Error(INVALID);
  const resolved = fs.realpathSync(candidate);
  if (!within(root, resolved)) throw new Error(INVALID);

  let descriptor: number | undefined;
  try {
    // Opening the resolved target permits workspace-local symlinks, while O_NOFOLLOW
    // prevents a last-component swap on the target itself.
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size > BigInt(MAX_FILE_BYTES)) throw new Error(INVALID);
    const openedPath = fs.realpathSync(candidate);
    const openedStat = fs.statSync(openedPath, { bigint: true });
    if (openedPath !== resolved || !within(root, openedPath) || !sameFile(before, openedStat)) {
      throw new Error(INVALID);
    }

    const buffer = Buffer.allocUnsafe(MAX_FILE_BYTES + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      const read = fs.readSync(descriptor, buffer, bytes, buffer.length - bytes, null);
      if (read === 0) break;
      bytes += read;
    }
    if (bytes > MAX_FILE_BYTES) throw new Error(INVALID);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const finalPath = fs.realpathSync(candidate);
    const finalStat = fs.statSync(finalPath, { bigint: true });
    if (finalPath !== resolved || !within(root, finalPath) || !sameFile(after, finalStat)
      || !sameFile(before, after) || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      throw new Error(INVALID);
    }
    return buffer.subarray(0, bytes);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

let validateSchema: ((value: unknown) => boolean) | undefined;
function schemaValid(value: unknown): boolean {
  if (!validateSchema) {
    const compiled = path.join(__dirname, '..', '..', 'schemas', 'nestjs-source-analysis-options.schema.json');
    const source = path.join(__dirname, '..', '..', '..', 'schemas', 'nestjs-source-analysis-options.schema.json');
    const schema = JSON.parse(fs.readFileSync(fs.existsSync(compiled) ? compiled : source, 'utf8')) as object;
    validateSchema = new Ajv({ strict: true }).compile(schema);
  }
  return validateSchema(value);
}

export function loadSourceAuthConfig(options: { workspaceRoot: string; inputPath: string }): LoadedSourceAuthConfig {
  if (!options || typeof options.workspaceRoot !== 'string' || !options.workspaceRoot.trim()
    || typeof options.inputPath !== 'string' || !options.inputPath.trim()
    || !/\.(?:ya?ml|json)$/iu.test(options.inputPath)) throw new Error(INVALID);
  try {
    const bytes = readSnapshot(options.workspaceRoot, options.inputPath);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    // JSON_SCHEMA has no executable tags or merge construction. Zero aliases and
    // bounded depth are enforced before schema validation or config use.
    const yamlValue = yaml.load(text, {
      schema: yaml.JSON_SCHEMA, json: false, maxAliases: 0, maxDepth: 16,
    });
    const parsed = /\.json$/iu.test(options.inputPath) ? JSON.parse(text) as unknown : yamlValue;
    if (!schemaValid(parsed)) throw new Error(INVALID);
    const config = validateNestJsAuthConfig(parsed);
    const digest = (value: Buffer | string) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
    return Object.freeze({ config, rawDigest: digest(bytes), textDigest: digest(text) });
  } catch {
    throw new Error(INVALID);
  }
}
