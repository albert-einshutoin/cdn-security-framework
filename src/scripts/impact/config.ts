import { readFileSync } from 'node:fs';
import path from 'node:path';

import Ajv, { type AnySchema } from 'ajv';

import type { ImpactConfig } from './core';

function readJson(filePath: string): unknown {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8')) as unknown;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`failed to parse ${filePath}: ${message}`);
  }
}

function assertUniqueIds(values: Array<{ id: string }>, label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value.id)) throw new Error(`duplicate ${label} id: ${value.id}`);
    seen.add(value.id);
  }
}

/**
 * Configuration is assembled from small concern-specific JSON files so CI
 * providers only consume the resulting plan. Semantic checks are performed
 * after JSON Schema validation because dangling command/module references are
 * unsafe even when each file is structurally valid on its own.
 */
export function loadImpactConfig(repositoryRoot: string): ImpactConfig {
  const configRoot = path.join(repositoryRoot, 'ci', 'impact', 'config');
  const settings = readJson(path.join(configRoot, 'project-settings.json')) as Record<string, unknown>;
  const combined: unknown = {
    ...settings,
    riskRules: readJson(path.join(configRoot, 'risk-rules.json')),
    modules: readJson(path.join(configRoot, 'module-mappings.json')),
    commands: readJson(path.join(configRoot, 'smoke-tests.json')),
    testMappings: readJson(path.join(configRoot, 'test-mappings.json')),
  };

  const schemaPath = path.join(repositoryRoot, 'ci', 'impact', 'schema', 'config.schema.json');
  const schema = readJson(schemaPath);
  const ajv = new Ajv({ allErrors: true, strict: true });
  const validate = ajv.compile(schema as AnySchema);
  if (!validate(combined)) {
    const details = validate.errors
      ?.map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
      .join('; ');
    throw new Error(`invalid impact configuration: ${details ?? 'unknown schema error'}`);
  }

  const config = combined as ImpactConfig;
  assertUniqueIds(config.riskRules, 'risk rule');
  assertUniqueIds(config.modules, 'module');
  assertUniqueIds(config.commands, 'command');
  assertUniqueIds(config.testMappings, 'test mapping');

  const commandIds = new Set(config.commands.map((command) => command.id));
  if (!config.fullTargetId || !commandIds.has(config.fullTargetId)) {
    throw new Error(`full validation target is not defined: ${config.fullTargetId ?? '<missing>'}`);
  }
  for (const smokeTargetId of config.smokeTargetIds ?? []) {
    if (!commandIds.has(smokeTargetId)) {
      throw new Error(`smoke target is not defined: ${smokeTargetId}`);
    }
  }
  for (const mapping of config.testMappings) {
    for (const targetId of mapping.targetIds) {
      if (!commandIds.has(targetId)) {
        throw new Error(`test mapping ${mapping.id} references unknown target: ${targetId}`);
      }
    }
  }

  const moduleIds = new Set(config.modules.map((moduleRule) => moduleRule.id));
  for (const moduleRule of config.modules) {
    for (const dependency of moduleRule.dependsOn) {
      if (!moduleIds.has(dependency)) {
        throw new Error(`module ${moduleRule.id} depends on unknown module: ${dependency}`);
      }
    }
  }

  // These rules protect the selector itself. Keeping their presence mandatory
  // prevents an innocent config edit from silently disabling the safety net.
  for (const requiredRuleId of ['impact-engine', 'dependency-definition']) {
    if (!config.riskRules.some((rule) => rule.id === requiredRuleId)) {
      throw new Error(`required risk rule is missing: ${requiredRuleId}`);
    }
  }

  return config;
}
