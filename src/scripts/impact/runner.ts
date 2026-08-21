import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import Ajv, { type AnySchema } from 'ajv';

import type { CommandConfig, ImpactConfig } from './core';
import type { AnalysisResult } from './result';

export interface MaterializedCommand {
  id: string;
  category: CommandConfig['category'];
  command: string;
  args: string[];
  resourceLocks: string[];
  always: boolean;
}

export interface TargetExecutionResult {
  id: string;
  category: CommandConfig['category'];
  status: 'passed' | 'failed' | 'skipped';
  exitCode: number | null;
  durationMs: number;
}

export interface ExecutionReport {
  schemaVersion: 1;
  strategy: AnalysisResult['strategy'];
  baseRevision: string;
  headRevision: string;
  startedAt: string;
  finishedAt: string;
  wallClockMs: number;
  totalComputeMs: number;
  estimatedCost: number | null;
  targetCount: number;
  successCount: number;
  failureCount: number;
  skippedCount: number;
  targets: TargetExecutionResult[];
}

function replacePlaceholders(value: string, revisions: { baseRevision: string; headRevision: string }): string {
  let replaced = value;
  for (const [placeholder, revision] of [
    ['{baseRevision}', revisions.baseRevision],
    ['{headRevision}', revisions.headRevision],
  ] as const) {
    if (replaced.includes(placeholder)) {
      if (!/^[0-9a-f]{40}$/u.test(revision)) {
        throw new Error(`unsafe revision for ${placeholder}: ${revision}`);
      }
      replaced = replaced.replaceAll(placeholder, revision);
    }
  }
  if (/\{[^}]+\}/u.test(replaced)) throw new Error(`unknown command placeholder in argument: ${value}`);
  if (replaced.includes('\0')) throw new Error('command arguments must not contain NUL bytes');
  return replaced;
}

export function materializeCommand(
  command: CommandConfig,
  revisions: { baseRevision: string; headRevision: string },
): MaterializedCommand {
  if (!/^[A-Za-z0-9._+-]+$/u.test(command.command)) {
    throw new Error(`unsafe executable for target ${command.id}: ${command.command}`);
  }
  return {
    id: command.id,
    category: command.category,
    command: command.command,
    args: command.args.map((argument) => replacePlaceholders(argument, revisions)),
    resourceLocks: command.resourceLocks ?? [],
    always: command.always ?? false,
  };
}

function executeTarget(repositoryRoot: string, target: MaterializedCommand): Promise<TargetExecutionResult> {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    console.log(`\n[impact] START ${target.id}: ${target.command} ${target.args.join(' ')}`);
    const child = spawn(target.command, target.args, {
      cwd: repositoryRoot,
      env: process.env,
      shell: false,
      stdio: 'inherit',
    });
    child.on('error', (error) => {
      const durationMs = Number(process.hrtime.bigint() - started) / 1_000_000;
      console.error(`[impact] FAIL ${target.id}: ${error.message}`);
      resolve({ id: target.id, category: target.category, status: 'failed', exitCode: null, durationMs });
    });
    child.on('exit', (code) => {
      const durationMs = Number(process.hrtime.bigint() - started) / 1_000_000;
      const status = code === 0 ? 'passed' : 'failed';
      console.log(`[impact] ${status === 'passed' ? 'PASS' : 'FAIL'} ${target.id} (${durationMs.toFixed(0)} ms)`);
      resolve({ id: target.id, category: target.category, status, exitCode: code, durationMs });
    });
  });
}

async function executeBounded(
  repositoryRoot: string,
  targets: MaterializedCommand[],
  maxParallel: number,
): Promise<TargetExecutionResult[]> {
  const pending = [...targets];
  const results: TargetExecutionResult[] = [];
  const activeLocks = new Set<string>();
  let active = 0;

  return await new Promise((resolve) => {
    const schedule = (): void => {
      while (active < maxParallel && pending.length > 0) {
        const runnableIndex = pending.findIndex((target) =>
          target.resourceLocks.every((lock) => !activeLocks.has(lock)),
        );
        if (runnableIndex < 0) break;
        const [target] = pending.splice(runnableIndex, 1);
        if (!target) break;
        active += 1;
        for (const lock of target.resourceLocks) activeLocks.add(lock);
        void executeTarget(repositoryRoot, target).then((result) => {
          results.push(result);
          active -= 1;
          for (const lock of target.resourceLocks) activeLocks.delete(lock);
          if (pending.length === 0 && active === 0) resolve(results);
          else schedule();
        });
      }
      if (pending.length === 0 && active === 0) resolve(results);
    };
    schedule();
  });
}

export async function runExecutionPlan(
  repositoryRoot: string,
  config: ImpactConfig,
  analysis: AnalysisResult,
): Promise<ExecutionReport> {
  if (analysis.strategy === 'failure') throw new Error('analysis did not produce a safe execution plan');
  const commandById = new Map(config.commands.map((command) => [command.id, command]));
  const targets = analysis.executionPlan.map((targetId) => {
    const configured = commandById.get(targetId);
    if (!configured) throw new Error(`analysis references unknown target: ${targetId}`);
    return materializeCommand(configured, analysis);
  });
  const startedAt = new Date();
  const started = process.hrtime.bigint();
  const results: TargetExecutionResult[] = [];

  const prerequisiteTargets = targets.filter((target) => target.always || target.category === 'full');
  const selectiveTargets = targets.filter((target) => !prerequisiteTargets.includes(target));
  let prerequisiteFailed = false;
  for (const target of prerequisiteTargets) {
    const result = await executeTarget(repositoryRoot, target);
    results.push(result);
    if (result.status === 'failed') {
      prerequisiteFailed = true;
      break;
    }
  }
  if (prerequisiteFailed) {
    for (const target of selectiveTargets) {
      results.push({
        id: target.id,
        category: target.category,
        status: 'skipped',
        exitCode: null,
        durationMs: 0,
      });
    }
  } else if (selectiveTargets.length > 0) {
    results.push(...(await executeBounded(repositoryRoot, selectiveTargets, config.maxParallel)));
  }

  const wallClockMs = Number(process.hrtime.bigint() - started) / 1_000_000;
  const totalComputeMs = results.reduce((total, result) => total + result.durationMs, 0);
  const costPerMinute = Number.parseFloat(process.env.CI_COST_PER_MINUTE ?? '');
  return {
    schemaVersion: 1,
    strategy: analysis.strategy,
    baseRevision: analysis.baseRevision,
    headRevision: analysis.headRevision,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    wallClockMs,
    totalComputeMs,
    estimatedCost: Number.isFinite(costPerMinute) ? (wallClockMs / 60_000) * costPerMinute : null,
    targetCount: results.length,
    successCount: results.filter((result) => result.status === 'passed').length,
    failureCount: results.filter((result) => result.status === 'failed').length,
    skippedCount: results.filter((result) => result.status === 'skipped').length,
    targets: results,
  };
}

export function writeExecutionReport(
  repositoryRoot: string,
  outputPath: string,
  report: ExecutionReport,
): void {
  const schema = JSON.parse(
    readFileSync(path.join(repositoryRoot, 'ci', 'impact', 'schema', 'execution.schema.json'), 'utf8'),
  ) as AnySchema;
  const validate = new Ajv({ allErrors: true, strict: true }).compile(schema);
  if (!validate(report)) {
    const details = validate.errors
      ?.map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
      .join('; ');
    throw new Error(`execution report does not match its schema: ${details ?? 'unknown error'}`);
  }
  const absoluteOutput = path.resolve(repositoryRoot, outputPath);
  mkdirSync(path.dirname(absoluteOutput), { recursive: true });
  writeFileSync(absoluteOutput, `${JSON.stringify(report, null, 2)}\n`);
  appendFileSync(path.join(path.dirname(absoluteOutput), 'history.ndjson'), `${JSON.stringify(report)}\n`);
}
