import { execFileSync } from 'node:child_process';
import path from 'node:path';

interface PythonAdapterResult {
  testFiles: string[];
  diagnostics: string[];
}

export function findRelatedPythonTests(
  analyzerRepositoryRoot: string,
  targetRepositoryRoot: string,
  projectRoot: string,
  changedPaths: string[],
): PythonAdapterResult {
  const adapterPath = path.join(
    analyzerRepositoryRoot,
    'ci',
    'impact',
    'adapters',
    'python.py',
  );
  try {
    const output = execFileSync('python3', [adapterPath], {
      input: JSON.stringify({
        repositoryRoot: targetRepositoryRoot,
        projectRoot,
        changedPaths,
      }),
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const parsed = JSON.parse(output) as Partial<PythonAdapterResult>;
    if (!Array.isArray(parsed.testFiles) || !Array.isArray(parsed.diagnostics)) {
      throw new Error('adapter result does not satisfy its JSON contract');
    }
    return {
      testFiles: parsed.testFiles.filter((value): value is string => typeof value === 'string'),
      diagnostics: parsed.diagnostics.filter((value): value is string => typeof value === 'string'),
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return { testFiles: [], diagnostics: [`python adapter failed: ${message}`] };
  }
}
