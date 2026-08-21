import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import ts from 'typescript';

const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

function normalize(value: string): string {
  return value.replaceAll('\\', '/').replace(/^\.\//u, '');
}

function walkSourceFiles(repositoryRoot: string): string[] {
  const ignored = new Set(['.git', 'node_modules', 'dist', 'coverage', 'reports', '__pycache__']);
  const files: string[] = [];
  function visit(absoluteDirectory: string): void {
    for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const absoluteEntry = path.join(absoluteDirectory, entry.name);
      if (entry.isDirectory()) {
        if (!ignored.has(entry.name)) visit(absoluteEntry);
        continue;
      }
      if (SOURCE_EXTENSIONS.includes(path.extname(entry.name))) {
        files.push(normalize(path.relative(repositoryRoot, absoluteEntry)));
      }
    }
  }
  visit(repositoryRoot);
  return files.sort();
}

function resolveRelativeImport(
  repositoryRoot: string,
  importer: string,
  specifier: string,
): string | null {
  const relativeBase = normalize(path.join(path.dirname(importer), specifier));
  const candidates = [
    relativeBase,
    ...SOURCE_EXTENSIONS.map((extension) => `${relativeBase}${extension}`),
    ...SOURCE_EXTENSIONS.map((extension) => `${relativeBase}/index${extension}`),
  ];
  for (const candidate of candidates) {
    const absoluteCandidate = path.resolve(repositoryRoot, candidate);
    const relativeCandidate = normalize(path.relative(repositoryRoot, absoluteCandidate));
    if (relativeCandidate.startsWith('../') || path.isAbsolute(relativeCandidate)) continue;
    if (existsSync(absoluteCandidate) && statSync(absoluteCandidate).isFile()) return relativeCandidate;
  }
  return null;
}

function isTestFile(filePath: string): boolean {
  return (
    /(^|\/)src\/scripts\/.*-tests\.[cm]?[jt]sx?$/u.test(filePath) ||
    /(^|\/)(test|tests)\/.*\.(test|spec)\.[cm]?[jt]sx?$/u.test(filePath)
  );
}

/**
 * TypeScript's preprocessor is used instead of path-only guesses so a changed
 * module selects tests through reverse import edges. Unresolved relative
 * imports in a changed file are diagnostics because continuing would risk a
 * false-negative test selection.
 */
export function findRelatedJavaScriptTests(
  repositoryRoot: string,
  changedPaths: string[],
): { testFiles: string[]; diagnostics: string[] } {
  const files = walkSourceFiles(repositoryRoot);
  const fileSet = new Set(files);
  const reverseDependencies = new Map<string, Set<string>>();
  const unresolvedByFile = new Map<string, string[]>();

  for (const file of files) {
    let source: string;
    try {
      source = readFileSync(path.join(repositoryRoot, file), 'utf8');
    } catch (error: unknown) {
      if (changedPaths.includes(file)) {
        const message = error instanceof Error ? error.message : String(error);
        unresolvedByFile.set(file, [`unable to read changed source: ${message}`]);
      }
      continue;
    }
    const imports = ts.preProcessFile(source, true, true).importedFiles;
    for (const imported of imports) {
      if (!imported.fileName.startsWith('.')) continue;
      const resolved = resolveRelativeImport(repositoryRoot, file, imported.fileName);
      if (!resolved || !fileSet.has(resolved)) {
        const unresolved = unresolvedByFile.get(file) ?? [];
        unresolved.push(imported.fileName);
        unresolvedByFile.set(file, unresolved);
        continue;
      }
      const importers = reverseDependencies.get(resolved) ?? new Set<string>();
      importers.add(file);
      reverseDependencies.set(resolved, importers);
    }
  }

  const diagnostics: string[] = [];
  const queue: string[] = [];
  const visited = new Set<string>();
  for (const changedPath of changedPaths.map(normalize)) {
    if (!SOURCE_EXTENSIONS.includes(path.extname(changedPath))) continue;
    if (!fileSet.has(changedPath)) {
      diagnostics.push(`changed JavaScript/TypeScript source is unavailable: ${changedPath}`);
      continue;
    }
    const unresolved = unresolvedByFile.get(changedPath);
    if (unresolved && unresolved.length > 0) {
      diagnostics.push(`unresolved imports in ${changedPath}: ${unresolved.join(', ')}`);
    }
    queue.push(changedPath);
    visited.add(changedPath);
  }

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;
    for (const importer of reverseDependencies.get(current) ?? []) {
      if (visited.has(importer)) continue;
      visited.add(importer);
      queue.push(importer);
    }
  }

  return {
    testFiles: [...visited].filter(isTestFile).sort(),
    diagnostics: [...new Set(diagnostics)].sort(),
  };
}
