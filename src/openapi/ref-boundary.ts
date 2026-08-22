import fs from 'node:fs';
import path from 'node:path';

import { OpenApiAnalysisError } from './analysis-error';

export type PathFlavor = 'native' | 'posix' | 'win32';

function pathImplementation(flavor: PathFlavor): typeof path.posix {
  if (flavor === 'posix') return path.posix;
  if (flavor === 'win32') return path.win32;
  return path;
}

export function isPathWithinWorkspace(
  workspaceRoot: string,
  candidatePath: string,
  flavor: PathFlavor = 'native',
): boolean {
  const implementation = pathImplementation(flavor);
  const relative = implementation.relative(
    implementation.resolve(workspaceRoot),
    implementation.resolve(candidatePath),
  );
  return relative === ''
    || (!relative.startsWith(`..${implementation.sep}`)
      && relative !== '..'
      && !implementation.isAbsolute(relative));
}

export interface ResolveOpenApiRefPathOptions {
  workspaceRoot: string;
  sourcePath: string;
  ref: string;
  realpath?: (inputPath: string) => string;
}

export function resolveOpenApiRefPath(options: ResolveOpenApiRefPathOptions): string {
  const { workspaceRoot, sourcePath, ref } = options;
  const realpath = options.realpath ?? fs.realpathSync;
  if (/^https?:\/\//i.test(ref)) {
    throw new OpenApiAnalysisError('OPENAPI_REMOTE_REF_DISABLED', { sourceUri: sourcePath });
  }
  const refPath = ref.split('#', 1)[0];
  if (/^file:/i.test(refPath)
    || path.isAbsolute(refPath)
    || path.win32.isAbsolute(refPath)) {
    throw new OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(refPath)) {
    throw new OpenApiAnalysisError('OPENAPI_REMOTE_REF_DISABLED', { sourceUri: sourcePath });
  }

  let rootRealPath: string;
  let sourceRealPath: string;
  try {
    rootRealPath = realpath(workspaceRoot);
    sourceRealPath = realpath(sourcePath);
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri: sourcePath });
  }
  if (!isPathWithinWorkspace(rootRealPath, sourceRealPath)) {
    throw new OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
  }

  const lexicalCandidate = refPath
    ? path.resolve(path.dirname(sourceRealPath), refPath)
    : sourceRealPath;
  if (!isPathWithinWorkspace(rootRealPath, lexicalCandidate)) {
    throw new OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
  }

  let candidateRealPath: string;
  try {
    candidateRealPath = realpath(lexicalCandidate);
  } catch {
    throw new OpenApiAnalysisError('OPENAPI_INPUT_NOT_FOUND', { sourceUri: lexicalCandidate });
  }
  if (!isPathWithinWorkspace(rootRealPath, candidateRealPath)) {
    throw new OpenApiAnalysisError('OPENAPI_REF_OUTSIDE_ROOT', { sourceUri: sourcePath });
  }
  return candidateRealPath;
}
