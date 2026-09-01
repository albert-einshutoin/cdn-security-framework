#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const RELEASE_VERSIONS = ['v1.5.0', 'v1.6.0', 'v1.7.0', 'v1.8.0', 'v1.9.0', 'v2.0.0', 'v2.1.0'];
const VERSION_PATTERN = /\bv\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\b/gu;
const CAPABILITY_ROWS = [
  ['OpenAPI inspect', 'Implemented', 'CLI/API', 'local refs only'],
  ['OpenAPI policy candidate', 'Implemented', 'CLI/API', 'review-only; never auto-applied'],
  ['OpenAPI↔Policy drift', 'Implemented', 'CLI/JSON/SARIF/GHA', 'no source needed'],
  ['NestJS Source Analyzer core', 'Experimental/Implemented core', 'Programmatic', 'no app execution; metadata is not enforcement proof'],
  ['Source-aware contract diff CLI', 'Planned v1.6', '—', '—'],
  ['Runtime Evidence v1', 'Planned v1.8', '—', '—'],
  ['Policy Composition', 'Planned v1.9', '—', '—'],
  ['LSP/VS Code', 'Planned v2.1', '—', '—'],
] as const;
const ROADMAP_EN_HEADINGS = [
  '## 1. Product thesis',
  '## 2. Four truths and evidence',
  '## 3. Current release and main status',
  '## 4. Version release train',
  '## 5. Version dependency graph',
  '## 6. Review cadence and release gates',
  '## 7. Status definitions',
  '## 8. Enabling lanes and historical track mapping',
  '## 9. Common release contract',
  '## 10. Status update rules',
];
const ROADMAP_JA_HEADINGS = [
  '## 1. Product thesis',
  '## 2. 4つの Truth と Evidence',
  '## 3. 現行リリースと main の状態',
  '## 4. Version Release Train',
  '## 5. Version dependency graph',
  '## 6. Review cadence と release gate',
  '## 7. Status の定義',
  '## 8. Enabling lane と過去 track の対応',
  '## 9. 共通 release contract',
  '## 10. Status 更新ルール',
];

function read(repoRoot: string, relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function assertIncludes(content: string, expected: string, label: string): void {
  if (!content.includes(expected)) throw new Error(`${label} is missing: ${expected}`);
}

function localLinks(content: string): string[] {
  const links: string[] = [];
  const pattern = /\]\(([^)#\s]+)(?:#[^)]+)?\)/gu;
  for (const match of content.matchAll(pattern)) {
    const target = match[1];
    if (target.startsWith('#') || target.startsWith('/') || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(target)) continue;
    links.push(target);
  }
  return links;
}

function versions(content: string): string[] {
  return [...new Set(content.match(VERSION_PATTERN) ?? [])].sort();
}

function checkLocalLinks(repoRoot: string, relativePath: string, content: string): void {
  for (const target of localLinks(content)) {
    const targetPath = path.resolve(path.dirname(path.join(repoRoot, relativePath)), target);
    if (!fs.existsSync(targetPath)) throw new Error(`${relativePath} links to missing file: ${target}`);
  }
}

function checkCapabilityTable(content: string, label: string): void {
  const marker = '### Capability status';
  const start = content.indexOf(marker);
  if (start < 0) throw new Error(`${label} is missing: ${marker}`);
  const afterMarker = content.slice(start + marker.length);
  const nextSection = afterMarker.search(/\n## /u);
  const section = nextSection < 0 ? afterMarker : afterMarker.slice(0, nextSection);
  const rows = [...section.matchAll(/^\| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$/gmu)]
    .filter((match) => match[1] !== 'Capability' && match[1] !== '---');
  if (rows.length !== CAPABILITY_ROWS.length) {
    throw new Error(`${label} capability row count is ${rows.length}; expected ${CAPABILITY_ROWS.length}`);
  }
  for (const [capability, status, interfaceName, limit] of CAPABILITY_ROWS) {
    if (!rows.some((row) => row[1] === capability
      && row[2] === status
      && row[3] === interfaceName
      && row[4] === limit)) {
      throw new Error(`${label} capability row is missing or changed: ${capability} / ${status} / ${interfaceName} / ${limit}`);
    }
  }
}

export function checkDocsSync(repoRoot: string): void {
  const roadmapEn = read(repoRoot, 'docs/ROADMAP.md');
  const roadmapJa = read(repoRoot, 'docs/ROADMAP.ja.md');
  const readmeEn = read(repoRoot, 'README.md');
  const readmeJa = read(repoRoot, 'README.ja.md');
  const architectureEn = read(repoRoot, 'docs/architecture.md');
  const architectureJa = read(repoRoot, 'docs/architecture.ja.md');

  for (const heading of ROADMAP_EN_HEADINGS) assertIncludes(roadmapEn, heading, 'English roadmap heading');
  for (const heading of ROADMAP_JA_HEADINGS) assertIncludes(roadmapJa, heading, 'Japanese roadmap heading');
  for (const version of RELEASE_VERSIONS) {
    assertIncludes(roadmapEn, version, `English roadmap version ${version}`);
    assertIncludes(roadmapJa, version, `Japanese roadmap version ${version}`);
  }
  if (JSON.stringify(versions(roadmapEn)) !== JSON.stringify(versions(roadmapJa))) {
    throw new Error(`English/Japanese roadmap version sets differ: ${versions(roadmapEn).join(',')} != ${versions(roadmapJa).join(',')}`);
  }
  if (/^## Track [A-G]:/mu.test(roadmapEn) || /^## Track [A-G]:/mu.test(roadmapJa)) {
    throw new Error('legacy Track A-G headings must not be canonical roadmap sections');
  }
  for (const [relativePath, content] of [
    ['docs/ROADMAP.md', roadmapEn],
    ['docs/ROADMAP.ja.md', roadmapJa],
    ['README.md', readmeEn],
    ['README.ja.md', readmeJa],
    ['docs/architecture.md', architectureEn],
    ['docs/architecture.ja.md', architectureJa],
  ] as const) checkLocalLinks(repoRoot, relativePath, content);
  assertIncludes(readmeEn, './docs/ROADMAP.md', 'English README roadmap link');
  assertIncludes(readmeJa, './docs/ROADMAP.ja.md', 'Japanese README roadmap link');
  assertIncludes(architectureEn, './ROADMAP.md', 'English architecture roadmap link');
  assertIncludes(architectureJa, './ROADMAP.ja.md', 'Japanese architecture roadmap link');
  for (const [label, content] of [
    ['English README', readmeEn],
    ['Japanese README', readmeJa],
    ['English architecture', architectureEn],
    ['Japanese architecture', architectureJa],
  ] as const) {
    assertIncludes(content, 'Application-aware Edge Security Compiler', `${label} product positioning`);
    checkCapabilityTable(content, label);
  }
  assertIncludes(roadmapEn, 'Implemented', 'English implementation status');
  assertIncludes(roadmapJa, 'Implemented', 'Japanese implementation status');
  assertIncludes(roadmapEn, '#555', 'English compatibility gate link');
  assertIncludes(roadmapJa, '#555', 'Japanese compatibility gate link');
  assertIncludes(roadmapEn, '#571', 'English release issue link');
  assertIncludes(roadmapJa, '#571', 'Japanese release issue link');
}

export function main(repoRoot = path.join(__dirname, '..')): void {
  try {
    checkDocsSync(repoRoot);
    console.log('[docs-sync] OK: roadmap, links, status headings, and EN/JA versions are aligned');
  } catch (error: unknown) {
    console.error('[docs-sync] FAIL:', error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

if (require.main === module) main();
