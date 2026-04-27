#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');

const expectedFiles = [
  'edge/viewer-request.js',
  'edge/viewer-response.js',
  'edge/origin-request.js',
  'edge/cloudflare/index.ts',
  'infra/waf-rules.tf.json',
  'infra/cloudflare-waf.tf.json',
];

const scenarios = [
  {
    name: 'base',
    policyPath: path.join(repoRoot, 'policy', 'base.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'base'),
  },
  {
    name: 'balanced',
    policyPath: path.join(repoRoot, 'policy', 'profiles', 'balanced.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'profiles', 'balanced'),
  },
  {
    name: 'strict',
    policyPath: path.join(repoRoot, 'policy', 'profiles', 'strict.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'profiles', 'strict'),
  },
  {
    name: 'permissive',
    policyPath: path.join(repoRoot, 'policy', 'profiles', 'permissive.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'profiles', 'permissive'),
  },
  {
    name: 'archetype:spa-static-site',
    policyPath: path.join(repoRoot, 'policy', 'archetypes', 'spa-static-site.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'archetypes', 'spa-static-site'),
  },
  {
    name: 'archetype:rest-api',
    policyPath: path.join(repoRoot, 'policy', 'archetypes', 'rest-api.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'archetypes', 'rest-api'),
  },
  {
    name: 'archetype:admin-panel',
    policyPath: path.join(repoRoot, 'policy', 'archetypes', 'admin-panel.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'archetypes', 'admin-panel'),
  },
  {
    name: 'archetype:microservice-origin',
    policyPath: path.join(repoRoot, 'policy', 'archetypes', 'microservice-origin.yml'),
    goldenDir: path.join(repoRoot, 'tests', 'golden', 'archetypes', 'microservice-origin'),
  },
];

type DriftScenario = {
  name: string;
  policyPath: string;
  goldenDir: string;
};

function runBuild(policyPath: string, outDir: string) {
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-cloudflare.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-infra.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'compile-cloudflare-waf.js'), '--policy', policyPath, '--out-dir', outDir], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
}

function readOrNull(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (_e) {
    return null;
  }
}

function compareScenario(scenario: DriftScenario) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `cdn-security-drift-${scenario.name}-`));
  let failed = false;

  try {
    runBuild(scenario.policyPath, tmpDir);

    for (const rel of expectedFiles) {
      const generated = readOrNull(path.join(tmpDir, rel));
      const golden = readOrNull(path.join(scenario.goldenDir, rel));

      if (generated === null) {
        console.error(`[${scenario.name}] Missing generated file:`, rel);
        failed = true;
        continue;
      }
      if (golden === null) {
        console.error(`[${scenario.name}] Missing golden file:`, rel);
        failed = true;
        continue;
      }
      if (generated !== golden) {
        console.error(`[${scenario.name}] Drift detected:`, rel);
        failed = true;
      } else {
        console.log(`[${scenario.name}] OK (no drift):`, rel);
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return !failed;
}

function checkParityDocsFresh() {
  const { renderEn, renderJa } = require('./generate-parity-doc');
  const targets = [
    { label: 'docs/cloudflare-waf-parity.md', path: path.join(repoRoot, 'docs', 'cloudflare-waf-parity.md'), actual: renderEn() },
    { label: 'docs/cloudflare-waf-parity.ja.md', path: path.join(repoRoot, 'docs', 'cloudflare-waf-parity.ja.md'), actual: renderJa() },
  ];
  let ok = true;
  for (const t of targets) {
    if (!fs.existsSync(t.path)) {
      console.error(`[parity-doc] MISSING: ${t.label}. Run: node scripts/generate-parity-doc.js --write${t.label.endsWith('.ja.md') ? ' --lang=ja' : ''}`);
      ok = false;
      continue;
    }
    const committed = fs.readFileSync(t.path, 'utf8');
    if (committed !== t.actual) {
      console.error(`[parity-doc] DRIFT: ${t.label} is out of sync with scripts/lib/cloudflare-waf-parity.js. Run: node scripts/generate-parity-doc.js --write${t.label.endsWith('.ja.md') ? ' --lang=ja' : ''}`);
      ok = false;
    } else {
      console.log(`[parity-doc] OK (no drift): ${t.label}`);
    }
  }
  return ok;
}

function main() {
  let allPassed = true;

  for (const scenario of scenarios) {
    const ok = compareScenario(scenario);
    if (!ok) allPassed = false;
  }

  if (!checkParityDocsFresh()) allPassed = false;

  if (!allPassed) {
    console.error('Drift check failed. Regenerate golden fixtures if change is intentional.');
    process.exit(1);
  }

  console.log('Drift check passed for base + all profiles + parity docs.');
}

main();
