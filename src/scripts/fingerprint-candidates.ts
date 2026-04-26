#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {
    input: '',
    minCount: 20,
    top: 50,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--input' && argv[i + 1]) {
      args.input = argv[++i];
    } else if (a === '--min-count' && argv[i + 1]) {
      args.minCount = Number(argv[++i]) || args.minCount;
    } else if (a === '--top' && argv[i + 1]) {
      args.top = Number(argv[++i]) || args.top;
    }
  }

  if (!args.input) {
    console.error('Usage: node scripts/fingerprint-candidates.js --input <waf-log.jsonl> [--min-count 20] [--top 50]');
    process.exit(1);
  }

  return args;
}

function readJsonLines(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  return content.split(/\r?\n/).filter(Boolean);
}

function main() {
  const { input, minCount, top } = parseArgs(process.argv.slice(2));
  const inputPath = path.resolve(process.cwd(), input);
  const lines = readJsonLines(inputPath);

  const ja3Map = new Map();
  const ja4Map = new Map();

  for (const line of lines) {
    let row;
    try {
      row = JSON.parse(line);
    } catch (_e) {
      continue;
    }

    const ja3 = row?.httpRequest?.ja3Fingerprint || row?.ja3Fingerprint || row?.ja3;
    const ja4 = row?.httpRequest?.ja4Fingerprint || row?.ja4Fingerprint || row?.ja4;

    if (ja3) ja3Map.set(ja3, (ja3Map.get(ja3) || 0) + 1);
    if (ja4) ja4Map.set(ja4, (ja4Map.get(ja4) || 0) + 1);
  }

  function pick(map) {
    return Array.from(map.entries())
      .filter(([, count]) => count >= minCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, top)
      .map(([fingerprint, count]) => ({ fingerprint, count }));
  }

  const result = {
    source: inputPath,
    min_count: minCount,
    top,
    ja3_candidates: pick(ja3Map),
    ja4_candidates: pick(ja4Map),
    recommended_policy_patch: {
      firewall: {
        waf: {
          fingerprint_action: 'count',
          ja3_fingerprints: pick(ja3Map).map((x) => x.fingerprint),
          ja4_fingerprints: pick(ja4Map).map((x) => x.fingerprint),
        },
      },
    },
  };

  console.log(JSON.stringify(result, null, 2));
}

main();
