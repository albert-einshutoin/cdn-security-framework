#!/usr/bin/env node
"use strict";

const { accessSync, constants, mkdirSync, rmSync, writeFileSync, mkdtempSync } = require("node:fs");
const { performance } = require("node:perf_hooks");
const { tmpdir } = require("node:os");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const process = require("node:process");

const DEFAULT_ITERATIONS = 8;
const DEFAULT_WARMUP = 1;
const DEFAULT_POLICY = "policy/base.yml";
const DEFAULT_INSTALL_BENCHMARKS = 1;
const USAGE = `Usage:
  node scripts/benchmark-compiler.js [options]

Options:
  --policy <path>       Policy file to compile (default: ${DEFAULT_POLICY})
  --iterations <n>      Compile iterations (default: ${DEFAULT_ITERATIONS})
  --warmup <n>          Number of warmup runs excluded from average (default: ${DEFAULT_WARMUP})
  --measure-install      Measure npm ci install time (1 run, optional)
  --install-iterations n  If set, measure npm ci with n runs
  --allow-placeholder-token  Pass --allow-placeholder-token to compiler (default: false)
  --output <path>       Write JSON report to file
  --out-dir <path>      Base output directory for compiler runs
  --keep-output          Keep compiled outputs in --out-dir
  --help                Show this help\n`;

function parseIntArg(value, label, minimum = 1) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < minimum) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return parsed;
}

function parseArgs(argv) {
  const options = {
    policyPath: DEFAULT_POLICY,
    iterations: DEFAULT_ITERATIONS,
    warmup: DEFAULT_WARMUP,
    measureInstall: false,
    allowPlaceholderToken: false,
    installIterations: DEFAULT_INSTALL_BENCHMARKS,
    output: "",
    outDir: "",
    keepOutput: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--policy") {
      options.policyPath = argv[++i];
      continue;
    }
    if (arg === "--iterations") {
      options.iterations = parseIntArg(argv[++i], "--iterations");
      continue;
    }
    if (arg === "--warmup") {
      options.warmup = parseIntArg(argv[++i], "--warmup", 0);
      continue;
    }
    if (arg === "--measure-install") {
      options.measureInstall = true;
      continue;
    }
    if (arg === "--allow-placeholder-token") {
      options.allowPlaceholderToken = true;
      continue;
    }
    if (arg === "--install-iterations") {
      options.installIterations = parseIntArg(argv[++i], "--install-iterations");
      continue;
    }
    if (arg === "--output") {
      options.output = argv[++i];
      continue;
    }
    if (arg === "--out-dir") {
      options.outDir = argv[++i];
      continue;
    }
    if (arg === "--keep-output") {
      options.keepOutput = true;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }
    throw new Error(`Unknown flag: ${arg}`);
  }

  return options;
}

function detectTimeCommand() {
  const base = process.platform === "darwin" ? "-l" : "-v";
  try {
    accessSync("/usr/bin/time", constants.X_OK);
    return { command: "/usr/bin/time", args: [base] };
  } catch {
    return null;
  }
}

function parseMaxRssBytes(raw) {
  if (!raw) return null;
  const candidates = [
    /\s*([0-9]+(?:\.[0-9]+)?)\s+maximum resident set size/i,
    /maximum resident set size\s*:\s*([0-9]+(?:\.[0-9]+)?)\s+bytes/i,
    /Maximum resident set size[^:]*:\s*([0-9]+(?:\.[0-9]+)?)\s*kbytes?/i,
    /maximum resident set size[^:]*:\s*([0-9]+(?:\.[0-9]+)?)/i,
  ];
  for (const regex of candidates) {
    const match = raw.match(regex);
    if (match) {
      const value = Number.parseFloat(match[1]);
      if (!Number.isFinite(value)) break;
      const isKbytes = /kbytes?/i.test(regex.source);
      return isKbytes ? Math.round(value * 1024) : Math.round(value);
    }
  }
  return null;
}

function runCommand(command, args, cwd) {
  const timeCommand = detectTimeCommand();
  const commandArgs = [];
  let launch = command;
  let timeWrapped = false;
  if (timeCommand) {
    launch = timeCommand.command;
    commandArgs.push(...timeCommand.args, command, ...args);
    timeWrapped = true;
  } else {
    commandArgs.push(...args);
  }

  const startWall = performance.now();
  const result = spawnSync(launch, commandArgs, {
    cwd: cwd || process.cwd(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 20 * 1024 * 1024,
    env: {
      ...process.env,
      NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} ${process.platform === "win32" ? "" : "--no-warnings"}`.trim(),
    },
  });
  const elapsedMs = performance.now() - startWall;

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `Command failed: ${command} ${args.join(" ")}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`,
    );
  }

  const outputForParse = timeWrapped ? result.stderr : "";
  const maxRssBytes = timeWrapped ? parseMaxRssBytes(outputForParse) : null;
  return {
    elapsedMs,
    maxRssBytes,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

function summarizeSamples(values) {
  if (values.length === 0) return { count: 0, min: 0, max: 0, mean: 0, p50: 0, p95: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  return {
    count: sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
    mean: sum / sorted.length,
    p50: sorted[Math.floor(sorted.length * 0.5)],
    p95: sorted[Math.floor(sorted.length * 0.95)],
  };
}

function formatMs(value) {
  return `${Math.round(value)}ms`;
}

function ensureDir(p) {
  mkdirSync(p, { recursive: true });
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    console.error(USAGE);
    process.exit(1);
  }

  if (options.help) {
    console.log(USAGE);
    return;
  }

  if (options.warmup >= options.iterations) {
    throw new Error("warmup must be less than iterations");
  }
  if (!options.outDir) {
    options.outDir = mkdtempSync(path.join(tmpdir(), "cdn-security-compiler-bench-"));
  }
  ensureDir(options.outDir);
  const projectRoot = process.cwd();
  const policyPath = path.join(projectRoot, options.policyPath);
  const compileSamples = [];
  const compileMemory = [];

  for (let i = 0; i < options.iterations; i += 1) {
    const runDir = path.join(options.outDir, `run-${String(i + 1).padStart(3, "0")}`);
    mkdirSync(runDir, { recursive: true });
    const result = runCommand(
      "node",
      [
        path.join(projectRoot, "scripts", "compile.js"),
        "--policy",
        policyPath,
        "--out-dir",
        runDir,
        ...(options.allowPlaceholderToken ? ["--allow-placeholder-token"] : []),
      ],
      projectRoot,
    );
    compileSamples.push(result.elapsedMs);
    if (result.maxRssBytes !== null) {
      compileMemory.push(result.maxRssBytes);
    }
  }

  const warmSamples = compileSamples.slice(options.warmup);
  const compileSummary = {
    coldStartMs: compileSamples[0] || 0,
    warm: summarizeSamples(warmSamples),
    all: summarizeSamples(compileSamples),
    memoryBytes: compileMemory.length > 0 ? summarizeSamples(compileMemory) : null,
  };

  let installReport = null;
  if (options.measureInstall) {
    const installSamples = [];
    for (let i = 0; i < options.installIterations; i += 1) {
      const result = runCommand("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], projectRoot);
      installSamples.push(result.elapsedMs);
    }
    installReport = {
      runs: options.installIterations,
      summary: summarizeSamples(installSamples),
    };
  }

  const report = {
    generatedAt: new Date().toISOString(),
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cwd: projectRoot,
    },
    benchmarkInput: {
      policyPath: options.policyPath,
      iterations: options.iterations,
      warmup: options.warmup,
      measureInstall: options.measureInstall,
      installIterations: options.measureInstall ? options.installIterations : 0,
    },
    compile: compileSummary,
    install: installReport,
  };

  console.log("=== cdn-security compiler benchmark ===");
  console.log(`Node ${report.environment.node} on ${report.environment.platform}/${report.environment.arch}`);
  console.log(`Policy: ${report.benchmarkInput.policyPath}`);
  console.log(`Iterations: ${options.iterations} (warmup: ${options.warmup})`);
  console.log(
    `Compile cold start: ${formatMs(compileSummary.coldStartMs)} ` +
      `| warm median ${formatMs(compileSummary.warm.p50)} ` +
      `| warm mean ${formatMs(compileSummary.warm.mean)}`,
  );
  if (compileSummary.memoryBytes) {
    console.log(
      `Compile max RSS (MiB): min ${Math.round(compileSummary.memoryBytes.min / 1024 / 1024)}, ` +
        `p50 ${Math.round(compileSummary.memoryBytes.p50 / 1024 / 1024)}, ` +
        `max ${Math.round(compileSummary.memoryBytes.max / 1024 / 1024)}`,
    );
  } else {
    console.log("Install / time-command metrics for RSS were not available in this environment.");
  }
  if (installReport) {
    console.log(`npm ci (ms): median ${formatMs(installReport.summary.p50)} | mean ${formatMs(installReport.summary.mean)}`);
  }

  const output = JSON.stringify(report, null, 2);
  if (options.output) {
    writeFileSync(options.output, `${output}\n`, "utf8");
    console.log(`Report written: ${options.output}`);
  } else {
    console.log(output);
  }

  if (!options.keepOutput) {
    rmSync(options.outDir, { recursive: true, force: true });
  }
}

main();
