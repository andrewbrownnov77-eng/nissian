#!/usr/bin/env node
/**
 * nissian — scope-aware bug bounty reconnaissance assistant.
 *
 * Stage 1: deep contextual discovery. Given a scope file and one or more
 * in-scope seed URLs, it crawls with a real browser, captures the API surface,
 * infers object-reference relationships (IDOR/BOLA candidates), and analyzes
 * client-side tokens — producing a structured result for later stages.
 *
 * Usage:
 *   nissian discover --scope ./scope.json --seed https://app.example.com [--seed ...]
 *                    [--out ./discovery.json] [--max-pages 50] [--settle 1500]
 *
 * By design it refuses to run without an authorized scope file, and refuses to
 * crawl any seed whose host is not in that scope.
 */

import { readFile, writeFile } from "node:fs/promises";
import { Scope, ScopeError } from "./config/scope.js";
import { Crawler } from "./crawler/browser.js";
import { analyzeRelationships } from "./analysis/relationships.js";
import { analyzeTokens } from "./analysis/tokens.js";
import { writeResult, summarize } from "./report/collector.js";
import { runValidation, type ValidationPlan } from "./validate/runner.js";
import { renderReport } from "./report/report.js";
import type { DiscoveryResult } from "./types.js";

interface Args {
  scope?: string;
  seeds: string[];
  out: string;
  maxPages: number;
  settle: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { seeds: [], out: "discovery.json", maxPages: 50, settle: 1500 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--scope": args.scope = argv[++i]; break;
      case "--seed": args.seeds.push(argv[++i]); break;
      case "--out": args.out = argv[++i]; break;
      case "--max-pages": args.maxPages = Number(argv[++i]); break;
      case "--settle": args.settle = Number(argv[++i]); break;
      default:
        if (a.startsWith("--")) throw new Error(`unknown flag: ${a}`);
    }
  }
  return args;
}

async function discover(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (!args.scope) throw new Error("--scope <file> is required (authorized-scope definition)");
  if (args.seeds.length === 0) throw new Error("at least one --seed <url> is required");

  const scope = await Scope.load(args.scope);
  console.error(`[scope] program: ${scope.config.program}`);
  console.error(`[scope] in-scope: ${scope.config.inScope.join(", ")}`);
  console.error(`[scope] allowed test types: ${scope.config.allowedTestTypes.join(", ")}`);

  const startedAt = new Date().toISOString();
  const crawler = new Crawler(scope);
  const crawl = await crawler.run({
    seeds: args.seeds,
    maxPages: args.maxPages,
    settleMs: args.settle,
  });

  const rel = analyzeRelationships(crawl.requests);
  const tokens = analyzeTokens(crawl.tokenSightings);

  const result: DiscoveryResult = {
    target: args.seeds[0],
    startedAt,
    finishedAt: new Date().toISOString(),
    requests: crawl.requests,
    identifiers: rel.identifiers,
    accessControlCandidates: rel.candidates,
    tokens,
    scopeWarnings: crawl.scopeWarnings,
  };

  await writeResult(args.out, result);
  console.log(summarize(result));
  console.error(`\n[done] full result written to ${args.out}`);
}

async function validate(argv: string[]): Promise<void> {
  let scopePath: string | undefined;
  let planPath: string | undefined;
  let out = "report.md";
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--scope": scopePath = argv[++i]; break;
      case "--plan": planPath = argv[++i]; break;
      case "--out": out = argv[++i]; break;
      default:
        if (argv[i].startsWith("--")) throw new Error(`unknown flag: ${argv[i]}`);
    }
  }
  if (!scopePath) throw new Error("--scope <file> is required");
  if (!planPath) throw new Error("--plan <file> is required (validation plan: targets + identities)");

  const scope = await Scope.load(scopePath);
  const plan = JSON.parse(await readFile(planPath, "utf8")) as ValidationPlan;

  console.error(`[scope] program: ${scope.config.program}`);
  console.error(`[scope] allowed test types: ${scope.config.allowedTestTypes.join(", ")}`);

  const result = await runValidation(scope, plan);
  const report = renderReport(result);
  await writeFile(out, report, "utf8");
  console.log(report);
  console.error(`\n[done] confirmed=${result.findings.length} refuted=${result.refuted.length} inconclusive=${result.inconclusive.length}; report written to ${out}`);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  try {
    switch (cmd) {
      case "discover":
        await discover(rest);
        break;
      case "validate":
        await validate(rest);
        break;
      default:
        console.error("usage:\n  nissian discover --scope <file> --seed <url> [options]\n  nissian validate --scope <file> --plan <file> [--out report.md]");
        process.exit(cmd ? 1 : 0);
    }
  } catch (err) {
    if (err instanceof ScopeError) {
      console.error(`[scope error] ${err.message}`);
    } else {
      console.error(`[error] ${(err as Error).message}`);
    }
    process.exit(1);
  }
}

void main();
