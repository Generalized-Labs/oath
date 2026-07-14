#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";

const input = resolve(process.argv[2] ?? "evidence-download");
const output = resolve(process.argv[3] ?? "ga-evidence-manifest.json");

async function filesUnder(root) {
  const result = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else result.push(path);
    }
  }
  await walk(root);
  return result.sort();
}

const artifacts = [];
for (const path of await filesUnder(input)) {
  const bytes = await readFile(path);
  let parsed = null;
  if (path.endsWith(".json")) {
    try { parsed = JSON.parse(bytes); } catch { parsed = null; }
  }
  artifacts.push({
    path: relative(input, path).replaceAll("\\", "/"),
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    evidence_class: parsed?.evidence_class ?? null,
    summary: parsed && typeof parsed === "object" ? parsed : null,
  });
}

const behavioral = artifacts.filter((item) => item.path.endsWith("behavioral-summary.json"));
const project = artifacts.find((item) => item.path.endsWith("project-summary.json"));
const generated = artifacts.filter((item) =>
  item.summary?.evidence_class === "generated_stress" &&
  Array.isArray(item.summary?.results)
);
const stress = generated.reduce((acc, item) => {
  acc.executed += item.summary.results.length;
  acc.equivalent += item.summary.results.filter((result) => result.equivalent === true).length;
  acc.failed += item.summary.results.filter((result) => result.equivalent !== true).length;
  return acc;
}, { executed: 0, equivalent: 0, failed: 0 });

const manifest = {
  schema_version: 1,
  evidence_status: "developer-preview",
  commit: process.env.GITHUB_SHA ?? "local",
  run_id: process.env.GITHUB_RUN_ID ?? null,
  run_url: process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
    ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
    : null,
  generated_at: new Date().toISOString(),
  claims: {
    independent_behavioral: {
      platform_reports: behavioral.length,
      executed: behavioral.reduce((sum, item) => sum + Number(item.summary?.executed ?? 0), 0),
      equivalent: behavioral.reduce((sum, item) => sum + Number(item.summary?.equivalent ?? 0), 0),
      failed: behavioral.reduce((sum, item) => sum + Number(item.summary?.failed ?? 0), 0),
    },
    generated_stress: stress,
    real_projects: {
      target: Number(project?.summary?.target ?? 0),
      exact_equivalents: Number(project?.summary?.exact_equivalents ?? 0),
      failures: project?.summary?.failures ?? [],
    },
  },
  ga_gate: {
    ready: false,
    open_external_gates: [
      "100 independent workflows",
      "250 pinned real projects",
      "10000 generated executions",
      "detection thresholds on frozen and private holdouts",
      "independent security review and penetration test",
      "60-day production SLO window",
      "commercial adoption thresholds",
      "legal and compliance approval",
    ],
  },
  artifacts,
};

await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify({ output, artifacts: artifacts.length, claims: manifest.claims }, null, 2));
