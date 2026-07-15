import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const generator = fileURLToPath(new URL("./generate-ga-evidence.mjs", import.meta.url));

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function generateEvidence({ workflows, projects, executions }) {
  const root = await mkdtemp(join(tmpdir(), "oath-ga-evidence-"));
  const input = join(root, "input");
  const output = join(root, "manifest.json");

  for (let platform = 0; platform < 3; platform += 1) {
    await writeJson(join(input, `platform-${platform}`, "behavioral-summary.json"), {
      executed: workflows,
      equivalent: workflows,
      failed: 0,
    });
  }
  await writeJson(join(input, "projects", "project-summary.json"), {
    target: projects,
    exact_equivalents: projects,
    failures: [],
  });
  await writeJson(join(input, "stress", "generated.json"), {
    evidence_class: "generated_stress",
    results: Array.from({ length: executions }, () => ({ equivalent: true })),
  });

  await execFileAsync(process.execPath, [generator, input, output]);
  return JSON.parse(await readFile(output, "utf8"));
}

test("moves satisfied measured gates out of the open list", async () => {
  const manifest = await generateEvidence({ workflows: 100, projects: 250, executions: 10000 });

  assert.deepEqual(manifest.ga_gate.open_evidence_gates, []);
  assert.deepEqual(manifest.ga_gate.completed_evidence_gates, [
    "100 independent workflows across required platforms",
    "250 pinned real projects",
    "10000 generated executions",
  ]);
  assert.equal(manifest.ga_gate.open_external_gates.includes("250 pinned real projects"), false);
  assert.equal(manifest.ga_gate.ready, false);
});

test("keeps under-threshold measured gates open", async () => {
  const manifest = await generateEvidence({ workflows: 99, projects: 249, executions: 9999 });

  assert.deepEqual(manifest.ga_gate.completed_evidence_gates, []);
  assert.deepEqual(manifest.ga_gate.open_evidence_gates, [
    "100 independent workflows across required platforms",
    "250 pinned real projects",
    "10000 generated executions",
  ]);
});
