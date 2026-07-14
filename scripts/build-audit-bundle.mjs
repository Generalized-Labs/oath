#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const output = resolve(process.argv[2] ?? "audit-dist");
const allowDirty = process.argv.includes("--allow-dirty");
const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const dirtyLines = execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim().split("\n").filter(Boolean);
if (dirtyLines.length && !allowDirty) throw new Error("audit bundles must be built from a clean exact commit");

const inputs = [
  ".github/workflows/ci.yml",
  ".github/workflows/release.yml",
  "Cargo.lock",
  "contracts/exec-assessment-v3.schema.json",
  "contracts/publish-assessment-v2.schema.json",
  "contracts/registry-verdict-v1.schema.json",
  "docs/EXTERNAL_AUDIT_SCOPE.md",
  "docs/GA_GATE_TRACKER.md",
  "docs/INCIDENT_RESPONSE.md",
  "docs/REGISTRY_OPERATIONS.md",
  "docs/SCANNER_THREAT_MODEL.md",
  "docs/SERVICE_LEVEL_OBJECTIVES.md",
  "docs/SUPPORTED_PLATFORMS.md",
  "tests/detection/corpus-metadata.schema.json",
  "crates/oath-registry/migrations/0001_registry.sql",
  "crates/oath-registry/migrations/0002_ga_foundation.sql",
  "crates/oath-registry/migrations/0003_limits.sql",
].map((path) => path === "docs/SCANNER_THREAT_MODEL.md" ? "docs/scanner-threat-model.md" : path);

await rm(output, { recursive: true, force: true });
const artifacts = [];
for (const source of inputs.sort()) {
  const bytes = await readFile(source);
  const destination = join(output, "inputs", source);
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination);
  artifacts.push({
    path: source,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
}
const manifest = {
  schema_version: 1,
  evidence_class: "external-audit-input-bundle",
  commit,
  dirty: dirtyLines.length > 0,
  qualifying_input_bundle: dirtyLines.length === 0,
  generated_at: new Date().toISOString(),
  limitations: [
    "This bundle prepares review inputs; it is not an independent audit result.",
    "External reviewers must issue and sign their own reports and findings ledger.",
  ],
  artifacts,
};
await writeFile(join(output, "audit-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
const checksums = artifacts.map(({ sha256, path }) => `${sha256}  inputs/${path}`);
const manifestBytes = await readFile(join(output, "audit-manifest.json"));
checksums.push(`${createHash("sha256").update(manifestBytes).digest("hex")}  audit-manifest.json`);
await writeFile(join(output, "SHA256SUMS"), `${checksums.join("\n")}\n`);
console.log(JSON.stringify({ output, commit, dirty: manifest.dirty, artifacts: artifacts.length }, null, 2));
