#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const command = process.argv[2] ?? "validate";
const npmReference = "11.12.1";
const categories = [
  "frameworks-applications",
  "build-tools",
  "typescript-compilers",
  "test-tools",
  "server-frameworks",
  "ui-libraries",
  "database-orm",
  "monorepos-workspaces",
  "native-platform",
  "cli-developer-tools"
];

function run(program, args, cwd, env = {}) {
  return spawnSync(program, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: Number(process.env.OATH_PROJECT_TIMEOUT_MS ?? 600_000),
    env: { ...process.env, CI: "1", ...env }
  });
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function validateManifest(manifest) {
  if (manifest.schema_version !== 1 || manifest.npm !== npmReference || !Array.isArray(manifest.projects)) {
    throw new Error("invalid pinned project corpus header");
  }
  if (manifest.projects.length !== 100) throw new Error(`expected 100 pinned projects, found ${manifest.projects.length}`);
  const repositories = new Set();
  const counts = Object.fromEntries(categories.map(category => [category, 0]));
  for (const project of manifest.projects) {
    if (!/^[0-9a-f]{40}$/.test(project.commit)) throw new Error(`${project.repository}: commit must be a full SHA`);
    if (!/^[0-9a-f]{64}$/.test(project.expected_lock_sha256)) throw new Error(`${project.repository}: missing lock SHA-256`);
    if (project.npm !== npmReference) throw new Error(`${project.repository}: npm reference drifted`);
    if (!(project.category in counts)) throw new Error(`${project.repository}: unknown category ${project.category}`);
    if (repositories.has(project.repository)) throw new Error(`duplicate repository ${project.repository}`);
    repositories.add(project.repository);
    counts[project.category]++;
  }
  for (const [category, count] of Object.entries(counts)) {
    if (count !== 10) throw new Error(`${category}: expected 10 projects, found ${count}`);
  }
  return counts;
}

async function preflight() {
  const candidatesPath = resolve(process.env.OATH_PROJECT_CANDIDATES ?? "tests/compat/project-candidates.json");
  const output = resolve(process.env.OATH_PROJECT_PREFLIGHT_OUTPUT ?? "compat-results/preflight/projects.json");
  const candidateDocument = await readJson(candidatesPath);
  const candidates = Array.isArray(candidateDocument)
    ? candidateDocument
    : Object.entries(candidateDocument.categories).flatMap(([category, repositories]) =>
        repositories.map(repository => ({ repository, subdirectory: ".", category }))
      );
  const shard = Number(process.env.OATH_PROJECT_SHARD ?? 0);
  const shards = Number(process.env.OATH_PROJECT_SHARDS ?? 1);
  const npmVersion = run("npm", ["--version"], process.cwd()).stdout.trim();
  if (npmVersion !== npmReference) throw new Error(`preflight requires npm ${npmReference}; found ${npmVersion}`);
  const root = await mkdtemp(join(tmpdir(), "oath-corpus-"));
  const results = [];
  try {
    for (const [index, candidate] of candidates.entries()) {
      if (index % shards !== shard) continue;
      const cwd = join(root, String(index));
      const clone = run("git", ["clone", "--depth=1", `https://github.com/${candidate.repository}.git`, cwd], root);
      if (clone.status !== 0) {
        results.push({ ...candidate, eligible: false, reason: "clone_failed", stderr: clone.stderr });
        continue;
      }
      const commit = run("git", ["rev-parse", "HEAD"], cwd).stdout.trim();
      const packageRoot = resolve(cwd, candidate.subdirectory ?? ".");
      try { await readJson(join(packageRoot, "package.json")); }
      catch { results.push({ ...candidate, commit, eligible: false, reason: "missing_package_json" }); continue; }
      const home = join(root, `home-${index}`);
      await mkdir(home, { recursive: true });
      const env = { HOME: home, npm_config_cache: join(home, ".npm") };
      const lock = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--package-lock=true"], packageRoot, env);
      if (lock.status !== 0) {
        results.push({ ...candidate, commit, eligible: false, reason: "npm_lock_rejected", stderr: lock.stderr });
        continue;
      }
      const install = run("npm", ["install", "--ignore-scripts", "--package-lock=true"], packageRoot, env);
      if (install.status !== 0) {
        results.push({ ...candidate, commit, eligible: false, reason: "npm_install_rejected", stderr: install.stderr });
        continue;
      }
      const lockBytes = await readFile(join(packageRoot, "package-lock.json"));
      results.push({
        repository: candidate.repository,
        commit,
        subdirectory: candidate.subdirectory ?? ".",
        npm: npmReference,
        category: candidate.category,
        expected_lock_sha256: sha256(lockBytes),
        eligible: true
      });
      await rm(cwd, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, JSON.stringify({ schema_version: 1, npm: npmReference, shard, shards, results }, null, 2));
  console.log(JSON.stringify({ shard, tested: results.length, eligible: results.filter(result => result.eligible).length }, null, 2));
}

async function aggregate() {
  const manifestPath = resolve(process.env.OATH_PROJECT_MANIFEST ?? "tests/compat/projects.lock.json");
  const resultDir = resolve(process.env.OATH_COMPAT_RESULTS ?? "compat-results/ga");
  const manifest = await readJson(manifestPath);
  validateManifest(manifest);
  const files = (await readdir(resultDir)).filter(name => /^project-shard-\d+\.json$/.test(name));
  const results = [];
  for (const file of files) results.push(...(await readJson(join(resultDir, file))).results);
  const byIdentity = new Map(results.map(result => [`${result.project}@${result.commit}`, result]));
  const failures = [];
  for (const project of manifest.projects) {
    const result = byIdentity.get(`${project.repository}@${project.commit}`);
    if (!result) failures.push({ repository: project.repository, reason: "missing_result" });
    else if (!result.equivalent) failures.push({ repository: project.repository, reason: result.classification ?? "not_equivalent" });
    else if (result.reference?.npm !== npmReference) failures.push({ repository: project.repository, reason: "npm_reference_drift" });
    else if (result.reference?.lock_sha256 !== project.expected_lock_sha256) failures.push({ repository: project.repository, reason: "lock_hash_drift" });
  }
  const summary = { schema_version: 1, target: 100, exact_equivalents: 100 - failures.length, failures };
  const output = resolve(process.env.OATH_PROJECT_AGGREGATE_OUTPUT ?? join(resultDir, "project-summary.json"));
  await writeFile(output, JSON.stringify(summary, null, 2));
  console.log(JSON.stringify(summary, null, 2));
  if (failures.length) process.exitCode = 1;
}

async function mergePreflight() {
  const input = resolve(process.env.OATH_PROJECT_PREFLIGHT_DIR ?? "compat-results/preflight");
  const output = resolve(process.env.OATH_PROJECT_MANIFEST ?? "tests/compat/projects.lock.json");
  const files = (await readdir(input)).filter(name => name.endsWith(".json"));
  const eligible = [];
  for (const file of files) {
    const artifact = await readJson(join(input, file));
    eligible.push(...artifact.results.filter(result => result.eligible));
  }
  const unique = new Map(eligible.map(({ eligible: _, ...project }) => [project.repository, project]));
  const projects = [];
  for (const category of categories) {
    const selected = [...unique.values()]
      .filter(project => project.category === category)
      .sort((left, right) => left.repository.localeCompare(right.repository))
      .slice(0, 10);
    if (selected.length !== 10) throw new Error(`${category}: only ${selected.length} eligible candidates; need 10`);
    projects.push(...selected);
  }
  const manifest = { schema_version: 1, npm: npmReference, projects };
  validateManifest(manifest);
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, JSON.stringify(manifest, null, 2));
  console.log(JSON.stringify({ output, projects: projects.length }, null, 2));
}

if (command === "preflight") await preflight();
else if (command === "merge-preflight") await mergePreflight();
else if (command === "validate") console.log(JSON.stringify(validateManifest(await readJson(resolve(process.argv[3] ?? "tests/compat/projects.lock.json"))), null, 2));
else if (command === "aggregate") await aggregate();
else throw new Error(`unknown command ${command}`);
