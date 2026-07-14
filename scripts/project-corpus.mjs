#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { access, cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";

const command = process.argv[2] ?? "validate";
const npmReference = "11.12.1";
const nodeReference = "24.13.0";
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

async function prepareLockWorkspace(packageRoot, workspaceRoot) {
  const lockDir = join(workspaceRoot, "lock");
  await cp(packageRoot, lockDir, {
    recursive: true,
    filter(source) {
      const path = relative(packageRoot, source);
      return path !== ".git" && !path.startsWith(`.git${sep}`);
    }
  });
  return lockDir;
}

function validateManifest(manifest) {
  if (manifest.schema_version !== 1 || manifest.npm !== npmReference || manifest.node !== nodeReference || !Array.isArray(manifest.projects)) {
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
  const nodeVersion = process.versions.node;
  if (nodeVersion !== nodeReference) throw new Error(`preflight requires Node ${nodeReference}; found ${nodeVersion}`);
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
      // npm derives a missing package name from the working-directory basename.
      // Match npm-parity.mjs's stable `lock` workspace exactly so the raw lock
      // digest remains reproducible for unnamed packages.
      const lockDir = await prepareLockWorkspace(packageRoot, join(root, `lock-workspace-${index}`));
      const home = join(root, `home-${index}`);
      await mkdir(home, { recursive: true });
      const env = { HOME: home, npm_config_cache: join(home, ".npm") };
      const lock = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--package-lock=true"], lockDir, env);
      if (lock.status !== 0) {
        results.push({ ...candidate, commit, eligible: false, reason: "npm_lock_rejected", stderr: lock.stderr });
        continue;
      }
      const install = run("npm", ["install", "--ignore-scripts", "--package-lock=true"], lockDir, env);
      if (install.status !== 0) {
        results.push({ ...candidate, commit, eligible: false, reason: "npm_install_rejected", stderr: install.stderr });
        continue;
      }
      let lockBytes;
      try {
        lockBytes = await readFile(join(lockDir, "package-lock.json"));
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
        results.push({
          ...candidate,
          commit,
          eligible: false,
          reason: "missing_package_lock",
          stderr: "npm completed successfully without producing package-lock.json"
        });
        continue;
      }
      results.push({
        repository: candidate.repository,
        commit,
        subdirectory: candidate.subdirectory ?? ".",
        npm: npmReference,
        category: candidate.category,
        candidate_index: index,
        expected_lock_sha256: sha256(lockBytes),
        eligible: true
      });
      await rm(cwd, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, JSON.stringify({ schema_version: 1, npm: npmReference, node: nodeReference, shard, shards, results }, null, 2));
  console.log(JSON.stringify({ shard, tested: results.length, eligible: results.filter(result => result.eligible).length }, null, 2));
}

async function selfTest() {
  const root = await mkdtemp(join(tmpdir(), "oath-corpus-self-test-"));
  try {
    const source = join(root, "62");
    await mkdir(join(source, ".git"), { recursive: true });
    await writeFile(join(source, "package.json"), JSON.stringify({ private: true }));
    await writeFile(join(source, ".git", "config"), "must not be copied");
    const lockDir = await prepareLockWorkspace(source, join(root, "workspace"));
    assert.equal(basename(lockDir), "lock");
    assert.deepEqual(await readJson(join(lockDir, "package.json")), { private: true });
    await assert.rejects(access(join(lockDir, ".git")));
    console.log(JSON.stringify({ stable_lock_basename: true, git_metadata_excluded: true }, null, 2));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
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
  const files = (await readdir(input)).filter(name => /^preflight-\d+\.json$/.test(name));
  const results = [];
  for (const file of files) {
    const artifact = await readJson(join(input, file));
    results.push(...artifact.results);
  }
  const eligible = results.filter(result => result.eligible);
  const unique = new Map(eligible.map(({ eligible: _, ...project }) => [project.repository, project]));
  const projects = [];
  const shortages = [];
  const categoryResults = [];
  for (const category of categories) {
    const categoryCandidates = results.filter(result => result.category === category);
    const categoryEligible = categoryCandidates.filter(result => result.eligible);
    const reasons = {};
    for (const result of categoryCandidates.filter(result => !result.eligible)) {
      reasons[result.reason] = (reasons[result.reason] ?? 0) + 1;
    }
    categoryResults.push({
      category,
      tested: categoryCandidates.length,
      eligible: categoryEligible.length,
      rejected: categoryCandidates.length - categoryEligible.length,
      rejection_reasons: reasons
    });
    const selected = [...unique.values()]
      .filter(project => project.category === category)
      .sort((left, right) => left.candidate_index - right.candidate_index)
      .slice(0, 10);
    if (selected.length !== 10) shortages.push({ category, eligible: selected.length, required: 10 });
    projects.push(...selected.map(({ candidate_index: _, ...project }) => project));
  }
  const selectionSummary = {
    schema_version: 1,
    npm: npmReference,
    shard_files: files.length,
    expected_shard_files: 20,
    tested: results.length,
    eligible: eligible.length,
    categories: categoryResults,
    shortages
  };
  await writeFile(join(input, "selection-summary.json"), JSON.stringify(selectionSummary, null, 2));
  console.log(JSON.stringify(selectionSummary, null, 2));
  if (files.length !== 20) throw new Error(`expected 20 preflight shard files; found ${files.length}`);
  if (shortages.length) {
    throw new Error(shortages.map(({ category, eligible, required }) => `${category}: ${eligible}/${required} eligible`).join(", "));
  }
  const manifest = { schema_version: 1, npm: npmReference, node: nodeReference, projects };
  validateManifest(manifest);
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, JSON.stringify(manifest, null, 2));
  console.log(JSON.stringify({ output, projects: projects.length }, null, 2));
}

if (command === "preflight") await preflight();
else if (command === "merge-preflight") await mergePreflight();
else if (command === "validate") console.log(JSON.stringify(validateManifest(await readJson(resolve(process.argv[3] ?? "tests/compat/projects.lock.json"))), null, 2));
else if (command === "aggregate") await aggregate();
else if (command === "self-test") await selfTest();
else throw new Error(`unknown command ${command}`);
