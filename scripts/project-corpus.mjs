#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { access, cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { analyzeLockMutation } from "./lock-mutation.mjs";

const command = process.argv[2] ?? "validate";
const npmReference = "11.12.1";
const nodeReference = "24.13.0";
const projectTarget = 250;
const projectsPerCategory = 25;
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

async function prepareReferenceWorkspace(packageRoot, workspaceRoot, workspaceName) {
  assert.ok(workspaceName === "lock" || workspaceName === "npm");
  const workspace = join(workspaceRoot, workspaceName);
  await cp(packageRoot, workspace, {
    recursive: true,
    filter(source) {
      const path = relative(packageRoot, source);
      return path !== ".git" && !path.startsWith(`.git${sep}`);
    }
  });
  return workspace;
}

async function runReferenceInstall(packageRoot, workspaceRoot, home) {
  const lockDir = await prepareReferenceWorkspace(packageRoot, workspaceRoot, "lock");
  const npmDir = await prepareReferenceWorkspace(packageRoot, workspaceRoot, "npm");
  await mkdir(home, { recursive: true });
  const env = { HOME: home, npm_config_cache: join(home, ".npm") };
  const lock = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--package-lock=true"], lockDir, env);
  if (lock.status !== 0) return { lock, install: null, npmDir };
  const generatedLock = join(lockDir, "package-lock.json");
  try {
    await access(generatedLock);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    return { lock, install: null, npmDir, missingLock: true };
  }
  await cp(generatedLock, join(npmDir, "package-lock.json"));
  const install = run("npm", ["install", "--ignore-scripts", "--package-lock=true"], npmDir, env);
  return { lock, install, npmDir };
}

function validateManifest(manifest, expectedTarget = projectTarget, expectedPerCategory = projectsPerCategory) {
  if (manifest.schema_version !== 2 || manifest.npm !== npmReference || manifest.node !== nodeReference || !Array.isArray(manifest.projects)) {
    throw new Error("invalid pinned project corpus header");
  }
  if (manifest.projects.length !== expectedTarget) throw new Error(`expected ${expectedTarget} pinned projects, found ${manifest.projects.length}`);
  const repositories = new Set();
  const counts = Object.fromEntries(categories.map(category => [category, 0]));
  for (const project of manifest.projects) {
    if (!/^[0-9a-f]{40}$/.test(project.commit)) throw new Error(`${project.repository}: commit must be a full SHA`);
    if (!/^[0-9a-f]{64}$/.test(project.expected_lock_sha256)) throw new Error(`${project.repository}: missing lock SHA-256`);
    if (!/^tests\/compat\/project-locks\/[A-Za-z0-9_.-]+\.json\.gz$/.test(project.lock_path)) {
      throw new Error(`${project.repository}: invalid pinned lock path`);
    }
    if (project.npm !== npmReference) throw new Error(`${project.repository}: npm reference drifted`);
    if (!(project.category in counts)) throw new Error(`${project.repository}: unknown category ${project.category}`);
    if (repositories.has(project.repository)) throw new Error(`duplicate repository ${project.repository}`);
    repositories.add(project.repository);
    counts[project.category]++;
  }
  for (const [category, count] of Object.entries(counts)) {
    if (count !== expectedPerCategory) throw new Error(`${category}: expected ${expectedPerCategory} projects, found ${count}`);
  }
  return counts;
}

async function validatePinnedLocks(manifest) {
  for (const project of manifest.projects) {
    const compressed = await readFile(resolve(project.lock_path));
    const actual = sha256(gunzipSync(compressed));
    if (actual !== project.expected_lock_sha256) {
      throw new Error(`${project.repository}: pinned lock digest mismatch; expected ${project.expected_lock_sha256}, found ${actual}`);
    }
  }
  return manifest.projects.length;
}

function aggregateFailure(project, result) {
  if (!result.equivalent) return result.classification ?? "not_equivalent";
  if (result.reference?.npm !== npmReference) return "npm_reference_drift";
  if (result.reference?.command !== "install") return "npm_reference_command_drift";
  if (result.reference?.pinned_lock_sha256 !== project.expected_lock_sha256) return "pinned_lock_hash_drift";
  if (result.reference?.lock_sha256 !== project.expected_lock_sha256 && result.reference?.lock_mutation?.explained !== true) {
    return "lock_hash_drift";
  }
  return null;
}

async function preflight() {
  const candidatesPath = resolve(process.env.OATH_PROJECT_CANDIDATES ?? "tests/compat/project-candidates.json");
  const output = resolve(process.env.OATH_PROJECT_PREFLIGHT_OUTPUT ?? "compat-results/preflight/projects.json");
  const outputDir = resolve(output, "..");
  await mkdir(join(outputDir, "locks"), { recursive: true });
  const candidateDocuments = [await readJson(candidatesPath)];
  const additionsPath = resolve("tests/compat/project-candidate-additions.json");
  try { candidateDocuments.push(await readJson(additionsPath)); }
  catch (error) { if (error?.code !== "ENOENT") throw error; }
  const candidates = candidateDocuments.flatMap(candidateDocument => Array.isArray(candidateDocument)
    ? candidateDocument
    : Object.entries(candidateDocument.categories).flatMap(([category, repositories]) =>
        repositories.map(repository => ({ repository, subdirectory: ".", category }))
      ));
  const identities = new Set();
  for (const candidate of candidates) {
    if (identities.has(candidate.repository)) throw new Error(`duplicate candidate repository ${candidate.repository}`);
    identities.add(candidate.repository);
  }
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
      // Mirror npm-parity.mjs exactly: generate in `lock`, copy the generated
      // lock into `npm`, install there, and hash the post-install npm lock.
      const workspaceRoot = join(root, `reference-workspace-${index}`);
      const home = join(root, `home-${index}`);
      const { lock, install, npmDir, missingLock } = await runReferenceInstall(packageRoot, workspaceRoot, home);
      if (lock.status !== 0) {
        results.push({ ...candidate, commit, eligible: false, reason: "npm_lock_rejected", stderr: lock.stderr });
        continue;
      }
      if (missingLock) {
        results.push({
          ...candidate,
          commit,
          eligible: false,
          reason: "missing_package_lock",
          stderr: "npm completed successfully without producing package-lock.json"
        });
        continue;
      }
      if (install.status !== 0) {
        results.push({ ...candidate, commit, eligible: false, reason: "npm_install_rejected", stderr: install.stderr });
        continue;
      }
      let lockBytes;
      try {
        lockBytes = await readFile(join(npmDir, "package-lock.json"));
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
      const lockDigest = sha256(lockBytes);
      const lockArtifactName = `${candidate.repository.replaceAll("/", "__")}--${lockDigest}.json.gz`;
      await writeFile(join(outputDir, "locks", lockArtifactName), gzipSync(lockBytes, { level: 9 }));
      results.push({
        repository: candidate.repository,
        commit,
        subdirectory: candidate.subdirectory ?? ".",
        npm: npmReference,
        category: candidate.category,
        candidate_index: index,
        expected_lock_sha256: lockDigest,
        lock_artifact: `locks/${lockArtifactName}`,
        eligible: true
      });
      await rm(cwd, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  await mkdir(outputDir, { recursive: true });
  await writeFile(output, JSON.stringify({ schema_version: 1, npm: npmReference, node: nodeReference, shard, shards, results }, null, 2));
  console.log(JSON.stringify({ shard, tested: results.length, eligible: results.filter(result => result.eligible).length }, null, 2));
}

async function selfTest() {
  const root = await mkdtemp(join(tmpdir(), "oath-corpus-self-test-"));
  try {
    const source = join(root, "62");
    await mkdir(join(source, ".git"), { recursive: true });
    await mkdir(join(source, "dep"), { recursive: true });
    const packageDocument = { private: true, dependencies: { "fixture-dep": "file:./dep" } };
    await writeFile(join(source, "package.json"), JSON.stringify(packageDocument));
    await writeFile(join(source, "dep", "package.json"), JSON.stringify({ name: "fixture-dep", version: "1.0.0" }));
    await writeFile(join(source, ".git", "config"), "must not be copied");
    const workspaceRoot = join(root, "workspace");
    const lockDir = await prepareReferenceWorkspace(source, workspaceRoot, "lock");
    const npmDir = await prepareReferenceWorkspace(source, workspaceRoot, "npm");
    assert.equal(basename(lockDir), "lock");
    assert.equal(basename(npmDir), "npm");
    assert.deepEqual(await readJson(join(lockDir, "package.json")), packageDocument);
    assert.deepEqual(await readJson(join(npmDir, "package.json")), packageDocument);
    await assert.rejects(access(join(lockDir, ".git")));
    await assert.rejects(access(join(npmDir, ".git")));

    const reference = await runReferenceInstall(source, join(root, "reference"), join(root, "home"));
    assert.equal(reference.lock.status, 0);
    assert.equal(reference.install.status, 0);
    const lockBytes = await readFile(join(reference.npmDir, "package-lock.json"));
    const expectedLockSha256 = sha256(lockBytes);
    const pinnedLockPath = join(root, "pinned-lock.json.gz");
    await writeFile(pinnedLockPath, gzipSync(lockBytes, { level: 9 }));
    const parity = run(process.execPath, [resolve("scripts/npm-parity.mjs"), source], process.cwd(), {
      OATH_BIN: process.execPath,
      OATH_PINNED_LOCK_PATH: pinnedLockPath,
      OATH_PINNED_LOCK_SHA256: expectedLockSha256
    });
    const parityEvidence = JSON.parse(parity.stdout);
    assert.equal(expectedLockSha256, parityEvidence.reference.lock_sha256);
    assert.equal(expectedLockSha256, parityEvidence.reference.pinned_lock_sha256);
    assert.equal(parityEvidence.reference.pinned_lock_preserved, true);
    assert.equal(parityEvidence.reference.command, "install");
    const classificationBefore = Buffer.from(JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/example": { version: "1.0.0", devOptional: true } }
    }));
    const classificationAfter = Buffer.from(JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/example": { version: "1.0.0", dev: true } }
    }));
    const explainedMutation = analyzeLockMutation(classificationBefore, classificationAfter);
    assert.equal(explainedMutation.explained, true);
    assert.equal(explainedMutation.kind, "npm_dependency_classification");
    const semanticMutation = analyzeLockMutation(
      classificationBefore,
      Buffer.from(JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/example": { version: "2.0.0", devOptional: true } }
      }))
    );
    assert.equal(semanticMutation.explained, false);
    const unexpectedClassificationMutation = analyzeLockMutation(
      classificationBefore,
      Buffer.from(JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/example": { version: "1.0.0", optional: true } }
      }))
    );
    assert.equal(unexpectedClassificationMutation.explained, false);
    const rootClassificationMutation = analyzeLockMutation(
      Buffer.from(JSON.stringify({
        lockfileVersion: 3,
        packages: { "": { version: "1.0.0", devOptional: true } }
      })),
      Buffer.from(JSON.stringify({
        lockfileVersion: 3,
        packages: { "": { version: "1.0.0", dev: true } }
      }))
    );
    assert.equal(rootClassificationMutation.explained, false);
    const formattingMutation = analyzeLockMutation(
      classificationBefore,
      Buffer.from(`${JSON.stringify(JSON.parse(classificationBefore), null, 2)}\n`)
    );
    assert.equal(formattingMutation.explained, false);
    const aggregateProject = { expected_lock_sha256: "input" };
    const aggregateResult = {
      equivalent: true,
      reference: {
        npm: npmReference,
        command: "install",
        pinned_lock_sha256: "input",
        lock_sha256: "normalized",
        lock_mutation: { explained: true }
      }
    };
    assert.equal(aggregateFailure(aggregateProject, aggregateResult), null);
    assert.equal(aggregateFailure(aggregateProject, {
      ...aggregateResult,
      reference: { ...aggregateResult.reference, command: "ci" }
    }), "npm_reference_command_drift");
    assert.equal(aggregateFailure(aggregateProject, {
      ...aggregateResult,
      reference: { ...aggregateResult.reference, pinned_lock_sha256: "changed" }
    }), "pinned_lock_hash_drift");
    assert.equal(aggregateFailure(aggregateProject, {
      ...aggregateResult,
      reference: { ...aggregateResult.reference, lock_mutation: { explained: false } }
    }), "lock_hash_drift");
    const tampered = run(process.execPath, [resolve("scripts/npm-parity.mjs"), source], process.cwd(), {
      OATH_BIN: process.execPath,
      OATH_PINNED_LOCK_PATH: pinnedLockPath,
      OATH_PINNED_LOCK_SHA256: "0".repeat(64)
    });
    assert.notEqual(tampered.status, 0);
    assert.match(tampered.stderr, /pinned lock digest mismatch/);
    console.log(JSON.stringify({
      stable_lock_basename: true,
      stable_npm_basename: true,
      git_metadata_excluded: true,
      parity_lock_digest_matched: true,
      pinned_lock_digest_matched: true,
      pinned_lock_preserved: true,
      pinned_reference_uses_npm_install: true,
      dependency_classification_normalization_explained: true,
      semantic_lock_mutation_rejected: true,
      unexpected_classification_mutation_rejected: true,
      root_classification_mutation_rejected: true,
      formatting_only_lock_mutation_rejected: true,
      aggregate_rejects_unexplained_drift: true,
      tampered_lock_rejected: true
    }, null, 2));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function aggregate() {
  const manifestPath = resolve(process.env.OATH_PROJECT_MANIFEST ?? "tests/compat/projects.lock.json");
  const resultDir = resolve(process.env.OATH_COMPAT_RESULTS ?? "compat-results/ga");
  const manifest = await readJson(manifestPath);
  validateManifest(manifest);
  await validatePinnedLocks(manifest);
  const files = (await readdir(resultDir)).filter(name => /^project-shard-\d+\.json$/.test(name));
  const results = [];
  for (const file of files) results.push(...(await readJson(join(resultDir, file))).results);
  const byIdentity = new Map(results.map(result => [`${result.project}@${result.commit}`, result]));
  const failures = [];
  for (const project of manifest.projects) {
    const result = byIdentity.get(`${project.repository}@${project.commit}`);
    if (!result) failures.push({ repository: project.repository, reason: "missing_result" });
    else {
      const reason = aggregateFailure(project, result);
      if (reason) failures.push({ repository: project.repository, reason });
    }
  }
  const summary = { schema_version: 1, target: projectTarget, exact_equivalents: projectTarget - failures.length, failures };
  const output = resolve(process.env.OATH_PROJECT_AGGREGATE_OUTPUT ?? join(resultDir, "project-summary.json"));
  await writeFile(output, JSON.stringify(summary, null, 2));
  console.log(JSON.stringify(summary, null, 2));
  if (failures.length) process.exitCode = 1;
}

async function mergePreflight() {
  const input = resolve(process.env.OATH_PROJECT_PREFLIGHT_DIR ?? "compat-results/preflight");
  const output = resolve(process.env.OATH_PROJECT_MANIFEST ?? "tests/compat/projects.lock.json");
  const files = (await readdir(input)).filter(name => /^preflight-\d+\.json$/.test(name));
  const baseline = await readJson(resolve("tests/compat/projects.lock.json"));
  validateManifest(baseline, 100, 10);
  await validatePinnedLocks(baseline);
  const results = [];
  for (const file of files) {
    const artifact = await readJson(join(input, file));
    results.push(...artifact.results);
  }
  const eligible = results.filter(result => result.eligible);
  const unique = new Map(eligible.map(({ eligible: _, ...project }) => [project.repository, project]));
  const projects = [];
  const finalLockDir = resolve("tests/compat/project-locks");
  await mkdir(finalLockDir, { recursive: true });
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
    const retained = baseline.projects.filter(project => project.category === category);
    const retainedRepositories = new Set(retained.map(project => project.repository));
    const selectedNew = [...unique.values()]
      .filter(project => project.category === category)
      .filter(project => !retainedRepositories.has(project.repository))
      .sort((left, right) => left.candidate_index - right.candidate_index)
      .slice(0, projectsPerCategory - retained.length);
    const selected = [...retained, ...selectedNew];
    if (selected.length !== projectsPerCategory) shortages.push({ category, eligible: selected.length, required: projectsPerCategory });
    projects.push(...retained);
    for (const project of selectedNew) {
      const { candidate_index: _, lock_artifact: lockArtifact, ...projectFields } = project;
      if (!/^locks\/[A-Za-z0-9_.-]+\.json\.gz$/.test(lockArtifact)) {
        throw new Error(`${project.repository}: invalid preflight lock artifact`);
      }
      const lockFile = basename(lockArtifact);
      const lockPath = `tests/compat/project-locks/${lockFile}`;
      await cp(join(input, lockArtifact), resolve(lockPath));
      projects.push({ ...projectFields, lock_path: lockPath });
    }
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
  const manifest = { schema_version: 2, npm: npmReference, node: nodeReference, projects };
  validateManifest(manifest);
  await validatePinnedLocks(manifest);
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, JSON.stringify(manifest, null, 2));
  console.log(JSON.stringify({ output, projects: projects.length }, null, 2));
}

if (command === "preflight") await preflight();
else if (command === "merge-preflight") await mergePreflight();
else if (command === "validate") {
  const manifest = await readJson(resolve(process.argv[3] ?? "tests/compat/projects.lock.json"));
  const categories = validateManifest(manifest);
  const locksVerified = await validatePinnedLocks(manifest);
  console.log(JSON.stringify({ categories, locks_verified: locksVerified }, null, 2));
}
else if (command === "aggregate") await aggregate();
else if (command === "self-test") await selfTest();
else throw new Error(`unknown command ${command}`);
