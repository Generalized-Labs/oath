#!/usr/bin/env node
import { mkdtemp, cp, mkdir, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const referenceNpmMajor = 11;
const fixture = resolve(process.argv[2] ?? "tests/compat/fixtures/basic");
const oath = resolve(process.env.OATH_BIN ?? "target/debug/oath");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

function run(command, args, cwd, home = process.env.HOME ?? process.env.USERPROFILE ?? tmpdir(), extraEnv = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: Number(process.env.OATH_COMPAT_TIMEOUT_MS ?? 600_000),
    killSignal: "SIGKILL",
    shell: process.platform === "win32" && command.toLowerCase().endsWith(".cmd"),
    env: { ...process.env, CI: "1", HOME: home, OATH_HOME: join(home, ".oath"), npm_config_cache: join(home, ".npm"), ...extraEnv }
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    ...(result.error ? { error: { code: result.error.code, message: result.error.message } } : {})
  };
}

function treeEvidence(entries, includeTree) {
  return {
    tree_count: entries.length,
    tree_sha256: createHash("sha256").update(entries.join("\n")).digest("hex"),
    ...(includeTree ? { tree: entries } : {})
  };
}

async function tree(root) {
  const entries = [];
  async function walk(dir, prefix = "") {
    for (const item of (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      if (item.name === ".package-lock.json" || item.name === "oath-lock.json" || item.name === ".oath-store-manifest.json") continue;
      if (item.name === ".oath" || item.name === ".bin") continue;
      const relative = join(prefix, item.name);
      let directory = item.isDirectory();
      let child = join(dir, item.name);
      if (item.isSymbolicLink()) {
        child = await realpath(child);
        directory = (await stat(child)).isDirectory();
      }
      entries.push(`${directory ? "d" : "f"}:${relative}`);
      if (directory && prefix.split(/[\\/]/).length < 4) await walk(child, relative);
    }
  }
  await walk(root);
  return entries;
}

const npmVersion = run(npmCommand, ["--version"], process.cwd()).stdout.trim();
if (Number(npmVersion.split(".")[0]) !== referenceNpmMajor) {
  throw new Error(`npm ${referenceNpmMajor}.x is the parity reference; found ${npmVersion}`);
}

const root = await mkdtemp(join(tmpdir(), "oath-parity-"));
try {
  const mode = process.env.OATH_COMPAT_MODE ?? "clean";
  const npmDir = join(root, "npm");
  const oathDir = join(root, "oath");
  const lockDir = join(root, "lock");
  await cp(fixture, npmDir, { recursive: true });
  await cp(fixture, oathDir, { recursive: true });
  await cp(fixture, lockDir, { recursive: true });
  const home = join(root, "home");
  // Compare materialization semantics against the same registry snapshot. A
  // package published between the two sequential installs is resolution-time
  // drift, not a placement difference. npm's generated lock pins the exact
  // versions and integrities that Oath must reproduce. Force lock creation for
  // projects such as Express that disable package-lock in their checked-in npmrc.
  const lockResult = run(npmCommand, ["install", "--package-lock-only", "--ignore-scripts", "--package-lock=true"], lockDir, home);
  const lockSha256 = lockResult.status === 0
    ? createHash("sha256").update(await readFile(join(lockDir, "package-lock.json"))).digest("hex")
    : null;
  if (lockResult.status === 0) {
    await cp(join(lockDir, "package-lock.json"), join(npmDir, "package-lock.json"));
    await cp(join(lockDir, "package-lock.json"), join(oathDir, "package-lock.json"));
  }
  let npmResult = lockResult.status === 0
    ? run(npmCommand, ["install", "--ignore-scripts", "--package-lock=true"], npmDir, home)
    : lockResult;
  if (npmResult.status === 0 && mode !== "clean") {
    await rm(join(npmDir, "node_modules"), { recursive: true, force: true });
    const offline = mode === "offline";
    npmResult = run(npmCommand, ["install", "--ignore-scripts", "--package-lock=true", ...(offline ? ["--offline"] : [])], npmDir, home);
  }
  const npmTree = npmResult.status === 0 ? await tree(join(npmDir, "node_modules")) : [];

  // Real repositories can materialize tens of gigabytes. Persist the reference
  // tree in memory, then remove npm's node_modules before Oath starts so peak
  // disk is one materialized tree instead of two. The ordered entry list and
  // SHA-256 remain the exact comparison contract.
  await rm(join(npmDir, "node_modules"), { recursive: true, force: true });

  let oathResult = npmResult.status === 0
    ? run(oath, ["install", "--ignore-scripts"], oathDir, home)
    : { status: null, stdout: "", stderr: "skipped: reference npm rejected the project" };
  if (npmResult.status === 0 && oathResult.status === 0 && mode !== "clean") {
    await rm(join(oathDir, "node_modules"), { recursive: true, force: true });
    if (mode === "interrupted") {
      const stage = join(oathDir, ".oath-node_modules-stage");
      await mkdir(stage, { recursive: true });
      await writeFile(join(stage, "partial"), "interrupted");
    }
    const offline = mode === "offline";
    oathResult = run(oath, ["install", "--ignore-scripts"], oathDir, home, offline ? { npm_config_offline: "true" } : {});
  }
  const oathTree = oathResult.status === 0 ? await tree(join(oathDir, "node_modules")) : [];
  const npmSet = new Set(npmTree);
  const oathSet = new Set(oathTree);
  const includeTree = process.env.OATH_COMPAT_INCLUDE_TREES === "1";
  const artifact = {
    schema_version: 1,
    reference: { npm: npmVersion, lock_sha256: lockSha256 },
    fixture,
    mode,
    classification: npmResult.status === 0 ? "compared" : "reference_rejected",
    npm: { ...npmResult, ...treeEvidence(npmTree, includeTree) },
    oath: { ...oathResult, ...treeEvidence(oathTree, includeTree) },
    differences: {
      npm_only_count: npmTree.filter(entry => !oathSet.has(entry)).length,
      oath_only_count: oathTree.filter(entry => !npmSet.has(entry)).length,
      npm_only_sample: npmTree.filter(entry => !oathSet.has(entry)).slice(0, 100),
      oath_only_sample: oathTree.filter(entry => !npmSet.has(entry)).slice(0, 100)
    },
    equivalent: npmResult.status === 0 && oathResult.status === 0 && JSON.stringify(npmTree) === JSON.stringify(oathTree)
  };
  console.log(JSON.stringify(artifact, null, 2));
  if (!artifact.equivalent) process.exitCode = 1;
} finally {
  if (process.env.OATH_COMPAT_KEEP_FAILURE === "1" && process.exitCode) {
    console.error(`preserved failed comparison at ${root}`);
  } else {
    await rm(root, { recursive: true, force: true });
  }
}
