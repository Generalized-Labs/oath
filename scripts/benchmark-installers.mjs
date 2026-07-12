#!/usr/bin/env node
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const oath = resolve(process.env.OATH_BIN ?? "target/release/oath");
const root = await mkdtemp(join(tmpdir(), "oath-installer-benchmark-"));
const manifest = {
  name: "oath-installer-benchmark",
  version: "1.0.0",
  private: true,
  dependencies: {
    chalk: "5.6.2",
    express: "5.1.0",
    "is-number": "7.0.0",
    typescript: "5.9.3",
    vite: "7.3.1"
  }
};

function run(command, args, cwd, home) {
  const started = process.hrtime.bigint();
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      CI: "1",
      HOME: home,
      OATH_HOME: join(home, ".oath"),
      npm_config_cache: join(home, ".npm"),
      BUN_INSTALL_CACHE_DIR: join(home, ".bun-cache")
    }
  });
  return {
    status: result.status,
    elapsed_ms: Number(process.hrtime.bigint() - started) / 1e6,
    stdout_tail: result.stdout.slice(-1000),
    stderr_tail: result.stderr.slice(-1000)
  };
}

async function treeDigest(dir) {
  const entries = [];
  async function walk(path, prefix = "") {
    let children;
    try { children = await import("node:fs/promises").then(fs => fs.readdir(path, { withFileTypes: true })); } catch { return; }
    for (const child of children.sort((a, b) => a.name.localeCompare(b.name))) {
      if (child.name === ".bin" || child.name === ".cache" || child.name === ".oath") continue;
      const relative = join(prefix, child.name);
      entries.push(`${child.isDirectory() ? "d" : "f"}:${relative}`);
      if (child.isDirectory()) await walk(join(path, child.name), relative);
    }
  }
  await walk(join(dir, "node_modules"));
  return {
    entries: entries.length,
    sha256: createHash("sha256").update(entries.join("\n")).digest("hex")
  };
}

try {
  const seed = join(root, "seed");
  await mkdir(seed);
  await writeFile(join(seed, "package.json"), JSON.stringify(manifest, null, 2));
  const seedHome = join(root, "seed-home");
  await mkdir(seedHome);
  const lock = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit"], seed, seedHome);
  if (lock.status !== 0) throw new Error(`lock generation failed: ${lock.stderr_tail}`);

  const installers = [
    { name: "npm", command: "npm", args: ["install", "--ignore-scripts", "--no-audit", "--package-lock=true"] },
    { name: "bun", command: "bun", args: ["install", "--ignore-scripts"] },
    { name: "oath", command: oath, args: ["install", "--ignore-scripts"] }
  ];
  const results = [];
  for (const installer of installers) {
    const cwd = join(root, installer.name);
    const home = join(root, `${installer.name}-home`);
    await cp(seed, cwd, { recursive: true });
    await mkdir(home);
    const cold = run(installer.command, installer.args, cwd, home);
    const coldTree = await treeDigest(cwd);
    await rm(join(cwd, "node_modules"), { recursive: true, force: true });
    const warm = run(installer.command, installer.args, cwd, home);
    const warmTree = await treeDigest(cwd);
    results.push({ installer: installer.name, cold, warm, cold_tree: coldTree, warm_tree: warmTree });
  }
  const artifact = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    platform: `${process.platform}-${process.arch}`,
    versions: {
      node: process.version,
      npm: run("npm", ["--version"], root, root).stdout_tail.trim(),
      bun: run("bun", ["--version"], root, root).stdout_tail.trim()
    },
    methodology: {
      dependency_manifest: manifest.dependencies,
      scripts: "disabled for every installer",
      npm_audit: "disabled",
      oath_scanner: "enabled",
      cold: "isolated installer cache and no node_modules",
      warm: "same cache after deleting node_modules"
    },
    results
  };
  const output = resolve(process.env.OATH_BENCHMARK_OUTPUT ?? "compat-results/benchmarks/installers.json");
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, JSON.stringify(artifact, null, 2));
  console.log(JSON.stringify(artifact, null, 2));
  if (results.some(result => result.cold.status !== 0 || result.warm.status !== 0)) process.exitCode = 1;
} finally {
  if (process.env.OATH_BENCHMARK_KEEP !== "1") await rm(root, { recursive: true, force: true });
}
