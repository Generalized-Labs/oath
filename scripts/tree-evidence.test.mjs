import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { installedTree } from "./tree-evidence.mjs";

test("installedTree handles absent roots and ignores empty directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "oath-tree-evidence-"));
  try {
    assert.deepEqual(await installedTree(join(root, "missing")), []);
    await mkdir(join(root, "node_modules", "@empty"), { recursive: true });
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await writeFile(join(root, "node_modules", "pkg", "index.js"), "");
    assert.deepEqual(await installedTree(join(root, "node_modules")), [
      "d:pkg",
      "f:pkg/index.js"
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installedTree records a dangling link without dereferencing it", async (t) => {
  if (process.platform === "win32") return t.skip("symlink creation requires elevated Windows permissions");
  const root = await mkdtemp(join(tmpdir(), "oath-tree-evidence-"));
  try {
    await mkdir(join(root, "node_modules"));
    await symlink("../missing-workspace", join(root, "node_modules", "workspace"));
    assert.deepEqual(await installedTree(join(root, "node_modules")), ["l:workspace"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
