import { readdir, realpath, stat } from "node:fs/promises";
import { join } from "node:path";

const ignoredEntries = new Set([
  ".package-lock.json",
  "oath-lock.json",
  ".oath-store-manifest.json",
  ".oath",
  ".bin"
]);

export async function installedTree(root) {
  async function walk(dir, prefix = "") {
    let items;
    try {
      items = await readdir(dir, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }

    const entries = [];
    for (const item of items.sort((a, b) => a.name.localeCompare(b.name))) {
      if (ignoredEntries.has(item.name)) continue;
      const relative = join(prefix, item.name);
      let directory = item.isDirectory();
      let child = join(dir, item.name);
      if (item.isSymbolicLink()) {
        try {
          child = await realpath(child);
          directory = (await stat(child)).isDirectory();
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
          entries.push(`l:${relative}`);
          continue;
        }
      }

      if (!directory) {
        entries.push(`f:${relative}`);
        continue;
      }

      if (prefix.split(/[\\/]/).length >= 4) {
        entries.push(`d:${relative}`);
        continue;
      }

      const descendants = await walk(child, relative);
      // npm can leave empty scope directories after deduplication. They carry
      // no package contents and Oath intentionally does not materialize them.
      if (descendants.length > 0) entries.push(`d:${relative}`, ...descendants);
    }
    return entries;
  }

  return walk(root);
}
