import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const root = resolve(import.meta.dirname, "..");

async function read(relativePath) {
  return readFile(resolve(root, relativePath), "utf8");
}

function requireMatch(contents, pattern, label) {
  if (!pattern.test(contents)) {
    throw new Error(`${label} does not declare Apache-2.0`);
  }
}

const [cargoToml, packageJson, packageLock, readme, notice, license] = await Promise.all([
  read("Cargo.toml"),
  read("website/package.json"),
  read("website/package-lock.json"),
  read("README.md"),
  read("NOTICE"),
  read("LICENSE"),
]);

requireMatch(cargoToml, /^license = "Apache-2\.0"$/m, "Cargo workspace metadata");
requireMatch(readme, /\[Apache License 2\.0\]\(LICENSE\)/, "README");
requireMatch(notice, /^Oath\nCopyright 2026 Generalized Labs\n/m, "NOTICE");
requireMatch(
  license,
  /^                                 Apache License\n                           Version 2\.0, January 2004$/m,
  "LICENSE",
);

const website = JSON.parse(packageJson);
const lock = JSON.parse(packageLock);
if (website.license !== "Apache-2.0") {
  throw new Error("website package metadata does not declare Apache-2.0");
}
if (lock.packages?.[""]?.license !== "Apache-2.0") {
  throw new Error("website lockfile root metadata does not declare Apache-2.0");
}

console.log("Apache-2.0 license declarations are consistent");
