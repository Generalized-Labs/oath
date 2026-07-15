import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, verifySignedDocument } from "./oath-contracts.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const examples = [
  "exec-assessment-v3.signed.json",
  "publish-assessment-v2.signed.json",
  "registry-verdict-v1.signed.json",
];

for (const name of examples) {
  const document = JSON.parse(await readFile(join(here, "..", "examples", name), "utf8"));
  if (!verifySignedDocument(document)) throw new Error(`${name}: signature rejected`);
  document.generated_at += 1;
  if (verifySignedDocument(document)) throw new Error(`${name}: mutation was accepted`);
}

const unicodeKeys = { "\u{10000}": 1, "\uE000": 2 };
if (canonicalJson(unicodeKeys) !== '{"\uE000":2,"\u{10000}":1}') {
  throw new Error("canonical key ordering is not Unicode scalar order");
}

console.log(`verified ${examples.length} JavaScript contract fixtures`);
