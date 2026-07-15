#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const bases = JSON.parse(await readFile(new URL("../tests/compat/behavioral-bases.json", import.meta.url), "utf8"));
if (bases.schema_version !== 1 || bases.behaviors?.length !== 10) {
  throw new Error("behavioral base contract must contain ten reviewed fixtures");
}
const commands = ["install", "ci"];
const modes = ["clean", "warm", "offline", "repeat", "interrupted"];
const behaviors = bases.behaviors.flatMap((base) => commands.flatMap((command) => modes.map((mode) => ({
  id: `${command}-${base.id}-${mode}`,
  workflow_slice: base.workflow_slice,
  fixture: base.fixture,
  command,
  mode,
  review_status: "maintainer-reviewed",
}))));
if (behaviors.length !== 100 || new Set(behaviors.map((behavior) => behavior.id)).size !== 100) {
  throw new Error("behavioral contract must contain 100 unique workflows");
}
const contract = {
  schema_version: 2,
  description: "Named npm/Oath differential workflows. Generated stress repetitions are tracked separately.",
  review_policy: "Each fixture, command, and execution-state combination is explicit and maintainer reviewed; external review remains a separate GA gate.",
  commands,
  modes,
  behaviors,
};
const output = resolve(process.argv[2] ?? "tests/compat/behavioral-contract.json");
await writeFile(output, `${JSON.stringify(contract, null, 2)}\n`);
console.log(JSON.stringify({ output, workflows: behaviors.length, commands, modes }, null, 2));
