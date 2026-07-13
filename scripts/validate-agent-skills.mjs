#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const skills = [
  ["oath-safe-package", ["--dry-run", "--json", "abstain", "not a safety proof", "Bun"]],
  ["oath-publish-transfer", ["oath transfer create", "oath transfer verify", "review-required", "stage download", "human"]]
];

for (const [name, required] of skills) {
  const root = new URL(`../.agents/skills/${name}/`, import.meta.url);
  const skill = await readFile(new URL("SKILL.md", root), "utf8");
  const evals = JSON.parse(await readFile(new URL("evals/evals.json", root), "utf8"));
  if (!skill.startsWith("---\n") || !skill.includes(`name: ${name}`)) {
    throw new Error(`${name}: invalid skill frontmatter`);
  }
  if (evals.skill_name !== name || !Array.isArray(evals.evals) || evals.evals.length < 2) {
    throw new Error(`${name}: expected at least two evals`);
  }
  for (const marker of required) {
    if (!skill.toLowerCase().includes(marker.toLowerCase())) {
      throw new Error(`${name}: missing safety marker ${marker}`);
    }
  }
  for (const evaluation of evals.evals) {
    if (!evaluation.prompt || !evaluation.expected_output || evaluation.expectations?.length < 3) {
      throw new Error(`${name}: incomplete eval ${evaluation.id}`);
    }
  }
}

console.log(JSON.stringify({ schema_version: 1, skills: skills.length, evals: 4, valid: true }, null, 2));
