#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";

const fixtureCount=500;
const projectTarget=100;
const out=resolve(process.env.OATH_COMPAT_RESULTS??"compat-results/ga");
const shard=Number(process.env.OATH_COMPAT_SHARD??0);
const shards=Number(process.env.OATH_COMPAT_SHARDS??1);
const execute=process.argv.includes("--execute");
const projects=(await readFile(new URL("../tests/compat/projects.txt",import.meta.url),"utf8")).split(/\r?\n/).map(v=>v.trim()).filter(v=>v&&!v.startsWith("#"));
if(projects.length!==projectTarget)throw new Error(`expected ${projectTarget} real projects, found ${projects.length}`);

const templates=["basic","alias","workspace"];
const fixtures=Array.from({length:fixtureCount},(_,id)=>({id,template:templates[id%templates.length],mode:["clean","warm","offline","repeat","interrupted"][Math.floor(id/templates.length)%5],shard:id%shards}));
await mkdir(out,{recursive:true});
await writeFile(join(out,"manifest.json"),JSON.stringify({schema_version:1,reference_npm_major:11,fixture_target:fixtureCount,project_target:projectTarget,shards,fixtures,projects},null,2));

const results=[];
if(execute){
  for(const fixture of fixtures.filter(item=>item.shard===shard)){
    const path=resolve("tests/compat/fixtures",fixture.template);
    const run=spawnSync(process.execPath,[resolve("scripts/npm-parity.mjs"),path],{encoding:"utf8",env:{...process.env,OATH_COMPAT_MODE:fixture.mode}});
    let artifact; try{artifact=JSON.parse(run.stdout)}catch{artifact={equivalent:false,stdout:run.stdout,stderr:run.stderr}}
    results.push({fixture,...artifact});
  }
  await writeFile(join(out,`fixture-shard-${shard}.json`),JSON.stringify({schema_version:1,shard,results},null,2));
  if(results.some(item=>!item.equivalent))process.exitCode=1;
}
console.log(JSON.stringify({fixture_target:fixtures.length,project_target:projects.length,shard,shards,executed:results.length,manifest:join(out,"manifest.json")},null,2));
