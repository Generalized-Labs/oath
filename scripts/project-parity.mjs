#!/usr/bin/env node
import { copyFile,mkdtemp,readFile,rm,writeFile,mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join,resolve } from "node:path";
import { spawnSync } from "node:child_process";
const shard=Number(process.env.OATH_PROJECT_SHARD??0),shards=Number(process.env.OATH_PROJECT_SHARDS??1);
const limit=Number(process.env.OATH_PROJECT_LIMIT??Number.POSITIVE_INFINITY);
const start=Number(process.env.OATH_PROJECT_START??0);
const failFast=process.env.OATH_PROJECT_FAIL_FAST==="1";
const manifestPath=process.env.OATH_PROJECT_MANIFEST;
let projects;
if(manifestPath){
 const manifest=JSON.parse(await readFile(resolve(manifestPath),"utf8"));
 if(manifest.schema_version!==1||manifest.npm!=="11.12.1"||manifest.node!=="24.13.0"||!Array.isArray(manifest.projects))throw new Error("invalid pinned project manifest");
 if(process.versions.node!==manifest.node)throw new Error(`pinned project corpus requires Node ${manifest.node}; found ${process.versions.node}`);
 projects=manifest.projects;
}else{
 projects=(await readFile(new URL("../tests/compat/projects.txt",import.meta.url),"utf8")).split(/\r?\n/).map(v=>v.trim()).filter(Boolean).map(repository=>({repository}));
}
if(projects.length!==100)throw new Error(`expected 100 projects, found ${projects.length}`);
const root=await mkdtemp(join(tmpdir(),"oath-projects-")); const results=[];
const out=resolve(process.env.OATH_COMPAT_RESULTS??"compat-results/ga");await mkdir(out,{recursive:true});
const checkpoint=()=>writeFile(join(out,`project-shard-${shard}.json`),JSON.stringify({schema_version:1,shard,results},null,2));
try{
 const parityScript=join(root,"npm-parity.mjs");
 await copyFile(resolve("scripts/npm-parity.mjs"),parityScript);
 let selectedIndex=0;
 for(const [index,projectSpec] of projects.entries()){
  if(index%shards!==shard)continue;
  if(selectedIndex++<start)continue;
  if(results.length>=limit)break;
  const project=projectSpec.repository;
  console.error(`[project ${results.length+1}] ${project}${projectSpec.commit?`@${projectSpec.commit}`:""}`);
  const cwd=join(root,String(index));
  const cloneArgs=projectSpec.commit
   ? ["clone","--filter=blob:none","--no-checkout",`https://github.com/${project}.git`,cwd]
   : ["clone","--depth=1",`https://github.com/${project}.git`,cwd];
  const clone=spawnSync("git",cloneArgs,{encoding:"utf8",timeout:300_000});
  if(clone.status!==0){
   results.push({project,equivalent:false,phase:"clone",stderr:clone.stderr});
   await checkpoint();
   if(failFast)break;
   continue;
  }
  if(projectSpec.commit){
   const fetch=spawnSync("git",["fetch","--depth=1","origin",projectSpec.commit],{cwd,encoding:"utf8",timeout:300_000});
   const checkout=fetch.status===0?spawnSync("git",["checkout","--detach",projectSpec.commit],{cwd,encoding:"utf8",timeout:60_000}):fetch;
   if(checkout.status!==0){results.push({project,commit:projectSpec.commit,equivalent:false,phase:"checkout",stderr:checkout.stderr});await checkpoint();continue;}
  }
  await rm(join(cwd,".git"),{recursive:true,force:true});
  const sha=projectSpec.commit??spawnSync("git",["ls-remote",`https://github.com/${project}.git`,"HEAD"],{encoding:"utf8",timeout:60_000}).stdout.split(/\s/)[0];
  const projectRoot=resolve(cwd,projectSpec.subdirectory??".");
  const run=spawnSync(process.execPath,[parityScript,projectRoot],{encoding:"utf8",maxBuffer:64*1024*1024,timeout:Number(process.env.OATH_PROJECT_TIMEOUT_MS??300_000),env:{...process.env}});
  let evidence;
  if(run.error){
   evidence={equivalent:false,classification:run.error.code==="ETIMEDOUT"?"harness_timeout":"harness_error",error:run.error.message,stdout:run.stdout,stderr:run.stderr};
  }else{
   try{evidence=JSON.parse(run.stdout)}catch{evidence={equivalent:false,classification:"invalid_harness_output",stdout:run.stdout,stderr:run.stderr}}
  }
  if(projectSpec.expected_lock_sha256&&evidence.reference?.lock_sha256!==projectSpec.expected_lock_sha256){
   evidence={...evidence,equivalent:false,classification:"lock_hash_drift",expected_lock_sha256:projectSpec.expected_lock_sha256};
  }
  results.push({project,commit:sha,category:projectSpec.category,...evidence});
  await checkpoint();
  console.error(`[project ${results.length}] ${project}: ${evidence.equivalent?"passed":"failed"}`);
  await rm(cwd,{recursive:true,force:true});
  if(failFast&&!evidence.equivalent)break;
 }
 await checkpoint();
 console.log(JSON.stringify({shard,projects:results.length,passed:results.filter(v=>v.equivalent).length},null,2));
 if(results.some(v=>!v.equivalent))process.exitCode=1;
}finally{await rm(root,{recursive:true,force:true});}
