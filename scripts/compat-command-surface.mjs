#!/usr/bin/env node
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { installedTree } from "./tree-evidence.mjs";

const contract = JSON.parse(await readFile(new URL("../tests/compat/command-surface-contract.json", import.meta.url), "utf8"));
const manifest = JSON.parse(await readFile(new URL("../contracts/npm-compatibility-manifest-v1.json", import.meta.url), "utf8"));
const execute = process.argv.includes("--execute");
const selfTest = process.argv.includes("--self-test");
const caseIndex = process.argv.indexOf("--case");
const caseFilter = caseIndex === -1 ? null : process.argv[caseIndex + 1];
const output = resolve(process.env.OATH_COMPAT_RESULTS ?? "compat-results/command-surface");
const oath = resolve(process.env.OATH_BIN ?? "target/release/oath");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const timeoutMs = Number(process.env.OATH_COMPAT_COMMAND_TIMEOUT_MS ?? 600_000);
const registryToken = "oath-compat-token";
const registryUser = "oath-compat-user";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, stable(item)]));
  }
  return value;
}

function digest(value) {
  return `sha256:${sha256(JSON.stringify(stable(value)))}`;
}

function commandResult(result) {
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    timed_out: result.error?.code === "ETIMEDOUT",
    ...(result.error ? { error: { code: result.error.code ?? null, message: result.error.message } } : {}),
  };
}

function run(command, args, cwd, home, options = {}) {
  return commandResult(spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout: timeoutMs,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024 * 1024,
    input: options.input,
    shell: process.platform === "win32" && command.toLowerCase().endsWith(".cmd"),
    env: {
      ...process.env,
      CI: "1",
      NO_COLOR: "1",
      FORCE_COLOR: "0",
      HOME: home,
      USERPROFILE: home,
      OATH_HOME: join(home, ".oath"),
      npm_config_cache: join(home, ".npm"),
      npm_config_prefix: join(home, ".npm-global"),
      npm_config_userconfig: join(home, ".npmrc"),
      npm_config_audit: "false",
      npm_config_fund: "false",
      ...options.env,
    },
  }));
}

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function packageManifests(root) {
  const paths = ["package.json", "packages/a/package.json", "packages/b/package.json"];
  const entries = [];
  for (const relative of paths) {
    const path = join(root, relative);
    if (await exists(path)) {
      const value = await readJson(path);
      entries.push({
        path: relative,
        name: value.name ?? null,
        version: value.version ?? null,
        dependencies: stable(value.dependencies ?? {}),
        devDependencies: stable(value.devDependencies ?? {}),
      });
    }
  }
  return entries;
}

const UPDATE_DEPENDENCIES = {
  "package.json": ["lodash", "4.17.20", "^4.17.0"],
  "packages/a/package.json": ["chalk", "4.1.0", "^4.0.0"],
  "packages/b/package.json": ["debug", "4.3.4", "^4.0.0"],
};

async function configureUpdateManifests(root, useRanges) {
  for (const [relative, [name, exact, range]] of Object.entries(UPDATE_DEPENDENCIES)) {
    const path = join(root, relative);
    const manifest = await readJson(path);
    manifest.dependencies = { [name]: useRanges ? range : exact };
    await writeJson(path, manifest);
  }
}

async function workspaceDependencyVersions(root) {
  const versions = {};
  for (const [relative, [dependency]] of Object.entries(UPDATE_DEPENDENCIES)) {
    const manifest = await readJson(join(root, relative));
    const workspace = manifest.name;
    const workspaceRoot = dirname(join(root, relative));
    const candidates = [
      join(workspaceRoot, "node_modules", dependency, "package.json"),
      join(root, "node_modules", dependency, "package.json"),
    ];
    const packagePath = candidates.find(candidate => existsSync(candidate));
    versions[workspace] = packagePath ? (await readJson(packagePath)).version : null;
  }
  return versions;
}

async function semanticState(root) {
  const tree = await installedTree(join(root, "node_modules"));
  const manifests = await packageManifests(root);
  return {
    manifests,
    tree_count: tree.length,
    tree_digest: `sha256:${sha256(tree.join("\n"))}`,
  };
}

function packageJson(name, extra = {}) {
  return {
    name,
    version: "1.0.0",
    private: true,
    scripts: {
      probe: "node -e \"console.log(JSON.stringify({name:process.env.npm_package_name,args:process.argv.slice(1)}))\" --",
    },
    ...extra,
  };
}

async function createProject(root, { dependencies = {}, workspace = false } = {}) {
  if (!workspace) {
    await writeJson(join(root, "package.json"), packageJson("oath-command-surface", { dependencies }));
    await writeFile(join(root, "index.js"), "export const value = 1;\n");
    return;
  }
  await writeJson(join(root, "package.json"), packageJson("@oath-compat/root", {
    workspaces: ["packages/*"],
    dependencies,
  }));
  for (const leaf of ["a", "b"]) {
    await writeJson(join(root, "packages", leaf, "package.json"), packageJson(`@oath-compat/${leaf}`, { dependencies }));
    await writeFile(join(root, "packages", leaf, "index.js"), `export const workspace = ${JSON.stringify(leaf)};\n`);
  }
}

async function installProbeBin(packageRoot) {
  const bin = join(packageRoot, "node_modules", ".bin", "oath-compat-probe");
  await mkdir(dirname(bin), { recursive: true });
  await writeFile(bin, `#!/usr/bin/env node\nconst fs=require("node:fs");const p=JSON.parse(fs.readFileSync("package.json","utf8"));console.log(JSON.stringify({name:p.name,args:process.argv.slice(2)}));\n`);
  await chmod(bin, 0o755);
  await writeFile(`${bin}.cmd`, `@ECHO OFF\r\nnode "%~dp0\\oath-compat-probe" %*\r\n`);
}

async function createTwin(root, options = {}) {
  const npmDir = join(root, "npm");
  const oathDir = join(root, "oath");
  const npmHome = join(root, "npm-home");
  const oathHome = join(root, "oath-home");
  await mkdir(npmHome, { recursive: true });
  await mkdir(oathHome, { recursive: true });
  await createProject(npmDir, options);
  await cp(npmDir, oathDir, { recursive: true });
  return { npmDir, oathDir, npmHome, oathHome };
}

async function bootstrap(twin) {
  const npmInstall = run(npmCommand, ["install", "--ignore-scripts", "--no-audit", "--package-lock=true"], twin.npmDir, twin.npmHome);
  if (npmInstall.status !== 0) return { npm: npmInstall, oath: { status: null, stdout: "", stderr: "skipped after npm bootstrap failure" } };
  await cp(join(twin.npmDir, "package-lock.json"), join(twin.oathDir, "package-lock.json"));
  const oathInstall = run(oath, ["install", "--ignore-scripts"], twin.oathDir, twin.oathHome);
  return { npm: npmInstall, oath: oathInstall };
}

function compactOutput(value) {
  return value.replaceAll("\\", "/").replaceAll(/\/private\/var\/folders\/[^\s"']+/g, "<tmp>").replaceAll(/\/tmp\/[^\s"']+/g, "<tmp>").trim();
}

function jsonObjects(text) {
  const candidates = [text.trim()];
  const firstObject = text.indexOf("{");
  const firstArray = text.indexOf("[");
  for (const index of [firstObject, firstArray].filter(value => value >= 0).sort((a, b) => a - b)) candidates.push(text.slice(index).trim());
  for (const candidate of candidates) {
    try { return JSON.parse(candidate); } catch { /* try the next candidate */ }
  }
  return null;
}

function namesFromOutput(text) {
  return [...new Set([...text.matchAll(/@oath-compat\/(?:root|a|b)/g)].map(match => match[0]))].sort();
}

function probeRecords(text) {
  const records = [];
  for (const line of text.split(/\r?\n/)) {
    try {
      const value = JSON.parse(line.trim());
      if (typeof value?.name === "string" && Array.isArray(value?.args)) records.push({ name: value.name, args: value.args });
    } catch { /* npm and Oath may print non-JSON command banners */ }
  }
  return records.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

function versionsFromOutput(text) {
  return [...new Set([...text.matchAll(/\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b/g)].map(match => match[0]))].sort();
}

function packFiles(text) {
  const records = jsonRecords(text);
  return [...new Set(records.flatMap(record => (record.files ?? record.package?.files ?? [])
    .map(file => typeof file === "string" ? file : file.path)
    .filter(Boolean)))].sort();
}

function packageNamesFromJson(text) {
  const records = jsonRecords(text);
  return [...new Set(records.map(record => record.name ?? record.package?.name).filter(Boolean))].sort();
}

function jsonRecords(text) {
  const parsed = jsonObjects(text);
  if (Array.isArray(parsed)) return parsed;
  if (!parsed || typeof parsed !== "object") return [];
  if (parsed.name || parsed.files || parsed.package) return [parsed];
  const values = Object.values(parsed).filter(value => value && typeof value === "object");
  return values.length ? values : [parsed];
}

async function startRegistry(root) {
  const portFile = join(root, "registry-port");
  const logFile = join(root, "registry-requests.jsonl");
  const child = spawn(process.execPath, [resolve("scripts/compat-registry-fixture.mjs"), "--port-file", portFile, "--log-file", logFile], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, OATH_COMPAT_REGISTRY_TOKEN: registryToken, OATH_COMPAT_REGISTRY_USER: registryUser },
  });
  const started = Date.now();
  while (!(await exists(portFile))) {
    if (child.exitCode !== null) throw new Error(`registry fixture exited ${child.exitCode}`);
    if (Date.now() - started > 10_000) throw new Error("registry fixture did not start within ten seconds");
    await new Promise(resolvePromise => setTimeout(resolvePromise, 25));
  }
  const port = (await readFile(portFile, "utf8")).trim();
  return {
    child,
    url: `http://127.0.0.1:${port}/`,
    logFile,
    async stop() {
      if (child.exitCode === null) child.kill("SIGTERM");
      await new Promise(resolvePromise => child.once("exit", resolvePromise));
    },
  };
}

async function authRequests(logFile) {
  if (!(await exists(logFile))) return [];
  return (await readFile(logFile, "utf8")).split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).map(({ method, url, authorization }) => ({ method, url, authorization }));
}

function registryCredentialKey(url) {
  const parsed = new URL(url);
  return `//${parsed.host}${parsed.pathname}:_authToken`;
}

async function writeAuth(home, registry) {
  await writeFile(join(home, ".npmrc"), `registry=${registry}\n${registryCredentialKey(registry)}=${registryToken}\n`);
}

async function tokenPresent(home) {
  if (!(await exists(join(home, ".npmrc")))) return false;
  return (await readFile(join(home, ".npmrc"), "utf8")).includes(registryToken);
}

function observation(command, result, state, extra = {}) {
  const output = `${result.stdout}\n${result.stderr}`;
  const value = {
    status: result.status,
    timed_out: result.timed_out,
    state,
    ...extra,
  };
  if (command === "run" || command === "exec") value.command_probe = probeRecords(output);
  if (command === "view") value.package_versions = versionsFromOutput(output);
  if (command === "pack" || command === "publish") {
    value.package_names = packageNamesFromJson(result.stdout);
    value.pack_files = packFiles(result.stdout);
  }
  return value;
}

function comparableObservation(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

async function runBaseCase(command) {
  const root = await mkdtemp(join(tmpdir(), `oath-command-${command}-`));
  let registry = null;
  try {
    const dependencies = new Set(["install", "ci", "remove", "update", "ls", "outdated", "dedupe", "cache"]).has(command)
      ? { "is-number": command === "update" ? "^6.0.0" : "7.0.0" }
      : {};
    const twin = await createTwin(root, { dependencies });
    let npmResult;
    let oathResult;
    let npmExtra = {};
    let oathExtra = {};

    if (new Set(["remove", "update", "ls", "outdated", "dedupe", "cache"]).has(command)) {
      const prepared = await bootstrap(twin);
      if (prepared.npm.status !== 0 || prepared.oath.status !== 0) return { command, bootstrap: prepared };
    }

    switch (command) {
      case "install":
        npmResult = run(npmCommand, ["install", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["install", "--ignore-scripts"], twin.oathDir, twin.oathHome);
        break;
      case "ci": {
        const lock = run(npmCommand, ["install", "--package-lock-only", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        if (lock.status === 0) await cp(join(twin.npmDir, "package-lock.json"), join(twin.oathDir, "package-lock.json"));
        npmResult = lock.status === 0 ? run(npmCommand, ["ci", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome) : lock;
        oathResult = lock.status === 0 ? run(oath, ["ci"], twin.oathDir, twin.oathHome) : { status: null, stdout: "", stderr: "skipped after lock generation failure" };
        break;
      }
      case "add":
        npmResult = run(npmCommand, ["install", "is-number@7.0.0", "--save", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["add", "is-number@7.0.0", "--yes"], twin.oathDir, twin.oathHome);
        break;
      case "remove":
        npmResult = run(npmCommand, ["uninstall", "is-number", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["remove", "is-number"], twin.oathDir, twin.oathHome);
        break;
      case "update":
        npmResult = run(npmCommand, ["update", "is-number", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["update", "is-number"], twin.oathDir, twin.oathHome);
        break;
      case "run":
        npmResult = run(npmCommand, ["run", "probe", "--", "one", "two"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["run", "probe", "one", "two"], twin.oathDir, twin.oathHome);
        break;
      case "exec":
        await installProbeBin(twin.npmDir);
        await installProbeBin(twin.oathDir);
        npmResult = run(npmCommand, ["exec", "--", "oath-compat-probe", "one", "two"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["exec", "oath-compat-probe", "one", "two"], twin.oathDir, twin.oathHome);
        break;
      case "pack":
        npmResult = run(npmCommand, ["pack", "--dry-run", "--json", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["pack", "--dry-run", "--json"], twin.oathDir, twin.oathHome);
        break;
      case "publish":
        npmResult = run(npmCommand, ["publish", "--dry-run", "--json", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["publish", "--dry-run", "--json"], twin.oathDir, twin.oathHome);
        break;
      case "view":
        npmResult = run(npmCommand, ["view", "is-number@7.0.0", "version", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["view", "is-number@7.0.0"], twin.oathDir, twin.oathHome);
        break;
      case "ls":
        npmResult = run(npmCommand, ["ls", "--all", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["ls", "--depth", "99"], twin.oathDir, twin.oathHome);
        break;
      case "outdated":
        npmResult = run(npmCommand, ["outdated", "--json"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["outdated", "--json"], twin.oathDir, twin.oathHome);
        break;
      case "dedupe":
        npmResult = run(npmCommand, ["dedupe", "--dry-run", "--ignore-scripts", "--no-audit"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["dedupe", "--dry-run"], twin.oathDir, twin.oathHome);
        break;
      case "link": {
        npmResult = run(npmCommand, ["link", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["link"], twin.oathDir, twin.oathHome);
        const npmRoot = run(npmCommand, ["root", "--global"], twin.npmDir, twin.npmHome);
        const npmLink = join(npmRoot.stdout.trim(), "oath-command-surface");
        const oathLink = join(twin.oathHome, ".oath", "global", "node_modules", "oath-command-surface");
        npmExtra.link_valid = npmRoot.status === 0 && await exists(npmLink) && (await readlink(npmLink)).length > 0;
        oathExtra.link_valid = await exists(oathLink) && (await readlink(oathLink)).length > 0;
        break;
      }
      case "unlink": {
        const npmLinked = run(npmCommand, ["link", "--ignore-scripts"], twin.npmDir, twin.npmHome);
        const oathLinked = run(oath, ["link"], twin.oathDir, twin.oathHome);
        npmResult = npmLinked.status === 0 ? run(npmCommand, ["unlink", "--global", "--ignore-scripts"], twin.npmDir, twin.npmHome) : npmLinked;
        oathResult = oathLinked.status === 0 ? run(oath, ["unlink"], twin.oathDir, twin.oathHome) : oathLinked;
        const npmRoot = run(npmCommand, ["root", "--global"], twin.npmDir, twin.npmHome);
        npmExtra.link_removed = npmRoot.status === 0 && !(await exists(join(npmRoot.stdout.trim(), "oath-command-surface")));
        oathExtra.link_removed = !(await exists(join(twin.oathHome, ".oath", "global", "node_modules", "oath-command-surface")));
        break;
      }
      case "cache":
        npmResult = run(npmCommand, ["cache", "verify"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["cache", "verify"], twin.oathDir, twin.oathHome);
        break;
      case "config": {
        const registryUrl = "https://registry.npmjs.org/";
        await writeFile(join(twin.npmDir, ".npmrc"), `registry=${registryUrl}\n`);
        await writeFile(join(twin.oathDir, ".npmrc"), `registry=${registryUrl}\n`);
        npmResult = run(npmCommand, ["config", "get", "registry"], twin.npmDir, twin.npmHome);
        oathResult = run(oath, ["config", "registry", "--json"], twin.oathDir, twin.oathHome);
        npmExtra.registry = (npmResult.stdout.match(/https?:\/\/[^\s"']+/)?.[0] ?? "").replace(/\/+$/, "");
        oathExtra.registry = (oathResult.stdout.match(/https?:\/\/[^\s"']+/)?.[0] ?? "").replace(/\/+$/, "");
        break;
      }
      case "login": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        npmResult = run(npmCommand, ["whoami", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmExtra.authenticated_requests = (await authRequests(registry.logFile)).filter(request => request.authorization === "present");
        oathResult = run(oath, ["login", "--registry", registry.url, "--token-stdin", "--json"], twin.oathDir, twin.oathHome, { input: `${registryToken}\n` });
        oathExtra.authenticated_requests = (await authRequests(registry.logFile)).slice(npmExtra.authenticated_requests.length).filter(request => request.authorization === "present");
        npmExtra.identity = npmResult.stdout.trim().replaceAll('"', "");
        oathExtra.identity = jsonObjects(oathResult.stdout)?.username ?? null;
        npmExtra.reference_invocation = "npm whoami with a pre-provisioned token (npm has no non-interactive token-login command)";
        oathExtra.reference_invocation = npmExtra.reference_invocation;
        break;
      }
      case "logout": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["logout", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmExtra.authenticated_requests = (await authRequests(registry.logFile)).filter(request => request.authorization === "present");
        oathResult = run(oath, ["logout", "--registry", registry.url, "--json"], twin.oathDir, twin.oathHome);
        oathExtra.authenticated_requests = (await authRequests(registry.logFile)).slice(npmExtra.authenticated_requests.length).filter(request => request.authorization === "present");
        npmExtra.token_present = await tokenPresent(twin.npmHome);
        oathExtra.token_present = await tokenPresent(twin.oathHome);
        break;
      }
      case "whoami": {
        registry = await startRegistry(root);
        await writeAuth(twin.npmHome, registry.url);
        await writeAuth(twin.oathHome, registry.url);
        npmResult = run(npmCommand, ["whoami", "--registry", registry.url], twin.npmDir, twin.npmHome);
        npmExtra.authenticated_requests = (await authRequests(registry.logFile)).filter(request => request.authorization === "present");
        oathResult = run(oath, ["whoami", "--json"], twin.oathDir, twin.oathHome, { env: { npm_config_registry: registry.url } });
        oathExtra.authenticated_requests = (await authRequests(registry.logFile)).slice(npmExtra.authenticated_requests.length).filter(request => request.authorization === "present");
        npmExtra.identity = npmResult.stdout.trim().replaceAll('"', "");
        oathExtra.identity = jsonObjects(oathResult.stdout)?.username ?? null;
        break;
      }
      default:
        throw new Error(`unimplemented command case: ${command}`);
    }

    const npmState = await semanticState(twin.npmDir);
    const oathState = await semanticState(twin.oathDir);
    const npmObservation = comparableObservation(observation(command, npmResult, npmState, npmExtra));
    const oathObservation = comparableObservation(observation(command, oathResult, oathState, oathExtra));
    const equivalent = digest(npmObservation) === digest(oathObservation);
    return {
      id: `command-${command}`,
      workflow_slice: "command-surface",
      fixture: "generated-command-surface",
      command,
      mode: "clean",
      args: [],
      npm: { ...npmResult, tree_sha256: npmState.tree_digest.slice(7) },
      oath: { ...oathResult, tree_sha256: oathState.tree_digest.slice(7) },
      npm_observation: npmObservation,
      oath_observation: oathObservation,
      equivalent,
      reason: equivalent ? null : "normalized command semantics differed",
      ...(process.env.OATH_COMPAT_KEEP_FAILURE === "1" ? { debug_root: root } : {}),
    };
  } finally {
    if (registry) await registry.stop();
    if (process.env.OATH_COMPAT_KEEP_FAILURE !== "1") await rm(root, { recursive: true, force: true });
  }
}

function workspaceCommandArgs(command, form) {
  const npmFilter = form.args;
  const oathFilter = form.args;
  switch (command) {
    case "add": return { npm: ["install", "is-number@7.0.0", "--save", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["add", "is-number@7.0.0", "--yes", ...oathFilter] };
    case "remove": return { npm: ["uninstall", "is-number", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["remove", "is-number", ...oathFilter] };
    case "update": return { npm: ["update", "--ignore-scripts", "--no-audit", ...npmFilter], oath: ["update", ...oathFilter] };
    case "exec": return { npm: ["exec", ...npmFilter, "--", "oath-compat-probe", "workspace"], oath: ["exec", "oath-compat-probe", ...oathFilter, "workspace"] };
    case "pack": return { npm: ["pack", "--dry-run", "--json", "--ignore-scripts", ...npmFilter], oath: ["pack", "--dry-run", "--json", ...oathFilter] };
    case "publish": return { npm: ["publish", "--dry-run", "--json", "--ignore-scripts", ...npmFilter], oath: ["publish", "--dry-run", "--json", ...oathFilter] };
    default: throw new Error(`unimplemented workspace command: ${command}`);
  }
}

async function runWorkspaceCase(command, form) {
  const root = await mkdtemp(join(tmpdir(), `oath-workspace-${command}-${form.id}-`));
  try {
    const needsDependency = command === "remove" || command === "update";
    const twin = await createTwin(root, { workspace: true, dependencies: needsDependency ? { "is-number": "7.0.0" } : {} });
    if (command === "update") {
      await configureUpdateManifests(twin.npmDir, false);
      await configureUpdateManifests(twin.oathDir, false);
    }
    if (command === "publish") {
      for (const project of [twin.npmDir, twin.oathDir]) {
        for (const relative of ["package.json", "packages/a/package.json", "packages/b/package.json"]) {
          const path = join(project, relative);
          const value = await readJson(path);
          delete value.private;
          await writeJson(path, value);
        }
      }
    }
    if (needsDependency) {
      const prepared = await bootstrap(twin);
      if (prepared.npm.status !== 0 || prepared.oath.status !== 0) {
        return { id: `workspace-${command}-${form.id}`, command, form: form.id, bootstrap: prepared, equivalent: false, reason: "workspace bootstrap failed" };
      }
    }
    if (command === "update") {
      await configureUpdateManifests(twin.npmDir, true);
      await configureUpdateManifests(twin.oathDir, true);
    }
    if (command === "exec") {
      for (const relative of [".", "packages/a", "packages/b"]) {
        await installProbeBin(join(twin.npmDir, relative));
        await installProbeBin(join(twin.oathDir, relative));
      }
    }
    const beforeNpm = await packageManifests(twin.npmDir);
    const beforeOath = await packageManifests(twin.oathDir);
    const beforeNpmVersions = command === "update" ? await workspaceDependencyVersions(twin.npmDir) : null;
    const beforeOathVersions = command === "update" ? await workspaceDependencyVersions(twin.oathDir) : null;
    const args = workspaceCommandArgs(command, form);
    const npmResult = run(npmCommand, args.npm, twin.npmDir, twin.npmHome);
    const oathResult = run(oath, args.oath, twin.oathDir, twin.oathHome);
    const afterNpm = await packageManifests(twin.npmDir);
    const afterOath = await packageManifests(twin.oathDir);
    const changed = (before, after) => after.filter((entry, index) => digest(entry) !== digest(before[index])).map(entry => entry.name).sort();
    const npmState = await semanticState(twin.npmDir);
    const oathState = await semanticState(twin.oathDir);
    const outputSelected = result => command === "exec"
      ? probeRecords(`${result.stdout}\n${result.stderr}`).map(record => record.name).sort()
      : packageNamesFromJson(result.stdout).length
        ? packageNamesFromJson(result.stdout)
        : namesFromOutput(`${result.stdout}\n${result.stderr}`);
    const changedVersions = (before, after) => Object.keys(after).filter(name => after[name] !== before[name]).sort();
    const npmNames = command === "exec" || command === "pack" || command === "publish"
      ? outputSelected(npmResult)
      : command === "update" ? changedVersions(beforeNpmVersions, await workspaceDependencyVersions(twin.npmDir)) : changed(beforeNpm, afterNpm);
    const oathNames = command === "exec" || command === "pack" || command === "publish"
      ? outputSelected(oathResult)
      : command === "update" ? changedVersions(beforeOathVersions, await workspaceDependencyVersions(twin.oathDir)) : changed(beforeOath, afterOath);
    const npmObservation = {
      status: npmResult.status,
      selected: npmNames,
      expected_selected: form.selected,
      manifests: npmState.manifests,
      tree_digest: npmState.tree_digest,
    };
    const oathObservation = {
      status: oathResult.status,
      selected: oathNames,
      expected_selected: form.selected,
      manifests: oathState.manifests,
      tree_digest: oathState.tree_digest,
    };
    const equivalent = digest(npmObservation) === digest(oathObservation) && npmNames.length > 0 && JSON.stringify(npmNames) === JSON.stringify(form.selected);
    return {
      id: `workspace-${command}-${form.id}`,
      workflow_slice: "workspace-filtering",
      fixture: "generated-workspace",
      command,
      mode: "workspace",
      workspace_form: form.id,
      args: form.args,
      expected_selected: form.selected,
      npm: { ...npmResult, tree_sha256: npmState.tree_digest.slice(7) },
      oath: { ...oathResult, tree_sha256: oathState.tree_digest.slice(7) },
      npm_observation: npmObservation,
      oath_observation: oathObservation,
      equivalent,
      reason: equivalent ? null : "workspace selection or resulting state differed",
      ...(process.env.OATH_COMPAT_KEEP_FAILURE === "1" ? { debug_root: root } : {}),
    };
  } finally {
    if (process.env.OATH_COMPAT_KEEP_FAILURE !== "1") await rm(root, { recursive: true, force: true });
  }
}

function validateContract() {
  const errors = [];
  const required = [...manifest.ga_required_commands].sort();
  const declared = [...contract.commands].sort();
  if (JSON.stringify(required) !== JSON.stringify(declared)) errors.push("command-surface contract must cover every GA-required command exactly once");
  if (new Set(contract.commands).size !== contract.commands.length) errors.push("command-surface commands must be unique");
  if (new Set(contract.workspace_forms.map(form => form.id)).size !== contract.workspace_forms.length) errors.push("workspace filter forms must be unique");
  for (const form of contract.workspace_forms) {
    if (!Array.isArray(form.args) || !form.args.length || !Array.isArray(form.selected) || !form.selected.length) errors.push(`workspace form ${form.id} is incomplete`);
  }
  return errors;
}

async function main() {
  const contractErrors = validateContract();
  if (contractErrors.length) throw new Error(contractErrors.join("; "));
  if (selfTest) {
    console.log(JSON.stringify({ self_test: "passed", commands: contract.commands.length, workspace_forms: contract.workspace_forms.length, workspace_cases: contract.workspace_commands.length * contract.workspace_forms.length }, null, 2));
    return;
  }
  const npmVersion = run(npmCommand, ["--version"], process.cwd(), tmpdir()).stdout.trim();
  if (!execute) {
    console.log(JSON.stringify({ execute: false, commands: contract.commands.length, workspace_cases: contract.workspace_commands.length * contract.workspace_forms.length }, null, 2));
    return;
  }
  if (!existsSync(oath)) throw new Error(`Oath binary does not exist: ${oath}`);
  const results = [];
  for (const command of contract.commands) {
    if (caseFilter && caseFilter !== `command-${command}`) continue;
    const result = await runBaseCase(command);
    results.push(result);
    console.error(`${result.equivalent ? "PASS" : "FAIL"} ${result.id ?? command}`);
  }
  for (const command of contract.workspace_commands) {
    for (const form of contract.workspace_forms) {
      if (caseFilter && caseFilter !== `workspace-${command}-${form.id}`) continue;
      const result = await runWorkspaceCase(command, form);
      results.push(result);
      console.error(`${result.equivalent ? "PASS" : "FAIL"} ${result.id}`);
    }
  }
  const report = {
    schema_version: 1,
    evidence_class: "independent_behavioral",
    suite: "full-command-surface",
    generated_at: new Date().toISOString(),
    release_commit: process.env.GITHUB_SHA ?? process.env.OATH_RELEASE_COMMIT ?? null,
    platform: process.platform,
    architecture: process.arch,
    node_version: process.version,
    reference_npm: npmVersion,
    independent_behavior_target: results.length,
    executed: results.length,
    equivalent: results.filter(result => result.equivalent).length,
    failed: results.filter(result => !result.equivalent).length,
    results,
  };
  await mkdir(output, { recursive: true });
  await writeFile(join(output, "behavioral-summary.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ output: join(output, "behavioral-summary.json"), executed: report.executed, equivalent: report.equivalent, failed: report.failed }, null, 2));
  if (report.failed) process.exitCode = 1;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.stack ?? error.message);
    process.exitCode = 1;
  });
}
