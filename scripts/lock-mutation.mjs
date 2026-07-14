const missing = Symbol("missing");

function diffJson(before, after, path = [], changes = []) {
  if (Object.is(before, after)) return changes;
  if (before === missing || after === missing) {
    changes.push({ path, before, after });
    return changes;
  }
  if (Array.isArray(before) || Array.isArray(after)) {
    if (!Array.isArray(before) || !Array.isArray(after) || before.length !== after.length) {
      changes.push({ path, before, after });
      return changes;
    }
    for (let index = 0; index < before.length; index++) {
      diffJson(before[index], after[index], [...path, index], changes);
    }
    return changes;
  }
  if (before && after && typeof before === "object" && typeof after === "object") {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    for (const key of keys) {
      diffJson(
        Object.hasOwn(before, key) ? before[key] : missing,
        Object.hasOwn(after, key) ? after[key] : missing,
        [...path, key],
        changes
      );
    }
    return changes;
  }
  changes.push({ path, before, after });
  return changes;
}

function wireValue(value) {
  return value === missing ? { present: false } : { present: true, value };
}

function sampleChanges(changes) {
  return changes.slice(0, 20).map(change => ({
    path: change.path,
    before: wireValue(change.before),
    after: wireValue(change.after)
  }));
}

function knownClassificationNormalization(changes) {
  const byPackage = new Map();
  for (const change of changes) {
    if (change.path.length !== 3 || change.path[0] !== "packages") return false;
    const packagePath = change.path[1];
    if (typeof packagePath !== "string" || !packagePath.startsWith("node_modules/")) return false;
    if (!byPackage.has(packagePath)) byPackage.set(packagePath, []);
    byPackage.get(packagePath).push(change);
  }
  for (const packageChanges of byPackage.values()) {
    if (packageChanges.length !== 2) return false;
    const dev = packageChanges.find(change => change.path[2] === "dev");
    const devOptional = packageChanges.find(change => change.path[2] === "devOptional");
    if (!dev || dev.before !== missing || dev.after !== true) return false;
    if (!devOptional || devOptional.before !== true || devOptional.after !== missing) return false;
  }
  return byPackage.size > 0;
}

export function analyzeLockMutation(beforeBytes, afterBytes) {
  if (Buffer.compare(beforeBytes, afterBytes) === 0) {
    return { changed: false, explained: true, kind: "none", change_count: 0, changes_sample: [] };
  }
  let before;
  let after;
  try {
    before = JSON.parse(beforeBytes);
    after = JSON.parse(afterBytes);
  } catch (error) {
    return {
      changed: true,
      explained: false,
      kind: "invalid_json",
      change_count: null,
      changes_sample: [],
      error: error.message
    };
  }
  const changes = diffJson(before, after);
  if (changes.length === 0) {
    return { changed: true, explained: false, kind: "formatting_only", change_count: 0, changes_sample: [] };
  }
  const explained = knownClassificationNormalization(changes);
  return {
    changed: true,
    explained,
    kind: explained ? "npm_dependency_classification" : "unexplained",
    change_count: changes.length,
    affected_packages: explained ? new Set(changes.map(change => change.path[1])).size : null,
    changes_sample: sampleChanges(changes)
  };
}
