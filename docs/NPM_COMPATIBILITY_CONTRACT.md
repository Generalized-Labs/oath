# npm compatibility contract

Oath targets workflow parity with npm 11 for install, ci, add/remove, run,
exec, workspaces, lockfile import, registry authentication, peer dependencies,
overrides, aliases, git/file/tarball dependencies, lifecycle behavior, and exit
status. Registry administration commands are outside this contract.

`scripts/npm-parity.mjs` is the executable differential specification. It runs
the same fixture in isolated temporary directories and emits a versioned JSON
artifact containing the pinned npm version, command results, normalized
`node_modules` trees, and equivalence decision. Differences are failures unless
documented as intentional security divergences with a stable Oath reason code.

The semantic tree comparison follows package links and excludes npm's
`.package-lock.json` plus Oath's `.oath` content-addressed implementation data.
Oath's internal `.oath-store-manifest.json` integrity record is also excluded.
The installed package names and package contents must still be identical.

The required fixture corpus grows monotonically. Each fixed compatibility bug
must add a fixture before release.

The source matrix covers ten named behaviors: production and development
dependencies, optional dependencies, a peer pair, root overrides, nested
version placement, scoped packages, dist-tags, npm aliases, and a local
workspace. CI executes every case independently on Linux, macOS, and Windows.
The last signed baseline covers the original three; the expanded denominator is
not public release evidence until the exact-commit cross-platform run passes.
Ten reviewed behaviors are not proof of complete npm workflow coverage;
generated stress repetitions are reported separately.

The real-project corpus is a frozen-input `npm install` materialization
contract. It verifies the exact lock digest before both runs. If npm rewrites
the output lock, only the paired `devOptional: true` to `dev: true` package
classification normalization may differ, and every changed JSON path is
retained in the evidence. All other lock changes fail. `npm ci` remains a
separate workflow contract and is not inferred from the real-project install
corpus.

Known intentional fail-closed boundary: git dependencies must use an exact branch,
tag, or commit. npm-style `#semver:` git selectors are rejected with a stable
error instead of silently resolving a moving `HEAD`; exact tag-range resolution
remains outside the current supported slice.
