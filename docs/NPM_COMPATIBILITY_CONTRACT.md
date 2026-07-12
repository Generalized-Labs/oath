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

The initial required matrix covers a pinned ordinary dependency, npm aliases,
and a local workspace. CI executes every case independently on Linux and macOS.
