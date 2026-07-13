# Oath website

Technical-brutalist product site for Oath's evidence-first package execution model.

## Run with Oath

```sh
../target/release/oath ci
../target/release/oath run dev
```

Build the production bundle with:

```sh
../target/release/oath run build
```

The comparison copy deliberately separates the products' primary claims: npm is
the compatibility reference, Bun leads with speed, and Oath is positioned around
pre-execution evidence and enforced capability boundaries. The page does not
claim that static analysis proves safety.

The release figures shown on the page come from successful manual evidence run
[`29240267897`](https://github.com/Generalized-Labs/oath/actions/runs/29240267897)
plus post-merge exact-tree runs against Rspack, Karma, and Mattermost Webapp.
Generated stress executions, independent behavioral coverage, real-project
parity, and native capability reports are displayed as separate evidence
classes. The page does not turn three reviewed install behaviors into a claim
of complete npm workflow compatibility.
