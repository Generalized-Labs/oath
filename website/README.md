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

The release figures shown on the page come from the merged compatibility and
native-containment evidence plus post-merge exact-tree runs against Express,
Koa, and Redux. The 100-project GA corpus remains a separate release gate.
