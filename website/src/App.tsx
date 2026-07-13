import {
  ArrowDownRight,
  ArrowUpRight,
  Check,
  Copy,
  Fingerprint,
  Network,
  ShieldAlert,
  Terminal,
  X,
} from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";

const competitors = [
  {
    name: "npm / npx",
    role: "Compatibility reference",
    verdict: "RUNS FIRST",
    tone: "plain",
    rows: ["npm 11 workflow semantics", "Install-script controls", "No capability manifest", "No native execution boundary"],
  },
  {
    name: "Bun / bunx",
    role: "Speed reference",
    verdict: "SPEED FIRST",
    tone: "hazard",
    rows: ["Fast package installs", "Safer script defaults", "No evidence-backed verdict", "No Oath-style sandbox plan"],
  },
  {
    name: "Oath",
    role: "Trust reference",
    verdict: "EVIDENCE FIRST",
    tone: "cobalt",
    rows: ["npm 11 placement contract", "Hash-bound approvals", "Capability + risk assessment", "Linux / Windows containment"],
  },
];

const manifestRows = [
  ["IDENTITY", "prettier@3.7.4", "VERIFIED"],
  ["INTEGRITY", "sha512-8f0c…91da", "PINNED"],
  ["PUBLISH AGE", "14 days", "STABLE"],
  ["OWNER CHANGE", "none detected", "CLEAR"],
  ["LIFECYCLE", "0 install hooks", "CLEAR"],
  ["FILESYSTEM", "project:read", "GRANT"],
  ["NETWORK", "denied", "ENFORCED"],
  ["SANDBOX", "landlock+seccomp-v3", "ACTIVE"],
];

const proof = [
  ["500 / 500", "generated stress executions"],
  ["100 / 100", "pinned real-project trees"],
  ["3 / 3", "independent install behaviors"],
  ["4 / 4", "native runner capability reports"],
];

const postMergeProjects = [
  ["Rspack", "4,208", "c14b…c2d"],
  ["Karma", "33,719", "404c…f7c"],
  ["Mattermost", "70,449", "bbe6…bb0"],
];

const evidenceRun = "https://github.com/Generalized-Labs/oath/actions/runs/29240267897";

function App() {
  const [copied, setCopied] = useState(false);
  const command = "oath exec --dry-run --json prettier@3.7.4";

  const copyCommand = async () => {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <main className="min-h-screen overflow-hidden bg-paper text-carbon">
      <a href="#main-content" className="skip-link">Skip to content</a>

      <header className="border-b-2 border-carbon">
        <div className="grid min-h-20 grid-cols-[1fr_auto] items-stretch lg:grid-cols-[260px_1fr_auto]">
          <a href="#" className="flex items-center gap-3 border-r-2 border-carbon px-5 font-display text-3xl font-black uppercase tracking-[-0.08em] lg:px-8">
            <Fingerprint className="h-7 w-7 stroke-[2.5]" aria-hidden="true" /> Oath
          </a>
          <div className="hidden items-center px-8 font-mono text-[10px] font-bold uppercase tracking-[0.22em] lg:flex">
            Package execution / evidence protocol / v0.2.0 candidate
          </div>
          <nav className="flex items-center" aria-label="Primary navigation">
            <a href="#proof" className="nav-link">Proof</a>
            <a href="#compare" className="nav-link hidden sm:flex">Compare</a>
            <a href="https://github.com/Generalized-Labs/oath" className="nav-link border-r-0" target="_blank" rel="noreferrer">
              GitHub <ArrowUpRight className="h-3.5 w-3.5" />
            </a>
          </nav>
        </div>
      </header>

      <div className="signal-tape" aria-hidden="true">
        <div className="signal-tape-track">
          EXECUTION REQUIRES EVIDENCE // HASH CHANGED: REASSESS // NETWORK DENIED // EXACT PACKAGE, EXACT POLICY // EXECUTION REQUIRES EVIDENCE // HASH CHANGED: REASSESS // NETWORK DENIED // EXACT PACKAGE, EXACT POLICY //
        </div>
      </div>

      <section id="main-content" className="grid border-b-2 border-carbon lg:grid-cols-[minmax(0,1.08fr)_minmax(480px,.92fr)]">
        <div className="relative flex min-h-[680px] flex-col justify-between border-b-2 border-carbon p-5 sm:p-8 lg:border-b-0 lg:border-r-2 lg:p-12">
          <div className="absolute right-0 top-0 hidden border-b-2 border-l-2 border-carbon bg-hazard px-4 py-2 font-mono text-[10px] font-bold uppercase tracking-[0.2em] sm:block">
            Trust boundary: before exec
          </div>
          <div>
            <p className="mb-10 flex items-center gap-2 font-mono text-xs font-bold uppercase tracking-[0.18em]">
              <span className="status-dot" /> Security-first npm / npx replacement
            </p>
            <h1 className="max-w-[920px] font-display text-[clamp(4rem,10.5vw,9.8rem)] font-black uppercase leading-[0.76] tracking-[-0.085em]">
              Before the package <span className="text-cobalt">runs,</span> see the case against it.
            </h1>
          </div>

          <div className="mt-16 grid gap-8 xl:grid-cols-[1fr_auto] xl:items-end">
            <p className="max-w-xl text-lg font-semibold leading-snug sm:text-xl">
              Oath uses npm 11’s pinned placement contract, then adds identity, provenance, behavioral diff, capability policy, and a native containment boundary before unfamiliar code gets a process.
            </p>
            <Button size="lg" asChild>
              <a href="#manifest">Inspect the manifest <ArrowDownRight className="h-5 w-5" /></a>
            </Button>
          </div>
        </div>

        <div id="manifest" className="bg-carbon p-3 text-paper sm:p-6 lg:p-8">
          <div className="flex h-full min-h-[610px] flex-col border-2 border-paper">
            <div className="flex items-center justify-between border-b-2 border-paper p-4">
              <div className="flex items-center gap-3 font-mono text-xs font-bold uppercase tracking-[0.14em]">
                <Terminal className="h-4 w-4 text-hazard" /> Example exec assessment / schema 2
              </div>
              <span className="bg-paper px-2 py-1 font-mono text-[9px] font-black text-carbon">ILLUSTRATIVE</span>
            </div>
            <div className="border-b-2 border-paper p-4 sm:p-6">
              <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-evidence">Requested command</div>
              <div className="flex items-center justify-between gap-4">
                <code className="overflow-x-auto whitespace-nowrap font-mono text-sm font-bold text-white sm:text-base">$ {command}</code>
                <button className="copy-button" onClick={copyCommand} aria-label="Copy Oath command">
                  {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
            </div>
            <div className="flex-1">
              {manifestRows.map(([label, value, state], index) => (
                <div className="manifest-row" key={label}>
                  <span className="text-evidence">{String(index + 1).padStart(2, "0")} / {label}</span>
                  <strong>{value}</strong>
                  <span className={state === "GRANT" ? "text-hazard" : "text-[#62ff8c]"}>{state}</span>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-2 border-t-2 border-paper">
              <div className="border-r-2 border-paper bg-[#62ff8c] p-5 text-carbon">
                <div className="font-mono text-[10px] font-bold uppercase tracking-[0.18em]">Policy decision</div>
                <div className="mt-1 font-display text-3xl font-black uppercase">Allow / pinned</div>
              </div>
              <div className="flex items-center justify-center bg-cobalt p-5 font-mono text-xs font-black uppercase tracking-[0.2em] text-white">Run in boundary</div>
            </div>
          </div>
        </div>
      </section>

      <section id="proof" className="border-b-2 border-carbon">
        <div className="section-label">
          <span>01 / release evidence</span><a href={evidenceRun} target="_blank" rel="noreferrer">Run 29240267897 / passed ↗</a>
        </div>
        <div className="grid sm:grid-cols-2 xl:grid-cols-4">
          {proof.map(([number, label], index) => (
            <div key={label} className={`proof-cell ${index < proof.length - 1 ? "xl:border-r-2" : ""}`}>
              <div className="font-display text-6xl font-black uppercase tracking-[-0.07em] sm:text-7xl">{number}</div>
              <div className="mt-3 max-w-[16rem] font-mono text-[11px] font-bold uppercase tracking-[0.16em]">{label}</div>
            </div>
          ))}
        </div>
        <div className="grid border-t-2 border-carbon lg:grid-cols-[1.3fr_.7fr]">
          <div className="p-6 sm:p-10">
            <div className="mb-4 font-mono text-[10px] font-black uppercase tracking-[0.2em] text-cobalt">Post-merge / npm 11.12.1 / Node 24.13.0 / clean install</div>
            <div className="grid gap-px border-2 border-carbon bg-carbon sm:grid-cols-3">
              {postMergeProjects.map(([name, files, hash]) => (
                <div key={name} className="bg-paper p-5">
                  <div className="flex items-center justify-between font-display text-2xl font-black uppercase"><span>{name}</span><Check className="h-5 w-5 text-cobalt" /></div>
                  <div className="mt-8 font-mono text-[10px] uppercase leading-6"><strong>{files}</strong> entries<br />tree / {hash}<br />difference / 0</div>
                </div>
              ))}
            </div>
          </div>
          <aside className="border-t-2 border-carbon bg-hazard p-6 sm:p-10 lg:border-l-2 lg:border-t-0">
            <ShieldAlert className="mb-8 h-10 w-10" />
            <h2 className="font-display text-4xl font-black uppercase leading-[0.9] tracking-[-0.05em]">Same tree. More evidence.</h2>
            <p className="mt-6 max-w-md font-semibold leading-relaxed">Across Rspack, Karma, and Mattermost, Oath matched 108,376 entries after the release merge. Scanner findings remain review evidence—not proof of compromise or safety.</p>
          </aside>
        </div>
      </section>

      <section id="compare" className="border-b-2 border-carbon">
        <div className="section-label bg-carbon text-paper">
          <span>02 / competitive boundary</span><span>Different jobs. Honest claims.</span>
        </div>
        <div className="p-5 sm:p-10 lg:p-14">
          <h2 className="max-w-5xl font-display text-[clamp(3.4rem,8vw,8rem)] font-black uppercase leading-[0.82] tracking-[-0.075em]">
            Oath does not make the speed claim. <span className="text-hazard">Bun does.</span>
          </h2>
          <p className="mt-8 max-w-2xl text-lg font-semibold leading-relaxed">Bun leads with speed. npm defines the compatibility baseline. Oath’s measured wedge is an assessed identity, explicit grants, and a recorded enforcement backend before execution.</p>
        </div>
        <div className="grid border-t-2 border-carbon lg:grid-cols-3">
          {competitors.map((item, index) => (
            <article key={item.name} className={`competitor ${index < 2 ? "lg:border-r-2" : ""}`}>
              <div className="flex items-start justify-between gap-4 border-b-2 border-carbon p-5">
                <div>
                  <h3 className="font-display text-3xl font-black uppercase tracking-[-0.04em]">{item.name}</h3>
                  <p className="mt-1 font-mono text-[9px] font-bold uppercase tracking-[0.18em]">{item.role}</p>
                </div>
                <span className={`verdict verdict-${item.tone}`}>{item.verdict}</span>
              </div>
              <ul>
                {item.rows.map((row, rowIndex) => (
                  <li key={row} className="comparison-row">
                    {item.name === "Oath" || rowIndex < 2 ? <Check className="h-4 w-4" /> : <X className="h-4 w-4" />}
                    <span>{row}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section className="grid border-b-2 border-carbon lg:grid-cols-[.78fr_1.22fr]">
        <div className="border-b-2 border-carbon bg-cobalt p-6 text-white sm:p-10 lg:border-b-0 lg:border-r-2 lg:p-14">
          <div className="font-mono text-[10px] font-black uppercase tracking-[0.2em]">03 / enforcement pipeline</div>
          <h2 className="mt-16 font-display text-6xl font-black uppercase leading-[0.8] tracking-[-0.07em]">Resolve.<br />Verify.<br />Assess.<br />Contain.</h2>
          <Network className="mt-16 h-14 w-14" aria-hidden="true" />
        </div>
        <ol className="divide-y-2 divide-carbon">
          {[
            ["01", "Place like npm", "Bundled Arborist 9.4.2 implements the pinned npm 11.12.1 placement contract."],
            ["02", "Bind trust to bytes", "Approvals attach to package identity, integrity hash, policy, and exact granted capabilities."],
            ["03", "Show the evidence", "Publisher, provenance, age, behavioral diff, hooks, code signals, size, and requested access."],
            ["04", "Apply the boundary", "Linux uses namespaces, seccomp, Landlock, and limits. Windows uses AppContainer, ACL roots, and Job Objects."],
          ].map(([index, title, body]) => (
            <li key={index} className="pipeline-row">
              <span className="font-mono text-xs font-black text-cobalt">{index}</span>
              <h3 className="font-display text-3xl font-black uppercase tracking-[-0.04em]">{title}</h3>
              <p className="max-w-xl font-semibold leading-relaxed">{body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="bg-carbon p-5 text-paper sm:p-10 lg:p-14">
        <div className="grid border-2 border-paper lg:grid-cols-[1fr_auto]">
          <div className="p-6 sm:p-10">
            <div className="font-mono text-[10px] font-bold uppercase tracking-[0.2em] text-evidence">The next package wants a process.</div>
            <h2 className="mt-5 max-w-4xl font-display text-5xl font-black uppercase leading-[0.86] tracking-[-0.065em] sm:text-7xl">Make it show its work.</h2>
          </div>
          <div className="flex flex-col justify-center gap-3 border-t-2 border-paper bg-paper p-6 text-carbon lg:min-w-[360px] lg:border-l-2 lg:border-t-0">
            <Button size="lg" onClick={copyCommand}>{copied ? "Command copied" : "Copy safety check"} <Copy className="h-4 w-4" /></Button>
            <Button size="lg" variant="outline" asChild><a href={evidenceRun} target="_blank" rel="noreferrer">Read the evidence <ArrowUpRight className="h-4 w-4" /></a></Button>
            <Button size="lg" variant="outline" asChild><a href="https://github.com/Generalized-Labs/oath/issues/new?template=design-partner.yml" target="_blank" rel="noreferrer">Join the private beta <ArrowUpRight className="h-4 w-4" /></a></Button>
          </div>
        </div>
        <footer className="mt-8 flex flex-col justify-between gap-4 font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-evidence sm:flex-row">
          <span>Oath / Generalized Labs / 2026</span>
          <span><a href="https://docs.npmjs.com/cli/v11/commands/npm-exec/" target="_blank" rel="noreferrer">npm exec</a> / <a href="https://bun.sh/docs/pm/cli/install" target="_blank" rel="noreferrer">Bun install</a> / No scanner score is proof of safety.</span>
        </footer>
      </section>
    </main>
  );
}

export default App;
