// Bundle size of each entry (minified, gzipped), with a budget for the balanced entry, which runs in browsers
// (Shopify web pixels among them). The balanced bundle is then run in a worker thread with no DOM, as a web pixel
// runs, to check that it is self-contained and works.

import { build } from "esbuild";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import { gzipSync } from "node:zlib";

// The pixel bundle it goes into was 5.7 KB gzip; Shopify caps UI extensions at 64 KB. The HTML entity table
// (about 7 KB gzip) is what keeps the decoding identical to Go.
const BUDGET_GZIP = { balanced: 24 * 1024 };

const dir = mkdtempSync(join(tmpdir(), "inputguard-size-"));
let failed = false;
try {
  for (const entry of ["balanced", "index"]) {
    const out = await build({
      entryPoints: [`src/${entry}.ts`],
      bundle: true,
      minify: true,
      format: "esm",
      platform: "browser",
      target: "es2022",
      write: false,
    });
    const code = out.outputFiles[0].contents;
    const gz = gzipSync(code, { level: 9 }).length;
    const budget = BUDGET_GZIP[entry];
    const over = budget !== undefined && gz > budget;
    failed ||= over;
    console.log(
      `${entry.padEnd(9)} ${(code.length / 1024).toFixed(1).padStart(6)} KB minified ${(gz / 1024).toFixed(1).padStart(6)} KB gzip` +
        (budget !== undefined ? ` (budget ${budget / 1024} KB${over ? ", OVER" : ""})` : ""),
    );
    if (entry === "balanced") {
      const file = join(dir, "balanced.mjs");
      writeFileSync(file, code);
      await smoke(file);
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
if (failed) process.exit(1);

async function smoke(file) {
  const script = `
    import { parentPort } from "node:worker_threads";
    const { Guard } = await import(${JSON.stringify(pathToFileURL(file).href)});
    const g = new Guard();
    const url = g.processString("https://shop.example.com/p?utm=%3Cscript%3Ealert(1)%3C%2Fscript%3E&q=1", "url").value;
    const text = g.processString("Áo thun <img src=x onerror=alert(1)>").value;
    parentPort.postMessage({ url, text, dom: typeof document + typeof window });
  `;
  const w = new Worker(new URL("data:text/javascript," + encodeURIComponent(script)));
  const msg = await new Promise((resolve, reject) => {
    w.once("message", resolve);
    w.once("error", reject);
  });
  await w.terminate();
  const ok = msg.url === "https://shop.example.com/p?q=1" && msg.text === "Áo thun" && msg.dom === "undefinedundefined";
  console.log(`worker   ${ok ? "ok" : "FAILED " + JSON.stringify(msg)}`);
  if (!ok) process.exit(1);
}
