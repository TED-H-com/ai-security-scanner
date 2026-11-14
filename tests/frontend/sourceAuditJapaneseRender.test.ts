import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: `
      import React from "react";
      import { renderToStaticMarkup } from "react-dom/server";
      import { I18nProvider, useI18n } from "./src/i18n/index.tsx";
      import { AuditFailureDetails } from "./src/components/AuditFailureDetails.tsx";
      import { SourceAuditResults } from "./src/components/SourceAuditResults.tsx";
      import { failureDescription } from "./src/auditFailure.ts";
      import { sourceAudit } from "./tests/support/sourceAudit.ts";

      const ending = { ending: "terminated", reason: "host_interrupted", assignment_count: 1, capture_count: 1 };
      function Reason() {
        const { text } = useI18n();
        return React.createElement("p", null, text(failureDescription(ending).reason));
      }
      export function renderAudit() {
        const audit = sourceAudit();
        audit.unresolved_candidates = [];
        const execution = { kind: "agent_audit_failure", occurredAt: "2026-11-12T00:00:00Z",
          receiptSha256: "receipt-digest", terminalSha256: "terminal-digest", ending };
        return renderToStaticMarkup(React.createElement(I18nProvider, null,
          React.createElement("main", null,
            React.createElement(SourceAuditResults, { audits: [audit] }),
            React.createElement("dl", null, React.createElement(AuditFailureDetails, { execution })),
            React.createElement(Reason))));
      }
    `,
    loader: "tsx",
    resolveDir: process.cwd(),
    sourcefile: "source-audit-japanese-render.tsx",
  },
  bundle: true,
  jsx: "automatic",
  format: "esm",
  platform: "node",
  target: "node22",
  banner: { js: 'import { createRequire } from "node:module"; const require = createRequire(process.cwd() + "/package.json");' },
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the source audit render bundle should contain JavaScript");
const { renderAudit } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

test("Japanese source audit results and failure details render localized copy", () => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { localStorage: { getItem: () => "ja" }, navigator: { languages: ["ja"] } },
  });
  try {
    const html = renderAudit();
    for (const text of [
      "Cloudflare ソースコード監査",
      "ソースコード監査は未完了です。対象ユニットが 1 件残っています。記載されたパスから続行してください。",
      "検証待ち", "検証計画", "ソースコード監査は完了前に終了", "理由コード", "監査が中断されました。",
      "receipt-digest", "Candidate title",
    ]) assert.ok(html.includes(text), text);
  } finally {
    if (previous) Object.defineProperty(globalThis, "window", previous);
    else Reflect.deleteProperty(globalThis, "window");
  }
});
