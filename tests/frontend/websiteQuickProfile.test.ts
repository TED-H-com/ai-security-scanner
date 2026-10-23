import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { websiteQuickOrigin, websiteQuickProfile } from "../../src/websiteQuickProfile.ts";

const nativeCaseServiceSource = readFileSync(
  new URL("../../src-tauri/src/case_service.rs", import.meta.url),
  "utf8",
);

test("the public website quick profile delegates applicability to one pinned upstream Nuclei profile", () => {
  assert.equal(
    websiteQuickProfile.templateRevision,
    "nuclei-templates@f938a3dd530c283e9387b518b97911152ff5846c",
  );
  assert.equal(websiteQuickProfile.profileId, "nuclei_web_safe_v1");
  assert.deepEqual(websiteQuickProfile.engineIds, ["nuclei"]);
  assert.deepEqual(websiteQuickProfile.ratePolicy, {
    requestsPerSecond: 10,
    concurrency: 5,
    timeoutSeconds: 10,
  });
  assert.deepEqual(websiteQuickProfile.allowedTemplateIds, []);

  assert.match(nativeCaseServiceSource, /DECLARED_WEBSITE_ENGINE_ID: &str = "nuclei"/u);
  assert.ok(nativeCaseServiceSource.includes(websiteQuickProfile.templateRevision));
  assert.ok(nativeCaseServiceSource.includes(websiteQuickProfile.profileId));
  assert.match(nativeCaseServiceSource, /requests_per_second == 10/u);
  assert.match(nativeCaseServiceSource, /concurrency == 5/u);
  assert.match(nativeCaseServiceSource, /timeout_seconds == 10/u);
});

test("the website boundary always names an explicit scheme, host, and port", () => {
  assert.equal(websiteQuickOrigin("portal.example.test", "https", 443), "https://portal.example.test:443");
  assert.equal(websiteQuickOrigin("2001:db8::10", "http", 8080), "http://[2001:db8::10]:8080");
});
