import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  internalDeviceHttpsProfile,
  internalDeviceProfileFromScanProfile,
  internalDeviceTlsVulnerabilityOids,
  prepareInternalDeviceEndpoint,
} from "../../src/internalDeviceProfile.ts";

const oidPattern = /^1(?:\.[0-9]+)+$/u;

const greenboneLauncherSource = readFileSync(
  new URL("../../engines/images/greenbone-launcher/main.go", import.meta.url),
  "utf8",
);
const nativeCaseServiceSource = readFileSync(
  new URL("../../src-tauri/src/case_service.rs", import.meta.url),
  "utf8",
);
const engineCatalog = JSON.parse(
  readFileSync(new URL("../../engines/catalog.json", import.meta.url), "utf8"),
) as Array<{
  id: string;
  rule_version?: string;
  direct_network_contract?: { protocols?: string[]; target_kinds?: string[] };
}>;

test("the generic HTTPS-management profile stays pinned to exact Greenbone TLS vulnerability OIDs", () => {
  assert.equal(internalDeviceHttpsProfile.scanProfile, "internal_device_https");
  assert.equal(
    internalDeviceProfileFromScanProfile("internal_device_https"),
    internalDeviceHttpsProfile,
  );
  assert.equal(internalDeviceProfileFromScanProfile("website_quick"), undefined);
  assert.deepEqual(internalDeviceTlsVulnerabilityOids, [
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108094",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
  ]);
  assert.equal(internalDeviceHttpsProfile.label.en, "HTTPS management-service security");
  assert.equal(
    internalDeviceHttpsProfile.templateRevision,
    "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
  );
  assert.deepEqual(internalDeviceHttpsProfile.engineIds, ["greenbone"]);
  assert.deepEqual(internalDeviceHttpsProfile.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
  assert.deepEqual(
    internalDeviceHttpsProfile.allowedTemplateIds,
    internalDeviceTlsVulnerabilityOids,
  );
  assert.ok(internalDeviceHttpsProfile.allowedTemplateIds.every((oid) => oidPattern.test(oid)));
  assert.equal(
    new Set(internalDeviceHttpsProfile.allowedTemplateIds).size,
    internalDeviceHttpsProfile.allowedTemplateIds.length,
  );
});

test("the frontend profile matches the existing Greenbone direct-launcher boundary", () => {
  assert.match(
    greenboneLauncherSource,
    /feedRevision\s+= "a2e53c2e30f1fa5408369cb5cf99653a3e08e9df"/u,
  );
  assert.match(greenboneLauncherSource, /maxSelectedVTsPerGrant\s+= 128/u);
  assert.match(greenboneLauncherSource, /external\.Activity != "active_external"/u);
  assert.match(greenboneLauncherSource, /the Greenbone profile does not expand network targets/u);

  const greenbone = engineCatalog.find(({ id }) => id === "greenbone");
  assert.equal(greenbone?.rule_version, "a2e53c2e30f1fa5408369cb5cf99653a3e08e9df");
  assert.ok(greenbone?.direct_network_contract?.protocols?.includes("https"));
  assert.deepEqual(greenbone?.direct_network_contract?.target_kinds, ["hostname", "address"]);
});

test("the native boundary pins the same generic device engine, revision, rate, and OID allowlist", () => {
  assert.match(nativeCaseServiceSource, /INTERNAL_DEVICE_ENGINE_ID: &str = "greenbone"/u);
  assert.ok(nativeCaseServiceSource.includes(internalDeviceHttpsProfile.templateRevision));
  assert.match(nativeCaseServiceSource, /requests_per_second == 2/u);
  assert.match(nativeCaseServiceSource, /concurrency == 1/u);
  assert.match(nativeCaseServiceSource, /timeout_seconds == 15/u);
  for (const oid of internalDeviceHttpsProfile.allowedTemplateIds) {
    assert.ok(nativeCaseServiceSource.includes(oid), `native policy is missing ${oid}`);
  }
});

test("one exact HTTPS management URL produces one bounded generic Greenbone route policy", () => {
  const prepared = prepareInternalDeviceEndpoint(
    "https://Gateway.Example.test:8443/admin/status?tab=system#overview",
  );
  assert.equal(prepared.ok, true);
  if (!prepared.ok) return;

  assert.deepEqual(prepared.value, {
    scanProfile: "internal_device_https",
    target: "gateway.example.test",
    origin: "https://gateway.example.test:8443",
    protocol: "https",
    ports: [8443],
    enteredPath: "/admin/status",
    queryWasRemoved: true,
    engineIds: ["greenbone"],
    ratePolicy: {
      requestsPerSecond: 2,
      concurrency: 1,
      timeoutSeconds: 15,
    },
    templatePolicy: {
      revision: "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
      allowedTemplateIds: [...internalDeviceHttpsProfile.allowedTemplateIds],
      allowHeadless: false,
      allowOutOfBand: false,
      allowFuzzing: false,
      allowFileUpload: false,
      allowDenialOfService: false,
      allowCredentialAttacks: false,
    },
  });
});

test("custom HTTPS ports and IPv6 remain exact without a device-family choice", () => {
  const customPort = prepareInternalDeviceEndpoint("https://10.20.0.9:8080/");
  assert.equal(customPort.ok, true);
  if (customPort.ok) {
    assert.equal(customPort.value.origin, "https://10.20.0.9:8080");
    assert.deepEqual(customPort.value.ports, [8080]);
  }

  const ipv6 = prepareInternalDeviceEndpoint("https://[2001:db8::10]:9443/");
  assert.equal(ipv6.ok, true);
  if (ipv6.ok) {
    assert.equal(ipv6.value.target, "2001:db8::10");
    assert.equal(ipv6.value.origin, "https://[2001:db8::10]:9443");
  }
});

test("the generic profile rejects credentials and plaintext management endpoints", () => {
  assert.deepEqual(
    prepareInternalDeviceEndpoint("https://admin:secret@10.20.0.8/"),
    { ok: false, error: "userinfo_not_allowed" },
  );
  assert.deepEqual(
    prepareInternalDeviceEndpoint("http://10.20.0.8:8080/"),
    { ok: false, error: "https_required" },
  );
});
