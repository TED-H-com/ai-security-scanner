import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  internalEndpointCoordinate,
  internalEndpointProfiles,
  internalEndpointRdpTlsVulnerabilityOids,
  internalEndpointServiceFromScanProfile,
  internalEndpointSmtpVulnerabilityOids,
  internalEndpointSshVulnerabilityOids,
  internalEndpointTelnetVulnerabilityOids,
  internalEndpointVncVulnerabilityOids,
} from "../../src/internalEndpointProfile.ts";

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

test("the SSH endpoint profile is one fixed seven-check Greenbone profile", () => {
  assert.equal(internalEndpointServiceFromScanProfile("internal_endpoint_ssh"), "ssh");
  assert.equal(internalEndpointServiceFromScanProfile("unknown_profile"), undefined);
  assert.equal(internalEndpointProfiles.ssh.defaultPort, 22);
  assert.deepEqual(internalEndpointProfiles.ssh.engineIds, ["greenbone"]);
  assert.equal(
    internalEndpointProfiles.ssh.templateRevision,
    "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
  );
  assert.deepEqual(internalEndpointProfiles.ssh.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
  assert.deepEqual(internalEndpointProfiles.ssh.allowedTemplateIds, [
    "1.3.6.1.4.1.25623.1.0.801993",
    "1.3.6.1.4.1.25623.1.0.105497",
    "1.3.6.1.4.1.25623.1.0.105610",
    "1.3.6.1.4.1.25623.1.0.105611",
    "1.3.6.1.4.1.25623.1.0.117687",
    "1.3.6.1.4.1.25623.1.0.150712",
    "1.3.6.1.4.1.25623.1.0.150713",
  ]);
  assert.equal(internalEndpointSshVulnerabilityOids.length, 7);
  assert.equal(new Set(internalEndpointSshVulnerabilityOids).size, 7);
  assert.ok(internalEndpointSshVulnerabilityOids.every((oid) => /^1(?:\.[0-9]+)+$/u.test(oid)));
  // Terrapin's unauthenticated banner-only VT is deliberately not in the
  // default profile because its upstream QoD is too low for a beginner-facing
  // high-severity result.
  assert.equal(
    new Set<string>(internalEndpointSshVulnerabilityOids)
      .has("1.3.6.1.4.1.25623.1.0.114238"),
    false,
  );
  assert.match(internalEndpointProfiles.ssh.coverageNote.en, /does not sign in/u);
  assert.match(internalEndpointProfiles.ssh.coverageNote.en, /operating-system patches/u);
});

test("the serialized RDP endpoint profile is one fixed eleven-check Greenbone transport profile", () => {
  assert.equal(internalEndpointServiceFromScanProfile("internal_endpoint_rdp_tls"), "rdp_tls");
  assert.equal(internalEndpointProfiles.rdp_tls.defaultPort, 3389);
  assert.equal(internalEndpointProfiles.rdp_tls.label.en, "RDP transport security");
  assert.deepEqual(internalEndpointProfiles.rdp_tls.engineIds, ["greenbone"]);
  assert.equal(
    internalEndpointProfiles.rdp_tls.templateRevision,
    "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
  );
  assert.deepEqual(internalEndpointProfiles.rdp_tls.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
  assert.deepEqual(internalEndpointProfiles.rdp_tls.allowedTemplateIds, [
    "1.3.6.1.4.1.25623.1.0.902658",
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
  ]);
  assert.equal(internalEndpointRdpTlsVulnerabilityOids.length, 11);
  assert.equal(new Set(internalEndpointRdpTlsVulnerabilityOids).size, 11);
  assert.equal(
    new Set<string>(internalEndpointRdpTlsVulnerabilityOids)
      .has("1.3.6.1.4.1.25623.1.0.108094"),
    false,
  );
  assert.match(internalEndpointProfiles.rdp_tls.coverageNote.en, /ten TLS/u);
  assert.match(internalEndpointProfiles.rdp_tls.coverageNote.en, /RDP 5\.2 or earlier/u);
  assert.match(internalEndpointProfiles.rdp_tls.coverageNote.en, /does not sign in/u);
  assert.match(internalEndpointProfiles.rdp_tls.coverageNote.en, /Windows patches/u);
  assert.match(internalEndpointProfiles.rdp_tls.coverageNote.en, /other RDP implementation CVEs/u);
});

test("the VNC endpoint profile is one fixed RFB transport check", () => {
  assert.equal(internalEndpointServiceFromScanProfile("internal_endpoint_vnc"), "vnc");
  assert.equal(internalEndpointProfiles.vnc.defaultPort, 5900);
  assert.equal(internalEndpointProfiles.vnc.label.en, "VNC transport security");
  assert.deepEqual(internalEndpointProfiles.vnc.engineIds, ["greenbone"]);
  assert.equal(
    internalEndpointProfiles.vnc.templateRevision,
    "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
  );
  assert.deepEqual(internalEndpointProfiles.vnc.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
  assert.deepEqual(internalEndpointProfiles.vnc.allowedTemplateIds, [
    "1.3.6.1.4.1.25623.1.0.108529",
  ]);
  assert.equal(internalEndpointVncVulnerabilityOids.length, 1);
  assert.match(internalEndpointProfiles.vnc.coverageNote.en, /RFB security types/u);
  assert.match(internalEndpointProfiles.vnc.coverageNote.en, /unencrypted or weak transport/u);
  assert.match(internalEndpointProfiles.vnc.coverageNote.en, /does not sign in/u);
  assert.match(internalEndpointProfiles.vnc.coverageNote.en, /start a desktop session/u);
  assert.match(internalEndpointProfiles.vnc.coverageNote.en, /VNC implementation CVEs/u);
});

test("the SMTP endpoint profile checks cleartext AUTH and negotiable TLS without mail or login", () => {
  assert.equal(internalEndpointServiceFromScanProfile("internal_endpoint_smtp"), "smtp");
  assert.equal(internalEndpointProfiles.smtp.defaultPort, 25);
  assert.equal(internalEndpointProfiles.smtp.label.en, "SMTP transport security");
  assert.deepEqual(internalEndpointProfiles.smtp.engineIds, ["greenbone"]);
  assert.equal(
    internalEndpointProfiles.smtp.templateRevision,
    "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
  );
  assert.deepEqual(internalEndpointProfiles.smtp.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
  assert.deepEqual(internalEndpointProfiles.smtp.allowedTemplateIds, [
    "1.3.6.1.4.1.25623.1.0.108530",
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
  ]);
  assert.equal(internalEndpointSmtpVulnerabilityOids.length, 11);
  assert.equal(new Set(internalEndpointSmtpVulnerabilityOids).size, 11);
  assert.match(internalEndpointProfiles.smtp.coverageNote.en, /cleartext AUTH/u);
  assert.match(internalEndpointProfiles.smtp.coverageNote.en, /when TLS can be negotiated/u);
  assert.match(internalEndpointProfiles.smtp.coverageNote.en, /does not sign in, send mail/u);
  assert.match(internalEndpointProfiles.smtp.coverageNote.en, /open relay or anti-spam/u);
  assert.match(internalEndpointProfiles.smtp.coverageNote.en, /general mail-server CVEs/u);
});

test("the Telnet endpoint profile checks only cleartext login-prompt exposure", () => {
  assert.equal(internalEndpointServiceFromScanProfile("internal_endpoint_telnet"), "telnet");
  assert.equal(internalEndpointProfiles.telnet.defaultPort, 23);
  assert.equal(internalEndpointProfiles.telnet.label.en, "Telnet cleartext exposure");
  assert.deepEqual(internalEndpointProfiles.telnet.engineIds, ["greenbone"]);
  assert.equal(
    internalEndpointProfiles.telnet.templateRevision,
    "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df",
  );
  assert.deepEqual(internalEndpointProfiles.telnet.ratePolicy, {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  });
  assert.deepEqual(internalEndpointProfiles.telnet.allowedTemplateIds, [
    "1.3.6.1.4.1.25623.1.0.108522",
  ]);
  assert.equal(internalEndpointTelnetVulnerabilityOids.length, 1);
  assert.match(internalEndpointProfiles.telnet.coverageNote.en, /cleartext login prompt/u);
  assert.match(internalEndpointProfiles.telnet.coverageNote.en, /does not send credentials/u);
  assert.match(internalEndpointProfiles.telnet.coverageNote.en, /does not.*sign in/u);
  assert.match(internalEndpointProfiles.telnet.coverageNote.en, /default passwords/u);
  assert.match(internalEndpointProfiles.telnet.coverageNote.en, /Telnet implementation CVEs/u);
  assert.match(internalEndpointProfiles.telnet.coverageNote.zhTW, /不會送出帳號或密碼/u);
});

test("the endpoint profiles match the native and Greenbone launcher boundaries", () => {
  assert.match(
    greenboneLauncherSource,
    /feedRevision\s+= "a2e53c2e30f1fa5408369cb5cf99653a3e08e9df"/u,
  );
  assert.match(greenboneLauncherSource, /maxSelectedVTsPerGrant\s+= 128/u);
  assert.match(greenboneLauncherSource, /the Greenbone profile does not expand network targets/u);

  const greenbone = engineCatalog.find(({ id }) => id === "greenbone");
  assert.equal(greenbone?.rule_version, "a2e53c2e30f1fa5408369cb5cf99653a3e08e9df");
  assert.ok(greenbone?.direct_network_contract?.protocols?.includes("tcp"));
  assert.deepEqual(greenbone?.direct_network_contract?.target_kinds, ["hostname", "address"]);

  assert.match(nativeCaseServiceSource, /INTERNAL_DEVICE_ENGINE_ID: &str = "greenbone"/u);
  assert.match(nativeCaseServiceSource, /INTERNAL_ENDPOINT_TEMPLATE_REVISION: &str =/u);
  assert.ok(nativeCaseServiceSource.includes(internalEndpointProfiles.ssh.templateRevision));
  assert.match(nativeCaseServiceSource, /requests_per_second == 2/u);
  assert.match(nativeCaseServiceSource, /concurrency == 1/u);
  assert.match(nativeCaseServiceSource, /timeout_seconds == 15/u);
  for (const oid of internalEndpointSshVulnerabilityOids) {
    assert.ok(nativeCaseServiceSource.includes(oid), `native SSH policy is missing ${oid}`);
  }
  for (const oid of internalEndpointRdpTlsVulnerabilityOids) {
    assert.ok(nativeCaseServiceSource.includes(oid), `native RDP policy is missing ${oid}`);
  }
  for (const oid of internalEndpointVncVulnerabilityOids) {
    assert.ok(nativeCaseServiceSource.includes(oid), `native VNC policy is missing ${oid}`);
  }
  for (const oid of internalEndpointSmtpVulnerabilityOids) {
    assert.ok(nativeCaseServiceSource.includes(oid), `native SMTP policy is missing ${oid}`);
  }
  for (const oid of internalEndpointTelnetVulnerabilityOids) {
    assert.ok(nativeCaseServiceSource.includes(oid), `native Telnet policy is missing ${oid}`);
  }
});

test("endpoint review coordinates preserve exact ports and bracket IPv6", () => {
  assert.equal(internalEndpointCoordinate("server.example.test", 22), "server.example.test:22");
  assert.equal(internalEndpointCoordinate("2001:db8::10", 2222), "[2001:db8::10]:2222");
});
