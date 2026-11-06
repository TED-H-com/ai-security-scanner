export type InternalEndpointService = "ssh" | "rdp_tls" | "vnc" | "smtp" | "telnet";

export type InternalEndpointScanProfile =
  | "internal_endpoint_ssh"
  | "internal_endpoint_rdp_tls"
  | "internal_endpoint_vnc"
  | "internal_endpoint_smtp"
  | "internal_endpoint_telnet";

export const internalEndpointScanProfileByService: Record<
  InternalEndpointService,
  InternalEndpointScanProfile
> = {
  ssh: "internal_endpoint_ssh",
  rdp_tls: "internal_endpoint_rdp_tls",
  vnc: "internal_endpoint_vnc",
  smtp: "internal_endpoint_smtp",
  telnet: "internal_endpoint_telnet",
};

export const internalEndpointServiceFromScanProfile = (
  profile: string | undefined,
): InternalEndpointService | undefined => {
  const entry = Object.entries(internalEndpointScanProfileByService)
    .find(([, scanProfile]) => scanProfile === profile);
  return entry?.[0] as InternalEndpointService | undefined;
};

export const internalEndpointCoordinate = (target: string, port: number): string =>
  `${target.includes(":") ? `[${target}]` : target}:${port}`;

const GREENBONE_TEMPLATE_REVISION =
  "greenbone-community-feed@a2e53c2e30f1fa5408369cb5cf99653a3e08e9df";

/**
 * Reporting VTs from the pinned Greenbone feed. The launcher resolves their
 * upstream discovery dependencies; this product only chooses the reviewed
 * security checks and preserves their original results.
 */
export const internalEndpointSshVulnerabilityOids = [
  // Deprecated SSH-1 protocol.
  "1.3.6.1.4.1.25623.1.0.801993",
  // Known or static host key.
  "1.3.6.1.4.1.25623.1.0.105497",
  // Weak MAC and encryption algorithms.
  "1.3.6.1.4.1.25623.1.0.105610",
  "1.3.6.1.4.1.25623.1.0.105611",
  // Weak host-key algorithms, key sizes, and key exchange.
  "1.3.6.1.4.1.25623.1.0.117687",
  "1.3.6.1.4.1.25623.1.0.150712",
  "1.3.6.1.4.1.25623.1.0.150713",
] as const;

/**
 * Transport-security reporting VTs that apply to an exact RDP listener. Ten
 * negotiate TLS through RDP; the remaining VT checks the fixed private key in
 * RDP 5.2 or earlier. CRIME (108094) stays out because its upstream check is
 * specific to HTTP/SPDY and does not establish an RDP transport weakness.
 */
export const internalEndpointRdpTlsVulnerabilityOids = [
  // Fixed private key used by RDP 5.2 or earlier.
  "1.3.6.1.4.1.25623.1.0.902658",
  // Deprecated TLS/SSL protocols and protocol-level attacks.
  "1.3.6.1.4.1.25623.1.0.111012",
  "1.3.6.1.4.1.25623.1.0.117274",
  "1.3.6.1.4.1.25623.1.0.802087",
  // Anonymous, null, and weak cipher suites.
  "1.3.6.1.4.1.25623.1.0.108147",
  "1.3.6.1.4.1.25623.1.0.108022",
  "1.3.6.1.4.1.25623.1.0.103440",
  // Expired, weakly signed, or undersized server certificates.
  "1.3.6.1.4.1.25623.1.0.103955",
  "1.3.6.1.4.1.25623.1.0.105880",
  "1.3.6.1.4.1.25623.1.0.150710",
  "1.3.6.1.4.1.25623.1.0.150749",
] as const;

/**
 * Reads the RFB security types offered by one exact VNC service. It reports
 * only the upstream unencrypted/weak-transport result and never authenticates
 * or starts a desktop session.
 */
export const internalEndpointVncVulnerabilityOids = [
  "1.3.6.1.4.1.25623.1.0.108529",
] as const;

/**
 * Checks whether SMTP authentication is exposed before transport encryption
 * and, when TLS can be negotiated, applies the same reviewed protocol, cipher,
 * and certificate checks used by the other exact TLS-capable services.
 */
export const internalEndpointSmtpVulnerabilityOids = [
  // Cleartext SMTP authentication exposure.
  "1.3.6.1.4.1.25623.1.0.108530",
  // Deprecated TLS/SSL protocols and protocol-level attacks.
  "1.3.6.1.4.1.25623.1.0.111012",
  "1.3.6.1.4.1.25623.1.0.117274",
  "1.3.6.1.4.1.25623.1.0.802087",
  // Anonymous, null, and weak cipher suites.
  "1.3.6.1.4.1.25623.1.0.108147",
  "1.3.6.1.4.1.25623.1.0.108022",
  "1.3.6.1.4.1.25623.1.0.103440",
  // Expired, weakly signed, or undersized server certificates.
  "1.3.6.1.4.1.25623.1.0.103955",
  "1.3.6.1.4.1.25623.1.0.105880",
  "1.3.6.1.4.1.25623.1.0.150710",
  "1.3.6.1.4.1.25623.1.0.150749",
] as const;

/** Reads only the login-prompt exposure reported by the exact Telnet service. */
export const internalEndpointTelnetVulnerabilityOids = [
  "1.3.6.1.4.1.25623.1.0.108522",
] as const;

const sshProfile = {
  scanProfile: "internal_endpoint_ssh" as const,
  label: { en: "SSH service", zhTW: "SSH 服務" },
  exampleTarget: "server.example.internal",
  defaultPort: 22,
  engineIds: ["greenbone"] as const,
  templateRevision: GREENBONE_TEMPLATE_REVISION,
  allowedTemplateIds: [...internalEndpointSshVulnerabilityOids],
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
  coverageNote: {
    en: "Checks the exact SSH service for SSH-1, known or static host keys, and weak MAC, encryption, host-key, key-size, or key-exchange choices. It does not sign in or inspect operating-system patches, installed software, or local settings.",
    zhTW: "檢查精確 SSH 服務是否使用 SSH-1、已知或固定 host key，以及較弱的 MAC、加密、host-key、key size 或 key-exchange 選項；不會登入，也不會檢查作業系統修補、已安裝軟體或本機設定。",
  },
} as const;

const rdpTlsProfile = {
  scanProfile: "internal_endpoint_rdp_tls" as const,
  label: { en: "RDP transport security", zhTW: "RDP 傳輸安全" },
  exampleTarget: "desktop.example.internal",
  defaultPort: 3389,
  engineIds: ["greenbone"] as const,
  templateRevision: GREENBONE_TEMPLATE_REVISION,
  allowedTemplateIds: [...internalEndpointRdpTlsVulnerabilityOids],
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
  coverageNote: {
    en: "Runs ten TLS protocol, cipher, and certificate checks plus one fixed-private-key check for RDP 5.2 or earlier against the exact service. It does not sign in, test authentication or NLA, inspect Windows patches, or test other RDP implementation CVEs.",
    zhTW: "只對精確服務執行十項 TLS 協定、cipher 與憑證檢查，以及一項 RDP 5.2 或更早版本的固定私鑰檢查；不會登入、測試驗證或 NLA、檢查 Windows 修補，也不會測試其他 RDP 實作 CVE。",
  },
} as const;

const vncProfile = {
  scanProfile: "internal_endpoint_vnc" as const,
  label: { en: "VNC transport security", zhTW: "VNC 傳輸安全" },
  exampleTarget: "workstation.example.internal",
  defaultPort: 5900,
  engineIds: ["greenbone"] as const,
  templateRevision: GREENBONE_TEMPLATE_REVISION,
  allowedTemplateIds: [...internalEndpointVncVulnerabilityOids],
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
  coverageNote: {
    en: "Reads the RFB security types offered by the exact VNC service and flags only unencrypted or weak transport. It does not sign in, start a desktop session, inspect the operating system, or test VNC implementation CVEs.",
    zhTW: "讀取精確 VNC 服務提供的 RFB 安全類型，只標示未加密或較弱的傳輸方式；不會登入、啟動桌面工作階段、檢查作業系統，也不會測試 VNC 實作 CVE。",
  },
} as const;

const smtpProfile = {
  scanProfile: "internal_endpoint_smtp" as const,
  label: { en: "SMTP transport security", zhTW: "SMTP 傳輸安全" },
  exampleTarget: "mail.example.internal",
  defaultPort: 25,
  engineIds: ["greenbone"] as const,
  templateRevision: GREENBONE_TEMPLATE_REVISION,
  allowedTemplateIds: [...internalEndpointSmtpVulnerabilityOids],
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
  coverageNote: {
    en: "Checks the exact SMTP service for cleartext AUTH exposure and, when TLS can be negotiated, weak TLS protocols, ciphers, or certificates. It does not sign in, send mail, test open relay or anti-spam behavior, or test general mail-server CVEs.",
    zhTW: "檢查精確 SMTP 服務是否暴露明文 AUTH，並在可協商 TLS 時檢查較弱的 TLS 協定、cipher 或憑證；不會登入、寄信、測試 open relay 或 anti-spam 行為，也不會測試一般郵件伺服器 CVE。",
  },
} as const;

const telnetProfile = {
  scanProfile: "internal_endpoint_telnet" as const,
  label: { en: "Telnet cleartext exposure", zhTW: "Telnet 明文登入暴露" },
  exampleTarget: "network-device.example.internal",
  defaultPort: 23,
  engineIds: ["greenbone"] as const,
  templateRevision: GREENBONE_TEMPLATE_REVISION,
  allowedTemplateIds: [...internalEndpointTelnetVulnerabilityOids],
  ratePolicy: {
    requestsPerSecond: 2,
    concurrency: 1,
    timeoutSeconds: 15,
  },
  coverageNote: {
    en: "Checks whether the exact Telnet service exposes a cleartext login prompt. It does not send credentials, sign in, test default passwords, inspect the operating system, or test general Telnet implementation CVEs.",
    zhTW: "檢查精確 Telnet 服務是否暴露明文登入提示；不會送出帳號或密碼、登入、測試預設帳密、檢查作業系統，也不會測試一般 Telnet 實作 CVE。",
  },
} as const;

export const internalEndpointProfiles = {
  ssh: sshProfile,
  rdp_tls: rdpTlsProfile,
  vnc: vncProfile,
  smtp: smtpProfile,
  telnet: telnetProfile,
} as const;
