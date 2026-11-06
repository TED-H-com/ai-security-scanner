import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { PROJECT_ROOT, readJson, runMain } from "./lib.mjs";

const TEMPLATE_RELATIVE = "windows/nsis/installer.nsi";
const TEMPLATE_PATH = path.join(PROJECT_ROOT, "src-tauri", TEMPLATE_RELATIVE);
const PROVENANCE_PATH = path.join(
  PROJECT_ROOT,
  "src-tauri/windows/nsis/installer.provenance.json",
);

const PINNED_UPSTREAM = Object.freeze({
  schemaVersion: 1,
  upstreamRepository: "https://github.com/tauri-apps/tauri",
  upstreamTag: "tauri-cli-v2.12.4",
  upstreamCommit: "993038c49185307dfc895ab7657d77ca0d5ed7c7",
  upstreamPath: "crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi",
  upstreamUrl:
    "https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.12.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi",
  upstreamSha256: "d00089d3b1a2c4a30d7b6e098079100cb8f25e980f84d4515aca4597b95e967d",
  patchContract:
    "ai-security-scanner.windows-runtime-cache-prerequisite-version-neutral-repair-and-bounded-uninstall/v8",
  vendoredSha256: "11ec7d38d1588c6f654c62f7fc87c5a5d82d24d2b26fffbe0715a292b42d255a",
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function block(lines) {
  return `${lines.join("\n")}\n`;
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields changed`,
  );
}

function replaceOnce(source, patched, upstream, label) {
  const first = source.indexOf(patched);
  assert(first !== -1, `vendored NSIS template is missing reviewed patch hunk: ${label}`);
  assert(
    source.indexOf(patched, first + patched.length) === -1,
    `reviewed NSIS patch hunk is ambiguous: ${label}`,
  );
  return `${source.slice(0, first)}${upstream}${source.slice(first + patched.length)}`;
}

function replaceExactly(source, patched, upstream, expectedCount, label) {
  const actualCount = source.split(patched).length - 1;
  assert(actualCount === expectedCount, `${label} occurs ${actualCount} times instead of ${expectedCount}`);
  return source.replaceAll(patched, upstream);
}

function replaceBoundedSection(source, startMarker, endMarker, replacement, label) {
  const start = source.indexOf(startMarker);
  assert(start !== -1, `vendored NSIS template is missing reviewed section start: ${label}`);
  assert(
    source.indexOf(startMarker, start + startMarker.length) === -1,
    `reviewed NSIS section start is ambiguous: ${label}`,
  );
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert(end > start, `vendored NSIS template is missing reviewed section end: ${label}`);
  assert(
    source.indexOf(endMarker, end + endMarker.length) === -1,
    `reviewed NSIS section end is ambiguous: ${label}`,
  );
  return `${source.slice(0, start)}${replacement}${source.slice(end)}`;
}

function extractFunction(source, name) {
  const marker = `Function ${name}\n`;
  const start = source.indexOf(marker);
  assert(start !== -1, `NSIS function ${name} is missing`);
  assert(source.indexOf(marker, start + marker.length) === -1, `NSIS function ${name} is duplicated`);
  const functionEnd = source.indexOf("FunctionEnd\n", start);
  assert(functionEnd > start, `NSIS function ${name} has no FunctionEnd`);
  const end = functionEnd + "FunctionEnd\n".length;
  return { start, end, source: source.slice(start, end) };
}

function removeFunction(source, name) {
  const extracted = extractFunction(source, name);
  const trailingBlank = source.slice(extracted.end, extracted.end + 1) === "\n" ? 1 : 0;
  return `${source.slice(0, extracted.start)}${source.slice(extracted.end + trailingBlank)}`;
}

function assertOrdered(source, tokens, label) {
  let cursor = -1;
  for (const token of tokens) {
    const next = source.indexOf(token, cursor + 1);
    assert(next !== -1, `${label} is missing: ${token}`);
    assert(next > cursor, `${label} ordering changed near: ${token}`);
    cursor = next;
  }
}

function reconstructPinnedUpstream(vendored) {
  let reconstructed = vendored;
  const rewrites = [
    {
      label: "vendored provenance header",
      patched: block([
        "; Vendored from Tauri CLI's NSIS template for reproducible Windows packaging.",
        "; Upstream tag: tauri-cli-v2.12.4",
        "; Upstream commit: 993038c49185307dfc895ab7657d77ca0d5ed7c7",
        "; Upstream URL: https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.12.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi",
        "; Upstream SHA-256: d00089d3b1a2c4a30d7b6e098079100cb8f25e980f84d4515aca4597b95e967d",
        "; Upstream license: Apache-2.0 OR MIT",
        "; Local patch: version-neutral stale-registration and same-version repair,",
        "; data-preserving upgrade overlays, synchronous copied-uninstaller execution,",
        "; exact private runtime-cache seeding, fixed Windows-prerequisite preparation with",
        "; durable restart/resume state, and a bilingual three-choice uninstall",
        "; delegated to the fixed product CLI with bounded, visible coordinator records",
        "; and exact registration postconditions.",
        "; The release validator reverses these reviewed hunks and verifies both",
        "; complete-file SHA-256 values.",
        "",
      ]),
      upstream: "",
    },
    {
      label: "repair state variables",
      patched: block([
        "Var OldMainBinaryName",
        "Var RegistrationOverlayMode",
      ]),
      upstream: block(["Var OldMainBinaryName"]),
    },
    {
      label: "uninstaller string search helper",
      patched: block(["${StrLoc}", "${UnStrLoc}"]),
      upstream: block(["${StrLoc}"]),
    },
    {
      label: "early Traditional Chinese language identifier",
      patched: block([
        "; LoadLanguageFile defines ${LANG_TRADCHINESE} later, when Tauri expands the",
        "; configured MUI_LANGUAGE entries. These custom-page functions are compiled",
        "; before that point, so use the stable Windows/NSIS Traditional Chinese LCID",
        "; here instead of referencing a not-yet-defined preprocessor symbol.",
        "!define PRODUCT_LANG_TRADCHINESE 1028",
        "",
      ]),
      upstream: "",
    },
    {
      label: "maintenance-page repair bypass",
      patched: block([
        "  ; .onInit proves an exact current-user product registration before choosing",
        "  ; this path. Stale registrations, same-version repairs, and upgrades replace",
        "  ; only the candidate's known files and registration in place. They never run",
        "  ; an absent or older uninstaller and never touch runtime, cases, or app data.",
        "  ${If} $RegistrationOverlayMode <> 0",
        "    Abort",
        "  ${EndIf}",
        "",
      ]),
      upstream: "",
    },
    {
      label: "repair directory lock",
      patched: "!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirectoryIfRepairOrPassive\n",
      upstream: "!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive\n",
    },
    {
      label: "headless maintenance selection",
      patched: block([
        "  ; Passive and silent setup have no usable radio-button HWND. Make their",
        "  ; normal upgrade behavior explicit: select the first (uninstall old version)",
        "  ; choice. Tauri updater mode remains the separate no-uninstall path below.",
        "  ${If} $PassiveMode = 1",
        "    StrCpy $R1 1",
        "  ${ElseIf} ${Silent}",
        "    StrCpy $R1 1",
        "  ${Else}",
        "    ${NSD_GetState} $R2 $R1",
        "  ${EndIf}",
      ]),
      upstream: block(["  ${NSD_GetState} $R2 $R1"]),
    },
    {
      label: "synchronous copied old-uninstaller execution",
      patched: block([
        '      ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""',
        '      ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"',
        "      StrCpy $R3 '$\\\"$4\\uninstall.exe$\\\"'",
        '      ${If} $4 == ""',
        "        StrCpy $0 2",
        "      ${ElseIf} $R1 != $R3",
        "        ; Never execute a command taken from an inconsistent registration.",
        "        StrCpy $0 2",
        "      ${Else}",
        '        ${IfNot} ${FileExists} "$4\\uninstall.exe"',
        "          StrCpy $0 2",
        "        ${Else}",
        "          ; NSIS uninstallers normally launch a temporary child and return before",
        "          ; that child finishes. _?= makes execution synchronous, but also runs",
        "          ; the named executable in place. Copy the exact registered uninstaller",
        "          ; into this installer's private temp directory first so the original can",
        "          ; delete itself and its install directory before ExecWait returns.",
        "          InitPluginsDir",
        '          StrCpy $R2 "$PLUGINSDIR\\ai-security-scanner-previous-uninstaller.exe"',
        "          ClearErrors",
        '          CopyFiles /SILENT "$4\\uninstall.exe" "$R2"',
        "          ${If} ${Errors}",
        "            StrCpy $0 2",
        "          ${Else}",
        '            ${IfNot} ${FileExists} "$R2"',
        "              StrCpy $0 2",
        "            ${Else}",
        "              StrCpy $R1 '$\\\"$R2$\\\"'",
        '              ${IfThen} $UpdateMode = 1 ${|} StrCpy $R1 "$R1 /UPDATE" ${|} ; append /UPDATE',
        "              ${If} $PassiveMode = 1",
        '                StrCpy $R1 "$R1 /P" ; preserve passive mode in the old uninstaller',
        "              ${ElseIf} ${Silent}",
        '                StrCpy $R1 "$R1 /S" ; preserve silent mode in the old uninstaller',
        "              ${EndIf}",
        '              StrCpy $R1 "$R1 _?=$4" ; _?= must be the final argument',
        "              ClearErrors",
        "              ExecWait '$R1' $0",
        "              ${If} ${Errors}",
        "                StrCpy $0 2",
        "              ${EndIf}",
        "            ${EndIf}",
        "          ${EndIf}",
        '          Delete "$R2"',
        "        ${EndIf}",
        "      ${EndIf}",
      ]),
      upstream: block([
        '      ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""',
        '      ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"',
        '      ${IfThen} $UpdateMode = 1 ${|} StrCpy $R1 "$R1 /UPDATE" ${|} ; append /UPDATE',
        '      ${IfThen} $PassiveMode = 1 ${|} StrCpy $R1 "$R1 /P" ${|} ; append /P',
        '      StrCpy $R1 "$R1 _?=$4" ; append uninstall directory',
        "      ExecWait '$R1' $0",
      ]),
    },
    {
      label: "unconditional product repair detection",
      patched: block([
        "  ; These calls are intentionally unconditional and precede every silent,",
        "  ; passive, custom-page, and install-section path. Product-owned binaries and",
        "  ; registration can therefore be repaired without making private data or a",
        "  ; managed runtime an installer prerequisite.",
        "  Call DetectVersionNeutralProductRepair",
        "",
      ]),
      upstream: "",
    },
    {
      label: "fixed runtime-cache and Windows prerequisite preparation dispatch",
      patched: block([
        "",
        "  ; Seed a verified private recovery copy before first launch. This bounded,",
        "  ; non-executing optimization is deliberately non-fatal: app installation and",
        "  ; independent work remain available even when the cache cannot be prepared.",
        "  ; Registration overlays (stale/same-version/upgrade) preserve private runtime",
        "  ; bytes exactly and leave any new-version preparation to the reopened app.",
        "  ${If} $RegistrationOverlayMode = 0",
        "    Call SeedManagedRuntimePrivateCache",
        "  ${EndIf}",
        "",
        "  ; Prepare Windows support only after every application binary and its",
        "  ; registration have been installed. Failure can therefore never roll back or",
        "  ; hide the application shell, and no later manual setup page is required.",
        "  Call RunWindowsInstallerPrerequisiteCoordinator",
      ]),
      upstream: "",
    },
    {
      label: "uninstall default selection",
      patched: block([
        "",
        "  ; This default is intentionally immune to silent/passive command-line input.",
        "  ; /UPDATE also forces app-only again inside the coordinator function.",
        '  StrCpy $UninstallChoice "app-only"',
      ]),
      upstream: "",
    },
    {
      label: "do not mutate an unowned Windows Run value",
      patched: block([
        "  ; ai-security-scanner does not create a Windows Run entry. Do not delete a",
        "  ; same-named value that another program or the user may own.",
      ]),
      upstream: block([
        "  ; Removes the Autostart entry for ${PRODUCTNAME} from the HKCU Run key if it exists.",
        "  ; This ensures the program does not launch automatically after uninstallation if it exists.",
        "  ; If it doesn't exist, it does nothing.",
        "  ; We do this when not updating (to preserve the registry value on updates)",
        "  ${If} $UpdateMode <> 1",
        '    DeleteRegValue HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Run" "${PRODUCTNAME}"',
        "  ${EndIf}",
      ]),
    },
  ];

  for (const rewrite of rewrites) {
    reconstructed = rewrite.count
      ? replaceExactly(
          reconstructed,
          rewrite.patched,
          rewrite.upstream,
          rewrite.count,
          rewrite.label,
        )
      : replaceOnce(reconstructed, rewrite.patched, rewrite.upstream, rewrite.label);
  }
  reconstructed = removeFunction(reconstructed, "DetectVersionNeutralProductRepair");
  reconstructed = removeFunction(reconstructed, "SeedManagedRuntimePrivateCache");
  reconstructed = removeFunction(
    reconstructed,
    "RunWindowsInstallerPrerequisiteCoordinator",
  );
  reconstructed = removeFunction(reconstructed, "un.RunProductUninstallCoordinator");
  reconstructed = removeFunction(reconstructed, "un.PersistCoordinatorReceipt");
  reconstructed = removeFunction(reconstructed, "un.AppendPostconditionReceipt");
  reconstructed = removeFunction(reconstructed, "SkipDirectoryIfRepairOrPassive");
  reconstructed = replaceBoundedSection(
    reconstructed,
    "; BEGIN AI SECURITY SCANNER BILINGUAL PRODUCT STRINGS\n",
    "Function .onInit\n",
    "",
    "bilingual uninstall strings",
  );
  reconstructed = replaceBoundedSection(
    reconstructed,
    "  ; BEGIN AI SECURITY SCANNER BOUNDED UNINSTALL DISPATCH\n",
    "  ; Delete the app directory and its content from disk\n",
    "",
    "bounded uninstall dispatch",
  );
  reconstructed = replaceBoundedSection(
    reconstructed,
    "  ; BEGIN AI SECURITY SCANNER EXACT REGISTRATION AND POSTCONDITIONS\n",
    "  !ifmacrodef NSIS_HOOK_POSTUNINSTALL\n",
    block([
      "  ; Delete app data if the checkbox is selected",
      "  ; and if not updating",
      "  ${If} $DeleteAppDataCheckboxState = 1",
      "  ${AndIf} $UpdateMode <> 1",
      "    ; Clear the install location $INSTDIR from registry",
      '    DeleteRegKey SHCTX "${MANUPRODUCTKEY}"',
      '    DeleteRegKey /ifempty SHCTX "${MANUKEY}"',
      "",
      "    ; Clear the install language from registry",
      '    DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"',
      '    DeleteRegKey /ifempty HKCU "${MANUPRODUCTKEY}"',
      '    DeleteRegKey /ifempty HKCU "${MANUKEY}"',
      "",
      "    SetShellVarContext current",
      '    RmDir /r "$APPDATA\\${BUNDLEID}"',
      '    RmDir /r "$LOCALAPPDATA\\${BUNDLEID}"',
      "  ${EndIf}",
      "",
    ]),
    "exact registration and postconditions",
  );
  reconstructed = replaceBoundedSection(
    reconstructed,
    "; Uninstaller Pages\n",
    "; 2. Uninstalling Page\n",
    block([
      "; Uninstaller Pages",
      "; 1. Confirm uninstall page",
      "Var DeleteAppDataCheckbox",
      "Var DeleteAppDataCheckboxState",
      "!define /ifndef WS_EX_LAYOUTRTL         0x00400000",
      "!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.ConfirmShow",
      "Function un.ConfirmShow ; Add add a `Delete app data` check box",
      "  ; $1 inner dialog HWND",
      "  ; $2 window DPI",
      "  ; $3 style",
      "  ; $4 x",
      "  ; $5 y",
      "  ; $6 width",
      "  ; $7 height",
      '  FindWindow $1 "#32770" "" $HWNDPARENT ; Find inner dialog',
      '  System::Call "user32::GetDpiForWindow(p r1) i .r2"',
      "  ${If} $(^RTL) = 1",
      '    StrCpy $3 "${__NSD_CheckBox_EXSTYLE} | ${WS_EX_LAYOUTRTL}"',
      "    IntOp $4 50 * $2",
      "  ${Else}",
      '    StrCpy $3 "${__NSD_CheckBox_EXSTYLE}"',
      "    IntOp $4 0 * $2",
      "  ${EndIf}",
      "  IntOp $5 100 * $2",
      "  IntOp $6 400 * $2",
      "  IntOp $7 25 * $2",
      "  IntOp $4 $4 / 96",
      "  IntOp $5 $5 / 96",
      "  IntOp $6 $6 / 96",
      "  IntOp $7 $7 / 96",
      '  System::Call \'user32::CreateWindowEx(i r3, w "${__NSD_CheckBox_CLASS}", w "$(deleteAppData)", i ${__NSD_CheckBox_STYLE}, i r4, i r5, i r6, i r7, p r1, i0, i0, i0) i .s\'',
      "  Pop $DeleteAppDataCheckbox",
      "  SendMessage $HWNDPARENT ${WM_GETFONT} 0 0 $1",
      "  SendMessage $DeleteAppDataCheckbox ${WM_SETFONT} $1 1",
      "FunctionEnd",
      "!define MUI_PAGE_CUSTOMFUNCTION_LEAVE un.ConfirmLeave",
      "Function un.ConfirmLeave",
      "  SendMessage $DeleteAppDataCheckbox ${BM_GETCHECK} 0 0 $DeleteAppDataCheckboxState",
      "FunctionEnd",
      "!define MUI_PAGE_CUSTOMFUNCTION_PRE un.SkipIfPassive",
      "!insertmacro MUI_UNPAGE_CONFIRM",
      "",
    ]),
    "three-choice uninstall page",
  );
  return reconstructed;
}

function modeledRepairDecision({ exactIdentity, mainBinaryPresent, uninstallerPresent, compare }) {
  if (!exactIdentity) return "normal";
  if (!mainBinaryPresent || !uninstallerPresent) return "stale_repair";
  if (compare === 0) return "same_version_repair";
  if (compare === 1) return "upgrade_overlay";
  return "normal";
}

function modeledUninstallChoice({ updateMode, passive, silent, selected }) {
  if (updateMode || passive || silent) return "app-only";
  return ["app-only", "scan-tools", "all-data"].includes(selected) ? selected : "app-only";
}

function modeledCoordinatorOutcome({ invocationFailed, exitCode }) {
  if (invocationFailed) return "fatal";
  if (exitCode === 0) return "completed";
  if (exitCode === 10) return "retained-warning";
  if (exitCode === 20) return "contact-not-stopped";
  return "fatal";
}

function modeledRegistrationOutcome({ updateMode, selected }) {
  if (updateMode) return "preserve-install-path-and-language";
  if (selected === "all-data") return "remove-exact-product-key";
  return "remove-install-path-preserve-language";
}

function modeledWindowsPrerequisiteOutcome({ invocation, exitCode, resultClass }) {
  if (invocation === "missing" || invocation === "error" || invocation === "timeout") {
    return "retry";
  }
  if (exitCode === 0 && ["ready", "serviced"].includes(resultClass)) return "ready";
  if (exitCode === 10 && resultClass === "restart_required") return "restart_required";
  if (exitCode === 20 && resultClass === "cancelled") return "retry";
  if (exitCode === 30 && resultClass === "failed") return "retry";
  return "retry";
}

function modeledRuntimeCacheSeedOutcome({ invocation, exitCode, resultClass }) {
  if (invocation === "complete" && exitCode === 0 && resultClass === "seeded") {
    return "seeded";
  }
  return "unavailable";
}

function validateModeledDecisionTable() {
  const fixtures = [
    [{ exactIdentity: false, mainBinaryPresent: false, uninstallerPresent: false, compare: 1 }, "normal"],
    [{ exactIdentity: true, mainBinaryPresent: false, uninstallerPresent: false, compare: -1 }, "stale_repair"],
    [{ exactIdentity: true, mainBinaryPresent: false, uninstallerPresent: true, compare: 0 }, "stale_repair"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: false, compare: 0 }, "stale_repair"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: 0 }, "same_version_repair"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: 1 }, "upgrade_overlay"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: -1 }, "normal"],
    [{ exactIdentity: true, mainBinaryPresent: true, uninstallerPresent: true, compare: null }, "normal"],
  ];
  for (const [input, expected] of fixtures) {
    assert(
      modeledRepairDecision(input) === expected,
      `version-neutral installer decision drifted for ${JSON.stringify(input)}`,
    );
  }

  const uninstallFixtures = [
    [{ updateMode: false, passive: false, silent: false, selected: "app-only" }, "app-only"],
    [{ updateMode: false, passive: false, silent: false, selected: "scan-tools" }, "scan-tools"],
    [{ updateMode: false, passive: false, silent: false, selected: "all-data" }, "all-data"],
    [{ updateMode: false, passive: false, silent: false, selected: "unexpected" }, "app-only"],
    [{ updateMode: false, passive: true, silent: false, selected: "all-data" }, "app-only"],
    [{ updateMode: false, passive: false, silent: true, selected: "all-data" }, "app-only"],
    [{ updateMode: true, passive: false, silent: false, selected: "all-data" }, "app-only"],
  ];
  for (const [input, expected] of uninstallFixtures) {
    assert(
      modeledUninstallChoice(input) === expected,
      `uninstall choice drifted for ${JSON.stringify(input)}`,
    );
  }

  const outcomeFixtures = [
    [{ invocationFailed: false, exitCode: 0 }, "completed"],
    [{ invocationFailed: false, exitCode: 10 }, "retained-warning"],
    [{ invocationFailed: false, exitCode: 20 }, "contact-not-stopped"],
    [{ invocationFailed: false, exitCode: 1 }, "fatal"],
    [{ invocationFailed: false, exitCode: 30 }, "fatal"],
    [{ invocationFailed: true, exitCode: 0 }, "fatal"],
  ];
  for (const [input, expected] of outcomeFixtures) {
    assert(
      modeledCoordinatorOutcome(input) === expected,
      `uninstall coordinator outcome drifted for ${JSON.stringify(input)}`,
    );
  }

  const registrationFixtures = [
    [{ updateMode: true, selected: "app-only" }, "preserve-install-path-and-language"],
    [{ updateMode: true, selected: "all-data" }, "preserve-install-path-and-language"],
    [{ updateMode: false, selected: "app-only" }, "remove-install-path-preserve-language"],
    [{ updateMode: false, selected: "scan-tools" }, "remove-install-path-preserve-language"],
    [{ updateMode: false, selected: "all-data" }, "remove-exact-product-key"],
  ];
  for (const [input, expected] of registrationFixtures) {
    assert(
      modeledRegistrationOutcome(input) === expected,
      `uninstall registration outcome drifted for ${JSON.stringify(input)}`,
    );
  }

  const prerequisiteFixtures = [
    [{ invocation: "missing", exitCode: null, resultClass: null }, "retry"],
    [{ invocation: "error", exitCode: null, resultClass: null }, "retry"],
    [{ invocation: "timeout", exitCode: null, resultClass: null }, "retry"],
    [{ invocation: "complete", exitCode: 0, resultClass: "ready" }, "ready"],
    [{ invocation: "complete", exitCode: 0, resultClass: "serviced" }, "ready"],
    [{ invocation: "complete", exitCode: 10, resultClass: "restart_required" }, "restart_required"],
    [{ invocation: "complete", exitCode: 20, resultClass: "cancelled" }, "retry"],
    [{ invocation: "complete", exitCode: 30, resultClass: "failed" }, "retry"],
    [{ invocation: "complete", exitCode: 0, resultClass: "failed" }, "retry"],
    [{ invocation: "complete", exitCode: 99, resultClass: "ready" }, "retry"],
  ];
  for (const [input, expected] of prerequisiteFixtures) {
    assert(
      modeledWindowsPrerequisiteOutcome(input) === expected,
      `Windows prerequisite outcome drifted for ${JSON.stringify(input)}`,
    );
  }

  const cacheFixtures = [
    [{ invocation: "complete", exitCode: 0, resultClass: "seeded" }, "seeded"],
    [{ invocation: "complete", exitCode: 30, resultClass: "unavailable" }, "unavailable"],
    [{ invocation: "missing", exitCode: null, resultClass: null }, "unavailable"],
    [{ invocation: "timeout", exitCode: null, resultClass: null }, "unavailable"],
    [{ invocation: "complete", exitCode: 0, resultClass: "unavailable" }, "unavailable"],
    [{ invocation: "complete", exitCode: 30, resultClass: "seeded" }, "unavailable"],
  ];
  for (const [input, expected] of cacheFixtures) {
    assert(
      modeledRuntimeCacheSeedOutcome(input) === expected,
      `Windows runtime-cache seed outcome drifted for ${JSON.stringify(input)}`,
    );
  }
}

function validateManagedRuntimeCacheSeedPatch(vendored) {
  const coordinator = extractFunction(vendored, "SeedManagedRuntimePrivateCache").source;
  const fixedCommand =
    'nsExec::ExecToStack /TIMEOUT=180000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json windows-installer-runtime-cache\'';
  const seededEnvelope =
    '{"schema_version":"ai-security-scanner.windows-installer-runtime-cache/v1","result_class":"seeded","exit_code":0,"terminal":"complete"}';
  const unavailableEnvelope =
    '{"schema_version":"ai-security-scanner.windows-installer-runtime-cache/v1","result_class":"unavailable","exit_code":30,"terminal":"complete"}';
  assertOrdered(
    coordinator,
    [
      '${IfNot} ${FileExists} "$INSTDIR\\ai-security-scanner-cli.exe"',
      "Return",
      fixedCommand,
      "Pop $R0",
      "Pop $R1",
      '${If} $R0 = 0',
      `'${seededEnvelope}'`,
      "Return",
      '${If} $R0 = 30',
      `'${unavailableEnvelope}'`,
      "Return",
    ],
    "fixed managed-runtime private-cache seed coordinator",
  );
  assert(
    coordinator.split(fixedCommand).length === 2,
    "installer must invoke exactly one fixed runtime-cache seed command",
  );
  for (const envelope of [seededEnvelope, unavailableEnvelope]) {
    assert(
      coordinator.split(`'${envelope}'`).length === 2,
      `installer does not accept exactly one complete runtime-cache envelope: ${envelope}`,
    );
  }
  assert(
    coordinator.split("ai-security-scanner.windows-installer-runtime-cache/v1").length === 3,
    "installer accepts an incomplete or extra runtime-cache seed envelope",
  );
  for (const forbidden of [
    "$CMDLINE",
    "${GetOptions}",
    "${GetParameters}",
    "wsl.exe",
    "powershell",
    "pwsh",
    "cmd.exe",
    "--data-dir",
    "--managed-runtime-bundle",
    "--path",
    "--action",
    "--executable",
    "--arguments",
    "ExecWait",
    "ExecShell",
    "ShellExec",
    "Abort",
    "Quit",
    "MessageBox",
  ]) {
    assert(
      !coordinator.toLowerCase().includes(forbidden.toLowerCase()),
      `runtime-cache seed coordinator exposes or invokes an unreviewed surface: ${forbidden}`,
    );
  }
  assert(
    !coordinator.includes("DetailPrint $R1") &&
      !coordinator.includes('DetailPrint "$R1"') &&
      !coordinator.includes("FileWrite") &&
      !coordinator.includes("CopyFiles"),
    "runtime-cache seed coordinator persists, displays, or independently copies helper output",
  );
  assert(
    coordinator.includes("without executing Podman, WSL, or another runtime helper") &&
      coordinator.includes("never an application") &&
      coordinator.includes("leaves the installed shell/resources intact"),
    "runtime-cache seed boundary or non-blocking failure contract is missing",
  );

  const installStart = vendored.indexOf("Section Install\n");
  const installEnd = vendored.indexOf("SectionEnd\n", installStart);
  assert(installStart !== -1 && installEnd > installStart, "Install section is missing");
  const install = vendored.slice(installStart, installEnd);
  assertOrdered(
    install,
    [
      'File "${MAINBINARYSRCPATH}"',
      "; Copy external binaries",
      'WriteUninstaller "$INSTDIR\\uninstall.exe"',
      'WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"',
      "!insertmacro NSIS_HOOK_POSTINSTALL",
      "${If} $RegistrationOverlayMode = 0",
      "    Call SeedManagedRuntimePrivateCache",
      "${EndIf}",
      "Call RunWindowsInstallerPrerequisiteCoordinator",
      "SetAutoClose true",
    ],
    "application-first runtime-cache seed dispatch",
  );
  assert(
    install.split("Call SeedManagedRuntimePrivateCache").length === 2,
    "Install section must run the runtime-cache seed coordinator exactly once",
  );
  assert(
    install.includes("Registration overlays (stale/same-version/upgrade) preserve private runtime") &&
      install.indexOf("${If} $RegistrationOverlayMode = 0") <
        install.indexOf("Call SeedManagedRuntimePrivateCache") &&
      install.indexOf("Call SeedManagedRuntimePrivateCache") <
        install.indexOf("${EndIf}", install.indexOf("Call SeedManagedRuntimePrivateCache")),
    "runtime-cache seed must remain fresh-install-only and preserve every registration overlay",
  );
}

function validateInstallerRuntimeCacheBuildWiring({
  cargoManifest,
  buildScript,
  buildSidecar,
  ciWorkflow,
  releaseWorkflow,
}) {
  assert(
    /^installer-runtime-cache = \[\]$/mu.test(cargoManifest),
    "the installed CLI has no dedicated runtime-cache build feature",
  );
  for (const marker of [
    'std::env::var_os("CARGO_FEATURE_INSTALLER_RUNTIME_CACHE")',
    "let needs_managed_runtime_anchor = desktop || installer_runtime_cache;",
    "cargo:rustc-env={MANAGED_RUNTIME_MANIFEST_SHA256_ENV}={manifest_sha256}",
  ]) {
    assert(buildScript.includes(marker), `installer runtime-cache build anchor is missing: ${marker}`);
  }
  assert(
    buildSidecar.includes(
      'binary.name === "ai-security-scanner-cli" && target.includes("windows")',
    ) && buildSidecar.includes("`${binary.feature},installer-runtime-cache`"),
    "Windows sidecar staging does not compile the fixed cache coordinator with its build anchor",
  );
  assertOrdered(
    ciWorkflow,
    [
      "Vendor the release-equivalent Windows managed runtime",
      "node runtime/vendor-managed-runtime.mjs",
      "Verify the staged Windows managed-runtime manifest and files",
      "Build and stage required Windows sidecars",
      "npm run desktop:prepare-sidecar -- --target x86_64-pc-windows-msvc",
      "Test the installer runtime-cache coordinator and build trust anchor",
      "--features cli,installer-runtime-cache",
      "Compile the reviewed custom NSIS installer",
    ],
    "Windows CI runtime-cache build wiring",
  );
  assertOrdered(
    releaseWorkflow,
    [
      "Verify, build, and stage the release-managed local runtime",
      "node runtime/vendor-managed-runtime.mjs",
      "Build and stage the Linux managed egress sidecar",
      "Build and stage the universal macOS managed egress sidecar",
      "Build and stage the Windows managed egress sidecar",
      "npm run desktop:prepare-sidecar -- --target x86_64-pc-windows-msvc",
      "Build the application once without installers",
    ],
    "release runtime-cache build wiring",
  );
  for (const [workflow, label] of [
    [ciWorkflow, "CI"],
    [releaseWorkflow, "release"],
  ]) {
    assert(
      workflow.split("node scripts/release/validate-windows-nsis-template.mjs").length === 2,
      `${label} workflow must validate the reviewed Windows NSIS source exactly once`,
    );
  }
}

function validateWindowsPrerequisitePatch(vendored) {
  const coordinator = extractFunction(
    vendored,
    "RunWindowsInstallerPrerequisiteCoordinator",
  ).source;
  const fixedCommand =
    'nsExec::ExecToStack /TIMEOUT=360000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json windows-installer-prerequisite\'';
  const prerequisiteEnvelopes = [
    '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"ready","exit_code":0,"restart_required":false,"terminal":"complete"}',
    '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"serviced","exit_code":0,"restart_required":false,"terminal":"complete"}',
    '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"restart_required","exit_code":10,"restart_required":true,"terminal":"complete"}',
    '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"cancelled","exit_code":20,"restart_required":false,"terminal":"complete"}',
    '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"failed","exit_code":30,"restart_required":false,"terminal":"complete"}',
  ];
  assertOrdered(
    coordinator,
    [
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptSchema" "ai-security-scanner.windows-prerequisite-receipt/v1"',
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptInstallerVersion" "${VERSION}"',
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "checking"',
      'WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 1',
      'DetailPrint "$(windowsPrerequisiteChecking)"',
      '${IfNot} ${FileExists} "$INSTDIR\\ai-security-scanner-cli.exe"',
      "Goto windows_prerequisite_retry",
      fixedCommand,
      "Pop $R0",
      "Pop $R1",
      '${If} $R0 == "error"',
      '${If} $R0 == "timeout"',
      '${If} $R0 = 0',
      `'${prerequisiteEnvelopes[0]}'`,
      `'${prerequisiteEnvelopes[1]}'`,
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "ready"',
      'WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 0',
      '${ElseIf} $R0 = 10',
      `'${prerequisiteEnvelopes[2]}'`,
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "restart_required"',
      "SetRebootFlag true",
      "SetErrorLevel 3010",
      '${ElseIf} $R0 = 20',
      `'${prerequisiteEnvelopes[3]}'`,
      '${ElseIf} $R0 = 30',
      `'${prerequisiteEnvelopes[4]}'`,
      "windows_prerequisite_retry:",
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "retry"',
      'WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 1',
      'DetailPrint "$(windowsPrerequisiteRetry)"',
    ],
    "fixed Windows prerequisite coordinator",
  );
  assert(
    coordinator.split(fixedCommand).length === 2,
    "installer must invoke exactly one fixed Windows prerequisite coordinator command",
  );
  for (const envelope of prerequisiteEnvelopes) {
    assert(
      coordinator.split(`'${envelope}'`).length === 2,
      `installer does not accept exactly one complete prerequisite envelope: ${envelope}`,
    );
  }
  assert(
    coordinator.split("ai-security-scanner.windows-installer-prerequisite/v1").length === 6,
    "installer accepts an incomplete or extra Windows prerequisite envelope",
  );
  for (const forbidden of [
    "$CMDLINE",
    "${GetOptions}",
    "${GetParameters}",
    "wsl.exe",
    "powershell",
    "pwsh",
    "cmd.exe",
    "--install",
    "--update",
    "--path",
    "--action",
    "--executable",
    "--arguments",
    "--data-dir",
    "--managed-runtime-bundle",
    "ExecWait",
    "ExecShell",
    "ShellExec",
    "Abort",
    "Quit",
    "MessageBox",
  ]) {
    assert(
      !coordinator.toLowerCase().includes(forbidden.toLowerCase()),
      `Windows prerequisite coordinator exposes or invokes an unreviewed surface: ${forbidden}`,
    );
  }
  assert(
    !coordinator.includes("DetailPrint $R1") &&
      !coordinator.includes('DetailPrint "$R1"') &&
      !coordinator.includes("FileWrite") &&
      !coordinator.includes("CopyFiles"),
    "Windows prerequisite coordinator persists or displays helper output",
  );
  assert(
    coordinator.split('WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult"').length === 5 &&
      coordinator.split('WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint"').length === 5,
    "Windows prerequisite durable state is missing or has an unreviewed extra transition",
  );
  assert(
    coordinator.split("SetRebootFlag true").length === 2 &&
      coordinator.split("SetErrorLevel 3010").length === 2 &&
      coordinator.indexOf("SetRebootFlag true") >
        coordinator.indexOf('"WindowsPrerequisiteReceiptResult" "restart_required"') &&
      coordinator.indexOf("SetRebootFlag true") <
        coordinator.indexOf("SetErrorLevel 3010") &&
      coordinator.indexOf("SetErrorLevel 3010") <
        coordinator.indexOf('DetailPrint "$(windowsPrerequisiteRestart)"'),
    "Windows prerequisite restart is not propagated once through the NSIS reboot flag and standard success-with-restart exit",
  );
  assert(
    !coordinator.replace("SetErrorLevel 3010", "").includes("SetErrorLevel"),
    "Windows prerequisite coordinator contains an unreviewed process exit override",
  );
  assert(
    coordinator.indexOf('"WindowsPrerequisiteReceiptResult" "checking"') <
      coordinator.indexOf(fixedCommand),
    "Windows prerequisite operation is not durable before the side effect",
  );
  assert(
    coordinator.includes("one non-authoritative receipt") &&
      coordinator.includes("never readiness proof") &&
      coordinator.includes("every app") &&
      coordinator.includes("re-probes authoritative Windows state"),
    "Windows prerequisite receipt can be mistaken for authoritative readiness state",
  );
  for (const forbiddenControlName of [
    "WindowsPrerequisiteStatus",
    "WindowsPrerequisiteResumePending",
  ]) {
    assert(
      !coordinator.includes(forbiddenControlName),
      `Windows prerequisite receipt uses an authoritative-looking control name: ${forbiddenControlName}`,
    );
  }

  for (const id of [
    "windowsPrerequisiteChecking",
    "windowsPrerequisiteReady",
    "windowsPrerequisiteRestart",
    "windowsPrerequisiteRetry",
  ]) {
    assert(
      vendored.split(`LangString ${id} ${"${LANG_ENGLISH}"}`).length === 2 &&
        vendored.split(`LangString ${id} ${"${LANG_TRADCHINESE}"}`).length === 2,
      `Windows prerequisite message is not defined once in both product languages: ${id}`,
    );
  }

  const installStart = vendored.indexOf("Section Install\n");
  const installEnd = vendored.indexOf("SectionEnd\n", installStart);
  assert(installStart !== -1 && installEnd > installStart, "Install section is missing");
  const install = vendored.slice(installStart, installEnd);
  assertOrdered(
    install,
    [
      'File "${MAINBINARYSRCPATH}"',
      "; Copy external binaries",
      'WriteUninstaller "$INSTDIR\\uninstall.exe"',
      'WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"',
      "!insertmacro NSIS_HOOK_POSTINSTALL",
      "Call RunWindowsInstallerPrerequisiteCoordinator",
      "SetAutoClose true",
    ],
    "application-first Windows prerequisite dispatch",
  );
  assert(
    install.split("Call RunWindowsInstallerPrerequisiteCoordinator").length === 2,
    "Install section must run the fixed prerequisite coordinator exactly once",
  );
}

function validateProductUninstallPatch(vendored) {
  assert(
    vendored.split("UninstPage custom un.UninstallChoicePage un.UninstallChoiceLeave").length === 2,
    "the three-choice uninstall page is missing or duplicated",
  );
  for (const forbidden of [
    "DeleteAppDataCheckbox",
    "DeleteAppDataCheckboxState",
    "$(deleteAppData)",
    "MUI_UNPAGE_CONFIRM",
  ]) {
    assert(!vendored.includes(forbidden), `legacy all-or-nothing uninstall control remains: ${forbidden}`);
  }

  const page = extractFunction(vendored, "un.UninstallChoicePage").source;
  assertOrdered(
    page,
    [
      "${If} $PassiveMode = 1",
      "${OrIf} $UpdateMode = 1",
      "${OrIf} ${Silent}",
      "Abort",
      "nsDialogs::Create 1018",
      '${If} $UninstallChoice == "scan-tools"',
      "${NSD_Check} $UninstallScanToolsRadio",
      '${ElseIf} $UninstallChoice == "all-data"',
      "${NSD_Check} $UninstallAllDataRadio",
      "${Else}",
      "${NSD_Check} $UninstallAppOnlyRadio",
    ],
    "uninstall choice page",
  );
  assert(
    page.split("${NSD_CreateRadioButton}").length === 7,
    "each of the two language paths must expose exactly three uninstall choices",
  );
  for (const required of [
    "Remove the app only (default)",
    "Remove the app and scan tools; keep my projects",
    "Remove the app and all ai-security-scanner data",
    "Keeps projects, evidence, exports, preferences, signing identity, and scan tools.",
    "Ambiguous items are retained.",
    "僅移除應用程式（預設）",
    "移除應用程式與掃描工具；保留專案",
    "移除應用程式與所有 ai-security-scanner 資料",
  ]) {
    assert(page.includes(required), `uninstall choice disclosure is missing: ${required}`);
  }

  const leave = extractFunction(vendored, "un.UninstallChoiceLeave").source;
  assertOrdered(
    leave,
    [
      "${NSD_GetState} $UninstallScanToolsRadio $0",
      'StrCpy $UninstallChoice "scan-tools"',
      "${NSD_GetState} $UninstallAllDataRadio $0",
      "MB_ICONSTOP|MB_YESNO|MB_DEFBUTTON2",
      "IDYES un_all_data_confirmed",
      "Abort",
      "un_all_data_confirmed:",
      'StrCpy $UninstallChoice "all-data"',
      'StrCpy $UninstallChoice "app-only"',
    ],
    "explicit all-data confirmation",
  );
  assert(
    leave.includes("cannot be undone") && leave.includes("export a backup first"),
    "all-data confirmation does not disclose irreversibility and the backup exit",
  );
  assert(
    leave.includes("無法復原") && leave.includes("先匯出備份"),
    "Traditional Chinese all-data confirmation does not disclose irreversibility and backup",
  );

  const uninit = extractFunction(vendored, "un.onInit").source;
  assertOrdered(
    uninit,
    [
      '${GetOptions} $CMDLINE "/P" $PassiveMode',
      '${GetOptions} $CMDLINE "/UPDATE" $UpdateMode',
      'StrCpy $UninstallChoice "app-only"',
    ],
    "uninstall default selection",
  );
  assert(
    !/\$\{GetOptions\}\s+\$CMDLINE\s+"\/(?:MODE|SCAN-TOOLS|ALL-DATA|DATA-DIR)\b/iu.test(uninit) &&
      !uninit.includes("${GetParameters}"),
    "uninstaller accepts a command-line cleanup selection instead of defaulting headless use to app-only",
  );

  const coordinator = extractFunction(vendored, "un.RunProductUninstallCoordinator").source;
  const appOnlyCommand =
    'nsExec::ExecToStack /TIMEOUT=600000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json product-uninstall --mode app-only --non-interactive --coordinator-envelope\'';
  const scanToolsCommand =
    'nsExec::ExecToStack /TIMEOUT=600000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json product-uninstall --mode scan-tools --non-interactive --coordinator-envelope\'';
  const allDataCommand =
    'nsExec::ExecToStack /TIMEOUT=600000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json product-uninstall --mode all-data --non-interactive --confirmation "REMOVE ALL AI-SECURITY-SCANNER DATA" --coordinator-envelope\'';
  assertOrdered(
    coordinator,
    [
      "${If} $UpdateMode = 1",
      'StrCpy $UninstallChoice "app-only"',
      "un_coordinator_retry:",
      '${If} $UninstallChoice == "scan-tools"',
      scanToolsCommand,
      '${ElseIf} $UninstallChoice == "all-data"',
      allDataCommand,
      "${Else}",
      appOnlyCommand,
      "Pop $0",
      "Pop $UninstallCoordinatorOutput",
      'DetailPrint "$(unCoordinatorRecordLabel) $UninstallCoordinatorOutput"',
      '${If} $0 == "error"',
      'StrCpy $UninstallCoordinatorResult "fatal"',
      '${If} $0 == "timeout"',
      "Call un.PersistCoordinatorReceipt",
      'StrCpy $UninstallCoordinatorResult "fatal"',
      '${UnStrLoc} $1 $UninstallCoordinatorOutput \'"schema_version":"ai-security-scanner.product-uninstall/v1"\' ">"',
      'StrCpy $2 \'"mode":"scan_tools"\'',
      'StrCpy $2 \'"mode":"all_data"\'',
      'StrCpy $2 \'"mode":"app_only"\'',
      '${UnStrLoc} $1 $UninstallCoordinatorOutput \'"terminal":"complete"}\' ">"',
      'StrCpy $2 \'"result_class":"completed","exit_code":0\'',
      'StrCpy $2 \'"result_class":"completed_with_retained_state","exit_code":10\'',
      'StrCpy $2 \'"result_class":"contact_not_stopped","exit_code":20\'',
      "un_coordinator_invalid_record:",
      'StrCpy $UninstallCoordinatorResult "fatal"',
      "un_coordinator_record_valid:",
      "${If} $0 = 0",
      'StrCpy $UninstallCoordinatorResult "completed"',
      "${If} $0 = 10",
      'StrCpy $UninstallCoordinatorResult "retained-warning"',
      "${If} $0 = 20",
      "IDRETRY un_coordinator_retry",
      'StrCpy $UninstallCoordinatorResult "contact-not-stopped"',
      'StrCpy $UninstallCoordinatorResult "fatal"',
    ],
    "fixed product-uninstall coordinator",
  );
  for (const command of [appOnlyCommand, scanToolsCommand, allDataCommand]) {
    assert(
      coordinator.split(command).length === 2,
      `fixed product-uninstall command is missing or duplicated: ${command}`,
    );
  }
  assert(
    !coordinator.includes("ExecWait") &&
      coordinator.split("nsExec::ExecToStack /TIMEOUT=600000").length === 4 &&
      coordinator.split("--coordinator-envelope").length === 4,
    "uninstall coordinator is not limited to the three bounded stdout-capturing CLI forms",
  );
  assert(
    coordinator.includes("exactly one fixed envelope at exit") &&
      coordinator.includes('"terminal":"complete"}') &&
      coordinator.includes('"result_class":"completed","exit_code":0') &&
      coordinator.includes('"result_class":"completed_with_retained_state","exit_code":10') &&
      coordinator.includes('"result_class":"contact_not_stopped","exit_code":20'),
    "uninstall coordinator does not validate one complete mode/result/exit envelope",
  );
  assert(
    coordinator.split('--confirmation "REMOVE ALL AI-SECURITY-SCANNER DATA"').length === 2,
    "all-data confirmation token is missing, duplicated, or passed to another mode",
  );
  assert(
    vendored.split("\n${UnStrLoc}\n").length === 2 &&
      coordinator.split("${UnStrLoc}").length === 5 &&
      !coordinator.includes("${StrLoc}"),
    "uninstall string searches are not compiled and dispatched through the uninstaller helper",
  );
  assert(
    vendored.split("!define PRODUCT_LANG_TRADCHINESE 1028").length === 2 &&
      vendored.split("$LANGUAGE == ${PRODUCT_LANG_TRADCHINESE}").length === 5,
    "custom uninstall pages do not use the reviewed Traditional Chinese language identifier",
  );
  const languageActivation = vendored.indexOf("!insertmacro MUI_LANGUAGE");
  assert(languageActivation !== -1, "NSIS language activation is missing");
  assert(
    !vendored.slice(0, languageActivation).includes("$LANGUAGE == ${LANG_TRADCHINESE}"),
    "custom NSIS code references LANG_TRADCHINESE before LoadLanguageFile defines it",
  );
  for (const forbidden of [
    "--data-dir",
    "--path",
    "--runtime",
    "--distro",
    "$APPDATA",
    "$LOCALAPPDATA",
    "--unregister",
  ]) {
    assert(!coordinator.includes(forbidden), `coordinator accepts or derives an unreviewed target: ${forbidden}`);
  }

  const receipt = extractFunction(vendored, "un.PersistCoordinatorReceipt").source;
  assertOrdered(
    receipt,
    [
      '${If} $UninstallReceiptPath != ""',
      '${If} $UninstallCoordinatorOutput == ""',
      "GetTempFileName $UninstallReceiptPath $TEMP",
      'FileOpen $1 "$UninstallReceiptPath" w',
      'FileWrite $1 "$UninstallCoordinatorOutput$\\r$\\n"',
      "FileClose $1",
      'DetailPrint "$(unCoordinatorReceiptSaved) $UninstallReceiptPath"',
    ],
    "bounded unique uninstall receipt",
  );
  for (const forbidden of ["$APPDATA", "$LOCALAPPDATA", "$INSTDIR", "--output", "--receipt"] ) {
    assert(!receipt.includes(forbidden), `uninstall receipt derives an unsafe or caller-selected path: ${forbidden}`);
  }
  assert(
    receipt.split("GetTempFileName $UninstallReceiptPath $TEMP").length === 2 &&
      receipt.split('FileOpen $1 "$UninstallReceiptPath" w').length === 2,
    "uninstall receipt is not one unique Windows-temp file",
  );

  const postconditionReceipt = extractFunction(
    vendored,
    "un.AppendPostconditionReceipt",
  ).source;
  assertOrdered(
    postconditionReceipt,
    [
      "Call un.PersistCoordinatorReceipt",
      'FileOpen $1 "$UninstallReceiptPath" a',
      '"result":"partial"',
      '"reason_code":"known_app_or_registration_retained"',
      "FileClose $1",
    ],
    "truthful NSIS postcondition receipt",
  );

  const localizedMessageIds = [
    "unCoordinatorRecordLabel",
    "unCoordinatorStartFailed",
    "unCoordinatorTimedOut",
    "unCoordinatorInvalidRecord",
    "unCoordinatorFatal",
    "unCoordinatorRetained",
    "unCoordinatorReceiptSaved",
    "unCoordinatorReceiptFailed",
    "unCoordinatorContactNotStopped",
    "unCoordinatorContactRetained",
    "unPostconditionPartial",
  ];
  for (const id of localizedMessageIds) {
    assert(
      vendored.split(`LangString ${id} ${"${LANG_ENGLISH}"}`).length === 2 &&
        vendored.split(`LangString ${id} ${"${LANG_TRADCHINESE}"}`).length === 2,
      `uninstall message is not defined exactly once in English and Traditional Chinese: ${id}`,
    );
  }
  for (const [label, source] of [
    ["coordinator", coordinator],
    ["receipt", receipt],
  ]) {
    for (const line of source.split("\n").filter((candidate) => /^\s*(?:DetailPrint|MessageBox)\b/u.test(candidate))) {
      assert(line.includes("$("), `${label} has a non-localized uninstall message: ${line.trim()}`);
    }
  }

  const sectionStart = vendored.indexOf("Section Uninstall\n");
  const sectionEnd = vendored.indexOf("SectionEnd\n", sectionStart);
  assert(sectionStart !== -1 && sectionEnd > sectionStart, "Uninstall section is missing");
  const section = vendored.slice(sectionStart, sectionEnd);
  const exactRegistrationStart = section.indexOf(
    "  ; BEGIN AI SECURITY SCANNER EXACT REGISTRATION AND POSTCONDITIONS\n",
  );
  const exactRegistrationEnd = section.indexOf(
    "  ; END AI SECURITY SCANNER EXACT REGISTRATION AND POSTCONDITIONS\n",
    exactRegistrationStart,
  );
  assert(
    exactRegistrationStart !== -1 && exactRegistrationEnd > exactRegistrationStart,
    "exact registration and postcondition block is missing",
  );
  const exactRegistration = section.slice(exactRegistrationStart, exactRegistrationEnd);
  for (const line of section.split("\n").filter((candidate) => /^\s*(?:DetailPrint|MessageBox)\b/u.test(candidate))) {
    assert(line.includes("$("), `uninstall section has a non-localized message: ${line.trim()}`);
  }
  assertOrdered(
    section,
    [
      '!insertmacro CheckIfAppIsRunning "$INSTDIR\\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"',
      "Call un.RunProductUninstallCoordinator",
      '${If} $UninstallCoordinatorResult == "contact-not-stopped"',
      "SetErrorLevel 20",
      "Quit",
      '${ElseIf} $UninstallCoordinatorResult == "fatal"',
      "SetErrorLevel 1",
      "Quit",
      "StrCpy $UninstallPartialOutcome 0",
      '${If} $UninstallCoordinatorResult == "retained-warning"',
      '${AndIf} $UpdateMode <> 1',
      "StrCpy $UninstallPartialOutcome 1",
      'ReadRegStr $UninstallInstallPathRegistration HKCU "${MANUPRODUCTKEY}" ""',
      'ReadRegStr $UninstallInstallerLanguage HKCU "${MANUPRODUCTKEY}" "Installer Language"',
      'Delete "$INSTDIR\\${MAINBINARYNAME}.exe"',
      "; Delete external binaries",
      "{{#each binaries}}",
      'Delete "$INSTDIR\\\\{{this}}"',
      'DeleteRegKey HKCU "${UNINSTKEY}"',
      '${If} $UpdateMode <> 1',
      '${If} $UninstallChoice == "all-data"',
      'DeleteRegKey HKCU "${MANUPRODUCTKEY}"',
      'DeleteRegKey /ifempty HKCU "${MANUKEY}"',
      "${Else}",
      'DeleteRegValue HKCU "${MANUPRODUCTKEY}" ""',
      '${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"',
      "{{#each binaries}}",
      '${If} ${FileExists} "$INSTDIR\\\\{{this}}"',
      "{{/each}}",
      '${If} ${FileExists} "$INSTDIR\\uninstall.exe"',
      'EnumRegValue $0 HKCU "${UNINSTKEY}" 0',
      'EnumRegKey $0 HKCU "${UNINSTKEY}" 0',
      '${ElseIf} $UninstallChoice == "all-data"',
      'EnumRegValue $0 HKCU "${MANUPRODUCTKEY}" 0',
      'EnumRegKey $0 HKCU "${MANUPRODUCTKEY}" 0',
      '${If} $UninstallPostconditionFailed = 1',
      "Call un.AppendPostconditionReceipt",
      'DetailPrint "$(unPostconditionPartial)"',
      '${If} $UninstallPartialOutcome = 1',
      "SetErrorLevel 10",
    ],
    "bounded coordinator before application deletion",
  );
  assert(
    section.split("Call un.RunProductUninstallCoordinator").length === 2,
    "uninstall invokes the coordinator more or less than once",
  );
  for (const forbidden of [
    "RmDir /r",
    "RMDir /r",
    "$APPDATA\\${BUNDLEID}",
    "$LOCALAPPDATA\\${BUNDLEID}",
    "DeleteAppData",
  ]) {
    assert(!section.includes(forbidden), `NSIS still performs broad product-data cleanup: ${forbidden}`);
  }
  assert(section.split('DeleteRegValue HKCU "${MANUPRODUCTKEY}" ""').length === 2,
    "app-only/scan-tools do not remove exactly one install-path registration");
  assert(section.split('DeleteRegKey HKCU "${MANUPRODUCTKEY}"').length === 2,
    "all-data does not remove exactly one exact product registration key");
  assert(section.split('DeleteRegKey /ifempty HKCU "${MANUKEY}"').length === 2,
    "all-data does not remove exactly one exact empty manufacturer key");
  assert(!section.includes('DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"'),
    "app-only or scan-tools can delete the preserved installer language");
  assert(
    !section.includes('DeleteRegValue HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Run"'),
    "uninstaller still deletes a name-only Windows Run value that the product does not create",
  );
  assert(
    section.includes("/UPDATE preserves both product values.") &&
      section.includes("App-only and scan-tools") &&
      section.includes("All-data removes only the exact product key"),
    "mode-specific exact registration behavior is no longer explicit",
  );
  assertOrdered(
    exactRegistration,
    [
      '${If} $UpdateMode <> 1',
      '${If} $UninstallChoice == "all-data"',
      'DeleteRegKey HKCU "${MANUPRODUCTKEY}"',
      'DeleteRegKey /ifempty HKCU "${MANUKEY}"',
      "${Else}",
      'DeleteRegValue HKCU "${MANUPRODUCTKEY}" ""',
      'EnumRegValue $0 HKCU "${UNINSTKEY}" 0',
      'EnumRegKey $0 HKCU "${UNINSTKEY}" 0',
      '${ElseIf} $UninstallChoice == "all-data"',
      'EnumRegValue $0 HKCU "${MANUPRODUCTKEY}" 0',
      'EnumRegKey $0 HKCU "${MANUPRODUCTKEY}" 0',
      '${If} $UninstallPostconditionFailed = 1',
      "Call un.AppendPostconditionReceipt",
      'DetailPrint "$(unPostconditionPartial)"',
      '${If} $UninstallPartialOutcome = 1',
      "SetErrorLevel 10",
    ],
    "mode-specific exact registration and postconditions",
  );
}

function validateSynchronousPreviousUninstallerPatch(vendored) {
  const pageLeave = extractFunction(vendored, "PageLeaveReinstall").source;
  const branchStart = pageLeave.indexOf(
    '      ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""',
  );
  const branchEnd = pageLeave.indexOf("\n    ${EndIf}\n\n    BringToFront", branchStart);
  assert(
    branchStart !== -1 && branchEnd > branchStart,
    "NSIS previous-uninstaller branch is missing",
  );
  const branch = pageLeave.slice(branchStart, branchEnd);
  assertOrdered(
    branch,
    [
      'ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""',
      'ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"',
      "StrCpy $R3 '$\\\"$4\\uninstall.exe$\\\"'",
      '${If} $4 == ""',
      "${ElseIf} $R1 != $R3",
      '${IfNot} ${FileExists} "$4\\uninstall.exe"',
      "InitPluginsDir",
      'StrCpy $R2 "$PLUGINSDIR\\ai-security-scanner-previous-uninstaller.exe"',
      'CopyFiles /SILENT "$4\\uninstall.exe" "$R2"',
      '${IfNot} ${FileExists} "$R2"',
      "StrCpy $R1 '$\\\"$R2$\\\"'",
      '${IfThen} $UpdateMode = 1 ${|} StrCpy $R1 "$R1 /UPDATE" ${|}',
      "${If} $PassiveMode = 1",
      'StrCpy $R1 "$R1 /P"',
      "${ElseIf} ${Silent}",
      'StrCpy $R1 "$R1 /S"',
      'StrCpy $R1 "$R1 _?=$4" ; _?= must be the final argument',
      "ClearErrors",
      "ExecWait '$R1' $0",
      "${If} ${Errors}",
      'Delete "$R2"',
    ],
    "synchronous copied previous-uninstaller execution",
  );
  assert(
    branch.split("InitPluginsDir").length === 2 &&
      branch.split("CopyFiles /SILENT").length === 2 &&
      branch.split("              ExecWait '$R1' $0").length === 2 &&
      branch.split('Delete "$R2"').length === 2,
    "previous-uninstaller execution must have one private copy, one synchronous wait, and one exact cleanup",
  );
  assert(
    branch.split("$PLUGINSDIR\\ai-security-scanner-previous-uninstaller.exe").length === 2,
    "previous-uninstaller copy path is not one fixed child of the private NSIS plugin directory",
  );
  assert(
    !branch.includes("ExecWait '$R3'") &&
      !branch.includes('ExecWait \'"$4\\uninstall.exe"') &&
      branch.indexOf("StrCpy $R1 '$\\\"$R2$\\\"'") < branch.indexOf("ExecWait '$R1' $0"),
    "previous-uninstaller execution can still launch the registered in-place executable",
  );
}

function validateProductRepairPatch(vendored) {
  const detector = extractFunction(vendored, "DetectVersionNeutralProductRepair").source;
  assertOrdered(
    detector,
    [
      "StrCpy $RegistrationOverlayMode 0",
      'ReadRegStr $R2 HKCU "${UNINSTKEY}" "DisplayName"',
      'ReadRegStr $R3 HKCU "${UNINSTKEY}" "Publisher"',
      'ReadRegStr $R4 HKCU "${UNINSTKEY}" "DisplayVersion"',
      'ReadRegStr $R5 HKCU "${UNINSTKEY}" "InstallLocation"',
      'ReadRegStr $R6 HKCU "${UNINSTKEY}" "UninstallString"',
      'ReadRegStr $R7 HKCU "${UNINSTKEY}" "MainBinaryName"',
      'StrCpy $R8 \'$\\"$INSTDIR$\\"\'',
      'StrCpy $R9 \'$\\"$INSTDIR\\uninstall.exe$\\"\'',
      '${If} $R2 == "${PRODUCTNAME}"',
      '${AndIf} $R3 == "${MANUFACTURER}"',
      "${AndIf} $R5 == $R8",
      "${AndIf} $R6 == $R9",
      '${AndIf} $R7 == "${MAINBINARYNAME}.exe"',
      '${If} ${FileExists} "$INSTDIR\\${MAINBINARYNAME}.exe"',
      '${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"',
      'nsis_tauri_utils::SemverCompare "${VERSION}" $R4',
      "Pop $R1",
      "StrCpy $R0 $R1",
      "${If} $R1 = 0",
      "StrCpy $RegistrationOverlayMode 2",
      "${ElseIf} $R1 = 1",
      "StrCpy $RegistrationOverlayMode 3",
      "${Else}",
      "StrCpy $RegistrationOverlayMode 1",
    ],
    "version-neutral product repair detector",
  );
  assert(
    detector.split("ReadRegStr").length === 7,
    "product repair detector reads an unexpected registry field",
  );
  assert(
    !/^\s*(?:Delete|DeleteReg|RMDir|Exec|ExecWait|nsExec|WriteReg|EnumRegKey)\b/mu.test(detector),
    "product repair detection mutates state or executes an old command",
  );
  assert(!detector.includes("--unregister"), "product repair detection claims WSL state");
  assert(
    !/!if\s+"\$\{VERSION\}"\s+==\s+"\d|\$R4\s+==\s+"\d+\.\d+\.\d+"/u.test(detector),
    "product repair detector contains a predecessor-specific branch",
  );

  const page = extractFunction(vendored, "PageReinstall").source;
  assertOrdered(
    page,
    [
      "${If} $RegistrationOverlayMode <> 0",
      "Abort",
      "${EndIf}",
      "Call FindWixInstall",
    ],
    "maintenance-page repair bypass",
  );
  const onInit = extractFunction(vendored, ".onInit").source;
  assert(
    onInit.split("Call DetectVersionNeutralProductRepair").length === 2,
    "product repair detector is not one unconditional .onInit call",
  );
  assertOrdered(
    onInit,
    [
      "Call RestorePreviousInstallLocation",
      "Call DetectVersionNeutralProductRepair",
    ],
    "installer initialization",
  );
  assert(
    vendored.split("!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirectoryIfRepairOrPassive").length ===
      2,
    "repair-aware directory page hook is missing or duplicated",
  );
  const directoryGuard = extractFunction(
    vendored,
    "SkipDirectoryIfRepairOrPassive",
  ).source;
  assertOrdered(
    directoryGuard,
    [
      "${If} $RegistrationOverlayMode <> 0",
      "${OrIf} $PassiveMode = 1",
      "Abort",
      "${EndIf}",
    ],
    "repair install-directory lock",
  );
  const installSectionStart = vendored.indexOf("Section Install\n");
  const installSectionEnd = vendored.indexOf("SectionEnd\n", installSectionStart);
  assert(installSectionStart !== -1 && installSectionEnd > installSectionStart, "Install section is missing");
  const installSection = vendored.slice(installSectionStart, installSectionEnd);
  assert(
    installSection.includes('File "${MAINBINARYSRCPATH}"') &&
      installSection.includes('WriteUninstaller "$INSTDIR\\uninstall.exe"') &&
      installSection.includes('WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"'),
    "repair no longer replaces product binaries and registration",
  );
  for (const forbidden of [
    'RmDir /r "$APPDATA',
    'RmDir /r "$LOCALAPPDATA',
    "managed-runtime",
    "wsl",
    "--unregister",
  ]) {
    assert(!installSection.toLowerCase().includes(forbidden.toLowerCase()), `Install section touches excluded data: ${forbidden}`);
  }
}

function expectRepairMutationRejected(vendored, functionName, before, after, label) {
  const scope = extractFunction(vendored, functionName);
  const source = scope.source;
  const first = source.indexOf(before);
  assert(first !== -1, `mutation fixture is missing: ${label}`);
  assert(source.indexOf(before, first + before.length) === -1, `mutation fixture is ambiguous: ${label}`);
  const mutatedFunction = `${source.slice(0, first)}${after}${source.slice(first + before.length)}`;
  const mutated = `${vendored.slice(0, scope.start)}${mutatedFunction}${vendored.slice(scope.end)}`;
  let rejected = false;
  try {
    validateProductRepairPatch(mutated);
  } catch {
    rejected = true;
  }
  assert(rejected, `NSIS repair validator accepted mutation: ${label}`);
}

function validateMutationGuards(vendored) {
  for (const [before, after, label] of [
    [
      'nsExec::ExecToStack /TIMEOUT=180000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json windows-installer-runtime-cache\'',
      'nsExec::ExecToStack \'"$INSTDIR\\ai-security-scanner-cli.exe" --json windows-installer-runtime-cache\'',
      "runtime-cache seed outer timeout removed",
    ],
    [
      "--json windows-installer-runtime-cache'",
      "--json windows-installer-runtime-cache --data-dir C:\\unreviewed'",
      "runtime-cache seed mutable data directory added",
    ],
    [
      '"result_class":"seeded","exit_code":0,"terminal":"complete"',
      '"result_class":"seeded","exit_code":0,"terminal":"partial"',
      "runtime-cache seed complete-envelope sentinel changed",
    ],
    [
      '"result_class":"unavailable","exit_code":30,"terminal":"complete"',
      '"result_class":"unavailable","exit_code":0,"terminal":"complete"',
      "runtime-cache unavailable exit binding changed",
    ],
    [
      "  ${If} $RegistrationOverlayMode = 0\n    Call SeedManagedRuntimePrivateCache\n  ${EndIf}\n",
      "  ${If} $RegistrationOverlayMode <> 0\n    Call SeedManagedRuntimePrivateCache\n  ${EndIf}\n",
      "runtime-cache seed fresh-install guard inverted",
    ],
    [
      "    Call SeedManagedRuntimePrivateCache\n",
      "",
      "runtime-cache seed installer dispatch removed",
    ],
  ]) {
    const first = vendored.indexOf(before);
    assert(first !== -1, `runtime-cache seed mutation fixture is missing: ${label}`);
    assert(
      vendored.indexOf(before, first + before.length) === -1,
      `runtime-cache seed mutation fixture is ambiguous: ${label}`,
    );
    const mutated = `${vendored.slice(0, first)}${after}${vendored.slice(first + before.length)}`;
    let cacheSeedRejected = false;
    try {
      validateManagedRuntimeCacheSeedPatch(mutated);
    } catch {
      cacheSeedRejected = true;
    }
    assert(
      cacheSeedRejected,
      `NSIS runtime-cache seed validator accepted mutation: ${label}`,
    );
  }

  for (const [before, after, label] of [
    [
      'nsExec::ExecToStack /TIMEOUT=360000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json windows-installer-prerequisite\'',
      'nsExec::ExecToStack \'"$INSTDIR\\ai-security-scanner-cli.exe" --json windows-installer-prerequisite\'',
      "Windows prerequisite outer timeout removed",
    ],
    [
      '"WindowsPrerequisiteReceiptResult" "checking"',
      '"WindowsPrerequisiteReceiptResult" "ready"',
      "Windows prerequisite in-progress state removed",
    ],
    [
      '"result_class":"ready","exit_code":0,"restart_required":false,"terminal":"complete"',
      '"result_class":"ready","exit_code":0,"restart_required":false,"terminal":"partial"',
      "Windows prerequisite complete-envelope sentinel changed",
    ],
    [
      '"result_class":"restart_required","exit_code":10,"restart_required":true',
      '"result_class":"restart_required","exit_code":0,"restart_required":true',
      "Windows prerequisite restart exit binding changed",
    ],
    [
      "SetRebootFlag true",
      "",
      "Windows prerequisite restart flag removed",
    ],
    [
      "SetErrorLevel 3010",
      "",
      "Windows prerequisite restart process exit removed",
    ],
    [
      "SetErrorLevel 3010",
      "SetErrorLevel 0",
      "Windows prerequisite restart process exit changed",
    ],
    [
      'WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "retry"',
      'Abort',
      "Windows prerequisite graceful degradation replaced by install abort",
    ],
    [
      "Call RunWindowsInstallerPrerequisiteCoordinator",
      "",
      "Windows prerequisite installer dispatch removed",
    ],
  ]) {
    const first = vendored.indexOf(before);
    assert(first !== -1, `Windows prerequisite mutation fixture is missing: ${label}`);
    assert(
      vendored.indexOf(before, first + before.length) === -1,
      `Windows prerequisite mutation fixture is ambiguous: ${label}`,
    );
    const mutated = `${vendored.slice(0, first)}${after}${vendored.slice(first + before.length)}`;
    let prerequisiteRejected = false;
    try {
      validateWindowsPrerequisitePatch(mutated);
    } catch {
      prerequisiteRejected = true;
    }
    assert(
      prerequisiteRejected,
      `NSIS Windows prerequisite validator accepted mutation: ${label}`,
    );
  }

  for (const [functionName, before, after, label] of [
    ["DetectVersionNeutralProductRepair", '    ${AndIf} $R3 == "${MANUFACTURER}"\n', "", "publisher binding removed"],
    ["DetectVersionNeutralProductRepair", "    ${AndIf} $R6 == $R9\n", "", "uninstall path binding removed"],
    ["DetectVersionNeutralProductRepair", '      ${AndIf} ${FileExists} "$INSTDIR\\uninstall.exe"\n', "", "uninstaller state removed"],
    ["DetectVersionNeutralProductRepair", "          StrCpy $RegistrationOverlayMode 2\n", "          StrCpy $RegistrationOverlayMode 0\n", "same-version repair disabled"],
    ["DetectVersionNeutralProductRepair", "          StrCpy $RegistrationOverlayMode 3\n", "          StrCpy $RegistrationOverlayMode 0\n", "upgrade overlay disabled"],
    [
      "PageReinstall",
      "  ${If} $RegistrationOverlayMode <> 0\n    Abort\n  ${EndIf}\n",
      "",
      "old-uninstaller bypass removed",
    ],
    [
      "SkipDirectoryIfRepairOrPassive",
      "  ${If} $RegistrationOverlayMode <> 0\n",
      "  ${If} $RegistrationOverlayMode = 0\n",
      "repair install-directory lock disabled",
    ],
  ]) {
    expectRepairMutationRejected(vendored, functionName, before, after, label);
  }
  const detector = extractFunction(vendored, "DetectVersionNeutralProductRepair");
  const injected = `${vendored.slice(0, detector.end - "FunctionEnd\n".length)}  ExecWait '$R6' $0\nFunctionEnd\n${vendored.slice(detector.end)}`;
  let rejected = false;
  try {
    validateProductRepairPatch(injected);
  } catch {
    rejected = true;
  }
  assert(rejected, "NSIS repair validator accepted execution of the old uninstaller");

  for (const [before, after, label] of [
    [
      "      ${ElseIf} $R1 != $R3\n",
      "      ${ElseIf} $R1 == $R3\n",
      "registered uninstall command consistency check inverted",
    ],
    [
      '          StrCpy $R2 "$PLUGINSDIR\\ai-security-scanner-previous-uninstaller.exe"\n',
      '          StrCpy $R2 "$4\\uninstall.exe"\n',
      "private previous-uninstaller copy replaced with in-place execution",
    ],
    [
      "              StrCpy $R1 '$\\\"$R2$\\\"'\n",
      "              StrCpy $R1 $R3\n",
      "copied previous-uninstaller command replaced with registered command",
    ],
    [
      '              StrCpy $R1 "$R1 _?=$4" ; _?= must be the final argument\n',
      '              StrCpy $R1 "$R1"\n',
      "synchronous previous-uninstaller mode removed",
    ],
    [
      '          Delete "$R2"\n',
      "",
      "private previous-uninstaller copy cleanup removed",
    ],
  ]) {
    const scope = extractFunction(vendored, "PageLeaveReinstall");
    const first = scope.source.indexOf(before);
    assert(first !== -1, `previous-uninstaller mutation fixture is missing: ${label}`);
    assert(
      scope.source.indexOf(before, first + before.length) === -1,
      `previous-uninstaller mutation fixture is ambiguous: ${label}`,
    );
    const mutatedFunction = `${scope.source.slice(0, first)}${after}${scope.source.slice(first + before.length)}`;
    const mutated = `${vendored.slice(0, scope.start)}${mutatedFunction}${vendored.slice(scope.end)}`;
    let previousUninstallerRejected = false;
    try {
      validateSynchronousPreviousUninstallerPatch(mutated);
    } catch {
      previousUninstallerRejected = true;
    }
    assert(
      previousUninstallerRejected,
      `NSIS previous-uninstaller validator accepted mutation: ${label}`,
    );
  }

  for (const [before, after, label] of [
    [
      '  StrCpy $UninstallChoice "app-only"\nFunctionEnd\n\nFunction un.RunProductUninstallCoordinator',
      '  StrCpy $UninstallChoice "all-data"\nFunctionEnd\n\nFunction un.RunProductUninstallCoordinator',
      "headless default changed from app-only",
    ],
    [
      '--mode all-data --non-interactive --confirmation "REMOVE ALL AI-SECURITY-SCANNER DATA"',
      "--mode all-data --non-interactive",
      "all-data confirmation token removed",
    ],
    [
      "--mode scan-tools --non-interactive --coordinator-envelope'",
      "--mode scan-tools --non-interactive --data-dir $LOCALAPPDATA --coordinator-envelope'",
      "user-data path added to coordinator",
    ],
    [
      'nsExec::ExecToStack /TIMEOUT=600000 \'"$INSTDIR\\ai-security-scanner-cli.exe" --json product-uninstall --mode app-only --non-interactive --coordinator-envelope\'',
      'nsExec::ExecToStack \'"$INSTDIR\\ai-security-scanner-cli.exe" --json product-uninstall --mode app-only --non-interactive --coordinator-envelope\'',
      "outer uninstall coordinator timeout removed",
    ],
    [
      '  ${UnStrLoc} $1 $UninstallCoordinatorOutput \'"terminal":"complete"}\' ">"\n',
      "",
      "complete coordinator-envelope sentinel removed",
    ],
    [
      "  Pop $UninstallCoordinatorOutput\n",
      "",
      "captured coordinator output discarded",
    ],
    [
      "  GetTempFileName $UninstallReceiptPath $TEMP\n",
      '  StrCpy $UninstallReceiptPath "$LOCALAPPDATA\\uninstall.json"\n',
      "unique Windows-temp receipt replaced with a fixed data path",
    ],
    [
      '    StrCpy $UninstallCoordinatorResult "retained-warning"\n',
      '    StrCpy $UninstallCoordinatorResult "fatal"\n',
      "retained cleanup warning changed into a global block",
    ],
    [
      '  ${If} $UninstallCoordinatorResult == "contact-not-stopped"\n',
      '  ${If} $UninstallCoordinatorResult == "retained-warning"\n',
      "cleanup warning changed into a binary-deletion block",
    ],
    [
      "  ; Product data and disposable runtime cleanup is coordinator-owned. NSIS\n",
      '  RmDir /r "$LOCALAPPDATA\\${BUNDLEID}"\n  ; Product data and disposable runtime cleanup is coordinator-owned. NSIS\n',
      "broad application-data recursion restored",
    ],
    [
      '  ${If} $UpdateMode <> 1\n    ${If} $UninstallChoice == "all-data"\n',
      '  ${If} $UpdateMode = 1\n    ${If} $UninstallChoice == "all-data"\n',
      "updater registration preservation inverted",
    ],
    [
      '      DeleteRegValue HKCU "${MANUPRODUCTKEY}" ""\n',
      '      DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"\n',
      "app-only deletes installer language instead of install path",
    ],
    [
      '      DeleteRegKey HKCU "${MANUPRODUCTKEY}"\n',
      '      DeleteRegKey HKCU "${MANUKEY}"\n',
      "all-data broadens exact product registration deletion",
    ],
    [
      '  EnumRegValue $0 HKCU "${UNINSTKEY}" 0\n',
      "",
      "uninstall registration value postcondition removed",
    ],
    [
      '    EnumRegKey $0 HKCU "${MANUPRODUCTKEY}" 0\n',
      "",
      "all-data product registration subkey postcondition removed",
    ],
    [
      '  ${If} ${FileExists} "$INSTDIR\\uninstall.exe"\n',
      "",
      "uninstaller binary postcondition removed",
    ],
    [
      "    SetErrorLevel 10\n",
      "",
      "partial uninstall no longer returns nonzero",
    ],
    [
      'LangString unPostconditionPartial ${LANG_TRADCHINESE} "Windows 無法移除所有應用程式檔案或登錄資料。無法確認的內容都保持原狀。請重新啟動 Windows，然後再次解除安裝。"\n',
      "",
      "Traditional Chinese partial-outcome message removed",
    ],
    [
      "若要先匯出備份，請選擇「否」返回。",
      "請選擇「否」返回。",
      "Traditional Chinese all-data backup wording removed",
    ],
  ]) {
    const first = vendored.indexOf(before);
    assert(first !== -1, `uninstall mutation fixture is missing: ${label}`);
    assert(
      vendored.indexOf(before, first + before.length) === -1,
      `uninstall mutation fixture is ambiguous: ${label}`,
    );
    const mutated = `${vendored.slice(0, first)}${after}${vendored.slice(first + before.length)}`;
    let uninstallRejected = false;
    try {
      validateProductUninstallPatch(mutated);
    } catch {
      uninstallRejected = true;
    }
    assert(uninstallRejected, `NSIS uninstall validator accepted mutation: ${label}`);
  }
}

export async function validateWindowsNsisTemplate() {
  const [
    provenance,
    tauri,
    packageLock,
    vendored,
    noticeGenerator,
    cargoManifest,
    buildScript,
    buildSidecar,
    ciWorkflow,
    releaseWorkflow,
  ] = await Promise.all([
    readJson(PROVENANCE_PATH),
    readJson(path.join(PROJECT_ROOT, "src-tauri/tauri.conf.json")),
    readJson(path.join(PROJECT_ROOT, "package-lock.json")),
    readFile(TEMPLATE_PATH, "utf8"),
    readFile(path.join(PROJECT_ROOT, "scripts/release/generate-notices.mjs"), "utf8"),
    readFile(path.join(PROJECT_ROOT, "src-tauri/Cargo.toml"), "utf8"),
    readFile(path.join(PROJECT_ROOT, "src-tauri/build.rs"), "utf8"),
    readFile(path.join(PROJECT_ROOT, "scripts/release/build-sidecar.mjs"), "utf8"),
    readFile(path.join(PROJECT_ROOT, ".github/workflows/ci.yml"), "utf8"),
    readFile(path.join(PROJECT_ROOT, ".github/workflows/release.yml"), "utf8"),
  ]);
  exactKeys(provenance, Object.keys(PINNED_UPSTREAM), "NSIS template provenance");
  assert(
    JSON.stringify(provenance) === JSON.stringify(PINNED_UPSTREAM),
    "NSIS template provenance differs from the reviewed immutable pin",
  );
  assert(
    tauri.bundle?.windows?.nsis?.template === TEMPLATE_RELATIVE,
    "Tauri is not configured to build the reviewed custom NSIS template",
  );
  assert(
    tauri.bundle?.windows?.nsis?.installMode === "currentUser",
    "version-neutral NSIS repair requires the explicit current-user install mode",
  );
  assert(
    JSON.stringify(tauri.bundle?.windows?.nsis?.languages) ===
      JSON.stringify(["English", "TradChinese"]),
    "NSIS must build exactly the reachable English and Traditional Chinese language paths",
  );
  assert(
    tauri.bundle?.windows?.nsis?.displayLanguageSelector === true,
    "NSIS must expose the configured English and Traditional Chinese language selector",
  );
  assert(
    tauri.bundle?.externalBin?.includes("binaries/ai-security-scanner-cli") === true,
    "the fixed NSIS installer coordinator CLI is not packaged as an installed Windows sidecar",
  );
  assert(
    packageLock.packages?.["node_modules/@tauri-apps/cli"]?.version === "2.12.4",
    "reviewed NSIS template is not paired with the pinned Tauri CLI 2.12.4",
  );
  assert(sha256(vendored) === provenance.vendoredSha256, "vendored NSIS template digest changed");
  for (const noticeMarker of [
    "VENDORED PACKAGING SOURCE",
    "Tauri CLI NSIS installer template | tauri-cli-v2.12.4 | Apache-2.0 OR MIT",
    provenance.upstreamCommit,
    provenance.upstreamSha256,
  ]) {
    assert(
      noticeGenerator.includes(noticeMarker),
      `release third-party notice does not cover the vendored NSIS template: ${noticeMarker}`,
    );
  }
  validateModeledDecisionTable();
  validateInstallerRuntimeCacheBuildWiring({
    cargoManifest,
    buildScript,
    buildSidecar,
    ciWorkflow,
    releaseWorkflow,
  });
  validateManagedRuntimeCacheSeedPatch(vendored);
  validateWindowsPrerequisitePatch(vendored);
  validateSynchronousPreviousUninstallerPatch(vendored);
  validateProductRepairPatch(vendored);
  validateProductUninstallPatch(vendored);
  validateMutationGuards(vendored);
  const reconstructed = reconstructPinnedUpstream(vendored);
  assert(
    sha256(reconstructed) === provenance.upstreamSha256,
    "reversing the reviewed patch does not reconstruct the pinned upstream template",
  );
  process.stdout.write(
    `Source-validated exact private runtime-cache seeding, fixed Windows prerequisite preparation, version-neutral NSIS repair, bilingual bounded uninstall, and exact postconditions against ${provenance.upstreamTag} (${provenance.upstreamCommit}); this is not Windows installer qualification\n`,
  );
}

runMain(validateWindowsNsisTemplate);
