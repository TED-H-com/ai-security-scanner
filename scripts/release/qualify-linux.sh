#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: qualify-linux.sh ARTIFACT_DIRECTORY WORK_DIRECTORY\n' >&2
  exit 2
fi

artifact_directory="$(realpath -- "$1")"
work_directory="$(realpath -m -- "$2")"
case "${work_directory}" in
  "${RUNNER_TEMP}"/*) ;;
  *) printf 'Qualification work directory must be below RUNNER_TEMP.\n' >&2; exit 1 ;;
esac
mkdir -p -- "${work_directory}"
data_directory="${RUNNER_TEMP}/ai-security-scanner-platform-qualification-linux-data"
case "${data_directory}" in
  "${RUNNER_TEMP}"/ai-security-scanner-platform-qualification-*) ;;
  *) printf 'Refusing an unexpected qualification data directory.\n' >&2; exit 1 ;;
esac

package_name=""
cleanup_on_exit() {
  status=$?
  set +e
  if [[ -n "${package_name}" ]] && dpkg-query -W -f='${db:Status-Abbrev}' "${package_name}" 2>/dev/null | grep -q '^ii'; then
    sudo apt-get purge -y "${package_name}" >/dev/null
  fi
  if [[ -d "${data_directory}" ]]; then
    rm -rf -- "${data_directory}"
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

installer_manifest="${artifact_directory}/installers-linux-x86_64.json"
installer_name="$(node -e '
  const fs = require("fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const matches = manifest.installers.filter((item) => item.bundleType === "deb");
  if (matches.length !== 1 || require("path").basename(matches[0].file) !== matches[0].file) process.exit(1);
  process.stdout.write(matches[0].file);
' "${installer_manifest}")"
installer_path="$(realpath -- "${artifact_directory}/${installer_name}")"
[[ "$(dirname -- "${installer_path}")" == "${artifact_directory}" && -f "${installer_path}" ]]
package_name="$(dpkg-deb -f "${installer_path}" Package)"
[[ "${package_name}" == "ai-security-scanner" ]]

sudo apt-get update
sudo apt-get install -y --no-install-recommends xvfb "${installer_path}"

desktop="$(command -v ai-security-scanner)"
egress="$(command -v ai-security-scanner-egress-gateway)"
broker="$(command -v ai-security-scanner-bootstrap-broker)"
cli="$(command -v ai-security-scanner-cli)"
for installed_executable in "${desktop}" "${egress}" "${broker}" "${cli}"; do
  [[ "${installed_executable}" == /* && -f "${installed_executable}" && -x "${installed_executable}" ]]
  dpkg-query -S "${installed_executable}" | grep -Fq "${package_name}:"
done

mapfile -t runtime_manifests < <(dpkg -L "${package_name}" | grep -E '/managed-runtime/manifest\.json$')
[[ "${#runtime_manifests[@]}" -eq 1 ]]
runtime_manifest="$(realpath -- "${runtime_manifests[0]}")"
[[ -f "${runtime_manifest}" ]]
cp -- "${runtime_manifest}" "${work_directory}/installed-runtime-manifest.json"
runtime_root="$(dirname -- "${runtime_manifest}")"
manifest_sha256="$(sha256sum -- "${runtime_manifest}" | cut -d ' ' -f 1)"
[[ "${manifest_sha256}" =~ ^[0-9a-f]{64}$ ]]
provider_release_home="${data_directory}/managed-runtime/provider-home/${manifest_sha256:0:16}"

# Exercise the installed, manifest-bound image utility by its absolute path.
# This cannot fall back to a qemu-img that happens to be installed on the host.
node -e '
  const crypto = require("crypto");
  const fs = require("fs");
  const path = require("path");
  const { execFileSync } = require("child_process");
  const [manifestPath, runtimeRoot, workRoot] = process.argv.slice(1);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const records = manifest.files.filter((item) => item.path === "bin/qemu-img");
  if (records.length !== 1) throw new Error("Installed managed runtime has no exact bundled qemu-img file.");
  const record = records[0];
  if (record.executable !== true || !Number.isSafeInteger(record.size_bytes) || record.size_bytes <= 0 ||
      !/^[0-9a-f]{64}$/.test(record.sha256)) {
    throw new Error("Installed qemu-img manifest record is malformed.");
  }
  const components = manifest.components.filter((item) => item.id === "qemu");
  if (components.length !== 1 || typeof components[0].version !== "string" ||
      !/^[A-Za-z0-9._-]{1,64}$/.test(components[0].version)) {
    throw new Error("Installed runtime has no exact QEMU component identity.");
  }
  const artifacts = components[0].artifacts.filter((item) => item.delivery === "bundled_file" &&
    item.locator === record.path && item.sha256 === record.sha256 && item.size_bytes === record.size_bytes);
  if (artifacts.length !== 1) throw new Error("QEMU component does not bind the installed qemu-img file.");
  const binary = path.join(runtimeRoot, "bin", "qemu-img");
  const metadata = fs.lstatSync(binary);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== record.size_bytes ||
      (metadata.mode & 0o111) === 0 || fs.realpathSync(binary) !== binary) {
    throw new Error("Installed qemu-img is not the exact executable regular file.");
  }
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex");
  if (digest !== record.sha256) throw new Error("Installed qemu-img differs from its runtime manifest.");
  const runBinary = (executable, args) => execFileSync(executable, args, {
    cwd: workRoot,
    encoding: "utf8",
    env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", PATH: "/usr/bin:/bin" },
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  const run = (args) => runBinary(binary, args);
  const version = run(["--version"]);
  if (!version.includes(`qemu-img version ${components[0].version}`)) {
    throw new Error("Installed qemu-img version differs from the exact QEMU component.");
  }
  const emulatorRecords = manifest.files.filter((item) => item.path === "bin/qemu-system-x86_64.real");
  if (emulatorRecords.length !== 1) {
    throw new Error("Installed managed runtime has no exact bundled QEMU system emulator.");
  }
  const emulatorRecord = emulatorRecords[0];
  const emulatorArtifacts = components[0].artifacts.filter((item) =>
    item.delivery === "bundled_file" && item.locator === emulatorRecord.path &&
    item.sha256 === emulatorRecord.sha256 && item.size_bytes === emulatorRecord.size_bytes);
  if (emulatorRecord.executable !== true || emulatorArtifacts.length !== 1) {
    throw new Error("QEMU component does not bind the installed system emulator.");
  }
  const emulator = path.join(runtimeRoot, "bin", "qemu-system-x86_64.real");
  const emulatorMetadata = fs.lstatSync(emulator);
  const emulatorDigest = crypto.createHash("sha256").update(fs.readFileSync(emulator)).digest("hex");
  if (!emulatorMetadata.isFile() || emulatorMetadata.isSymbolicLink() ||
      emulatorMetadata.size !== emulatorRecord.size_bytes || (emulatorMetadata.mode & 0o111) === 0 ||
      fs.realpathSync(emulator) !== emulator || emulatorDigest !== emulatorRecord.sha256) {
    throw new Error("Installed QEMU system emulator is not the exact manifest-bound executable.");
  }
  const deviceNames = new Set(
    [...runBinary(emulator, ["-device", "help"]).matchAll(/name "([^"]+)"/gu)]
      .map((match) => match[1]),
  );
  if (!deviceNames.has("vhost-user-fs-pci")) {
    throw new Error("Installed QEMU system emulator omits the vhost-user-fs-pci device required by Podman.");
  }
  const probeRoot = fs.mkdtempSync(path.join(workRoot, "qemu-img-probe-"));
  const probe = path.join(probeRoot, "qualification.qcow2");
  try {
    run(["create", "-f", "qcow2", probe, "1G"]);
    run(["resize", probe, "40G"]);
    const information = JSON.parse(run(["info", "--output=json", probe]));
    if (information.format !== "qcow2" || information["virtual-size"] !== 40 * 1024 * 1024 * 1024) {
      throw new Error("Installed qemu-img failed the exact qcow2 create, resize, and inspect contract.");
    }
  } finally {
    fs.rmSync(probeRoot, { recursive: true, force: true });
  }

  const helperRecords = manifest.files.filter((item) => item.path === "bin/virtiofsd");
  if (helperRecords.length !== 1) {
    throw new Error("Installed managed runtime has no exact bundled virtiofsd file.");
  }
  const helperRecord = helperRecords[0];
  const helperComponents = manifest.components.filter((item) => item.id === "virtiofsd");
  if (helperComponents.length !== 1 || helperComponents[0].version !== "1.14.0") {
    throw new Error("Installed runtime has no exact virtiofsd component identity.");
  }
  const helperArtifacts = helperComponents[0].artifacts.filter((item) =>
    item.delivery === "bundled_file" && item.locator === helperRecord.path &&
    item.sha256 === helperRecord.sha256 && item.size_bytes === helperRecord.size_bytes);
  if (helperArtifacts.length !== 1) {
    throw new Error("virtiofsd component does not bind the installed helper file.");
  }
  const helper = path.join(runtimeRoot, "bin", "virtiofsd");
  const helperMetadata = fs.lstatSync(helper);
  const helperBytes = fs.readFileSync(helper);
  const helperDigest = crypto.createHash("sha256").update(helperBytes).digest("hex");
  if (!helperMetadata.isFile() || helperMetadata.isSymbolicLink() ||
      helperMetadata.size !== helperRecord.size_bytes || (helperMetadata.mode & 0o111) === 0 ||
      fs.realpathSync(helper) !== helper || helperDigest !== helperRecord.sha256 ||
      helperBytes.length < 64 || helperBytes.subarray(0, 4).toString("hex") !== "7f454c46" ||
      helperBytes[4] !== 2 || helperBytes[5] !== 1 || helperBytes.readUInt16LE(18) !== 62) {
    throw new Error("Installed virtiofsd is not the exact ELF64 x86-64 executable.");
  }
  const programOffset = Number(helperBytes.readBigUInt64LE(32));
  const programEntrySize = helperBytes.readUInt16LE(54);
  const programCount = helperBytes.readUInt16LE(56);
  if (!Number.isSafeInteger(programOffset) || programEntrySize < 56 ||
      programOffset + programEntrySize * programCount > helperBytes.length) {
    throw new Error("Installed virtiofsd has a malformed ELF program-header table.");
  }
  for (let index = 0; index < programCount; index += 1) {
    if (helperBytes.readUInt32LE(programOffset + index * programEntrySize) === 3) {
      throw new Error("Installed virtiofsd unexpectedly requires a host ELF interpreter.");
    }
  }
  if (!runBinary(helper, ["--version"]).includes("virtiofsd 1.14.0")) {
    throw new Error("Installed virtiofsd version differs from its exact component.");
  }
' "${runtime_manifest}" "${runtime_root}" "${work_directory}"

"${cli}" --help >/dev/null
set +e
timeout --signal=TERM 12s xvfb-run --auto-servernum "${desktop}" >"${work_directory}/desktop-startup.log" 2>&1
desktop_status=$?
set -e
if [[ "${desktop_status}" -ne 124 ]]; then
  cat "${work_directory}/desktop-startup.log" >&2
  printf 'Installed Linux desktop exited before the 12-second observation window (status %s).\n' "${desktop_status}" >&2
  exit 1
fi

mkdir -m 700 -- "${data_directory}"
short_runtime="$(node -e '
  const crypto = require("crypto");
  const fs = require("fs");
  const path = require("path");
  const state = Buffer.from(path.join(fs.realpathSync(process.argv[1]), "managed-runtime"));
  const manifest = crypto.createHash("sha256").update(fs.readFileSync(process.argv[2])).digest("hex");
  const u32 = Buffer.alloc(4);
  u32.writeUInt32BE(process.geteuid());
  const u64 = (value) => {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64BE(BigInt(value));
    return buffer;
  };
  const namespace = crypto.createHash("sha256")
    .update(Buffer.from("ai-security-scanner-linux-xdg-runtime-v1\0"))
    .update(u32)
    .update(u64(state.length))
    .update(state)
    .update(u64(Buffer.byteLength(manifest)))
    .update(Buffer.from(manifest))
    .digest("hex")
    .slice(0, 32);
  process.stdout.write(`/tmp/assm1-${namespace}`);
' "${data_directory}" "${runtime_manifest}")"
if [[ -e "${short_runtime}" || -L "${short_runtime}" ]]; then
  printf 'Linux qualification did not begin with a fresh exact short XDG runtime directory.\n' >&2
  exit 1
fi
run_managed() {
  output_name="$1"
  shift
  "${cli}" --json --data-dir "${data_directory}" runtime managed "$@" >"${work_directory}/${output_name}.json"
  node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "${work_directory}/${output_name}.json"
}

assert_managed_ssh_identity() {
  node -e '
    const fs = require("fs");
    const [privateKey, publicKey, privateStaging, publicStaging] = process.argv.slice(1);
    const absent = (entry) => {
      try { fs.lstatSync(entry); return false; }
      catch (error) { if (error.code === "ENOENT") return true; throw error; }
    };
    const verify = (entry, maximum, modes, label) => {
      const metadata = fs.lstatSync(entry);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
          metadata.uid !== process.geteuid() || metadata.size <= 0 || metadata.size > maximum ||
          !modes.includes(metadata.mode & 0o777)) {
        throw new Error(`${label} is not an exact current-user single-link private file.`);
      }
      return fs.readFileSync(entry, "utf8");
    };
    const privateText = verify(privateKey, 16 * 1024, [0o400, 0o600], "Managed SSH private key");
    const publicText = verify(publicKey, 4 * 1024, [0o400, 0o444, 0o600, 0o644], "Managed SSH public key");
    if (!privateText.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n") ||
        !privateText.trimEnd().endsWith("-----END OPENSSH PRIVATE KEY-----")) {
      throw new Error("Managed SSH private key is not an OpenSSH private key.");
    }
    if (!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2} ai-security-scanner-managed-runtime\n?$/.test(publicText)) {
      throw new Error("Managed SSH public key does not have the exact Ed25519 identity format.");
    }
    if (!absent(privateStaging) || !absent(publicStaging)) {
      throw new Error("Managed SSH identity staging entries remain after start.");
    }
  ' \
    "${provider_release_home}/data/containers/podman/machine/machine" \
    "${provider_release_home}/data/containers/podman/machine/machine.pub" \
    "${provider_release_home}/data/containers/podman/machine/.machine.private-key-new" \
    "${provider_release_home}/data/containers/podman/machine/.machine.public-key-new"
}

run_managed initial-status status
if [[ -e "${short_runtime}" || -L "${short_runtime}" ]]; then
  printf 'Initial managed status created the Linux short XDG runtime directory before installation.\n' >&2
  exit 1
fi
run_managed install install
if [[ -e "${short_runtime}" || -L "${short_runtime}" ]]; then
  printf 'Managed payload installation created the Linux short XDG runtime directory before a Podman command.\n' >&2
  exit 1
fi
run_managed installed-status status
[[ -d "${short_runtime}" && ! -L "${short_runtime}" ]]
[[ "$(stat -c '%u' "${short_runtime}")" == "$(id -u)" ]]
[[ "$(stat -c '%a' "${short_runtime}")" == "700" ]]
podman_runtime="${short_runtime}/podman"
[[ -d "${podman_runtime}" && ! -L "${podman_runtime}" ]]
[[ "$(stat -c '%u' "${podman_runtime}")" == "$(id -u)" ]]
podman_runtime_mode="$(stat -c '%a' "${podman_runtime}")"
podman_runtime_mode_value=$((8#${podman_runtime_mode}))
if (( (podman_runtime_mode_value & 0700) != 0700 ||
      (podman_runtime_mode_value & ~0755) != 0 )); then
  printf 'Managed runtime Linux Podman runtime directory has unsafe permissions.\n' >&2
  exit 1
fi
longest_gvproxy_socket="${podman_runtime}/$(printf '%030d' 0)-gvproxy.sock"
longest_gvproxy_socket_bytes="$(node -e 'process.stdout.write(String(Buffer.byteLength(process.argv[1])))' "${longest_gvproxy_socket}")"
if (( longest_gvproxy_socket_bytes > 103 )); then
  printf 'Managed runtime Linux gvproxy socket exceeds the Podman Unix-socket path budget.\n' >&2
  exit 1
fi
run_managed start start
assert_managed_ssh_identity
run_managed running-status status
run_managed egress-qualification qualify-egress
run_managed container-qualification qualify
run_managed stop stop
[[ -d "${short_runtime}" && ! -L "${short_runtime}" ]]
virtiofs_pid="${podman_runtime}/virtiofschar0.pid"
if [[ ! -f "${virtiofs_pid}" || -L "${virtiofs_pid}" ]]; then
  printf 'Pinned Podman stop did not leave the expected real virtiofsd pid evidence.\n' >&2
  exit 1
fi
[[ "$(stat -c '%u' "${virtiofs_pid}")" == "$(id -u)" ]]
[[ "$(stat -c '%h' "${virtiofs_pid}")" == "1" ]]
[[ "$(stat -c '%a' "${virtiofs_pid}")" == "600" ]]
if ! flock -n "${virtiofs_pid}" true; then
  printf 'Pinned Podman stop left the exact virtiofsd pid lock live.\n' >&2
  exit 1
fi
virtiofs_socket="${podman_runtime}/virtiofschar0"
if [[ -e "${virtiofs_socket}" || -L "${virtiofs_socket}" ]]; then
  if [[ ! -S "${virtiofs_socket}" || -L "${virtiofs_socket}" ]]; then
    printf 'Pinned Podman stop left an unsafe virtiofsd socket entry.\n' >&2
    exit 1
  fi
  [[ "$(stat -c '%u' "${virtiofs_socket}")" == "$(id -u)" ]]
  [[ "$(stat -c '%h' "${virtiofs_socket}")" == "1" ]]
  [[ "$(stat -c '%a' "${virtiofs_socket}")" == "700" ]]
fi
run_managed stopped-status status
run_managed uninstall-purge uninstall --force --purge-image-cache
if [[ -e "${provider_release_home}" || -L "${provider_release_home}" ]]; then
  printf 'Managed runtime uninstall left its exact release provider home behind.\n' >&2
  exit 1
fi
if [[ -e "${short_runtime}" || -L "${short_runtime}" ]]; then
  printf 'Managed runtime uninstall left its exact Linux short XDG runtime directory behind.\n' >&2
  exit 1
fi
run_managed final-status status

for private_root in "${data_directory}/managed-runtime/versions" "${data_directory}/managed-runtime/machine-images" "${data_directory}/managed-runtime/provider-home"; do
  if [[ -d "${private_root}" ]] && find "${private_root}" -mindepth 1 -print -quit | grep -q .; then
    printf 'Managed runtime cleanup left private entries below %s.\n' "${private_root}" >&2
    exit 1
  fi
done

sudo apt-get purge -y "${package_name}"
package_name=""
for removed_path in "${desktop}" "${egress}" "${broker}" "${cli}" "${runtime_manifest}"; do
  [[ ! -e "${removed_path}" ]]
done
rm -rf -- "${data_directory}"
[[ ! -e "${data_directory}" ]]

export QUAL_DESKTOP="${desktop}"
export QUAL_EGRESS="${egress}"
export QUAL_BROKER="${broker}"
export QUAL_CLI="${cli}"
export QUAL_RUNTIME_MANIFEST="${runtime_manifest}"
export QUAL_DATA_DIRECTORY="${data_directory}"
export QUAL_WORK_DIRECTORY="${work_directory}"
node --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
const read = (name) => JSON.parse(readFileSync(path.join(process.env.QUAL_WORK_DIRECTORY, `${name}.json`), "utf8"));
const passed = (name, file) => ({ name, outcome: "passed", status: read(file) });
const observations = {
  installedLayout: {
    pathsVerifiedAbsolute: true,
    desktop: process.env.QUAL_DESKTOP,
    cli: process.env.QUAL_CLI,
    companions: [
      { name: "ai-security-scanner-egress-gateway", path: process.env.QUAL_EGRESS },
      { name: "ai-security-scanner-bootstrap-broker", path: process.env.QUAL_BROKER },
      { name: "ai-security-scanner-cli", path: process.env.QUAL_CLI },
    ],
    runtimeManifestOriginalPath: process.env.QUAL_RUNTIME_MANIFEST,
  },
  desktopStartup: { outcome: "passed", observationSeconds: 12, installedExecutable: process.env.QUAL_DESKTOP },
  privateDataDirectory: process.env.QUAL_DATA_DIRECTORY,
  operations: [
    passed("initial_status", "initial-status"),
    passed("install", "install"),
    passed("installed_status", "installed-status"),
    passed("start", "start"),
    passed("running_status", "running-status"),
    passed("stop", "stop"),
    passed("stopped_status", "stopped-status"),
    passed("uninstall_purge", "uninstall-purge"),
    passed("final_status", "final-status"),
  ],
  egressGateway: { outcome: "passed", result: read("egress-qualification") },
  containerExecution: { outcome: "passed", result: read("container-qualification") },
  cleanup: { managedRuntimePurged: true, machineImageCachePurged: true, installerRemoved: true, privateDataRemoved: true },
  installedManifestSnapshot: "installed-runtime-manifest.json",
};
writeFileSync(path.join(process.env.QUAL_WORK_DIRECTORY, "observations.json"), `${JSON.stringify(observations, null, 2)}\n`, { flag: "wx" });
NODE
