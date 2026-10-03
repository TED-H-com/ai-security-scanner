// ai-security-scanner-local-launcher is the non-shell capability boundary for
// managed, offline source, dependency, and Kubernetes snapshot scanners. It
// accepts only the scanner-owned mount contract and never forwards user input
// as command-line arguments.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	workspaceMountPath  = "/workspace"
	outputMountPath     = "/output"
	maxEvidenceBytes    = 512 * 1024 * 1024
	maxImmutableBytes   = 2 * 1024 * 1024 * 1024
	maxLogBytes         = 8 * 1024 * 1024
	maxSnapshotBytes    = 8 * 1024 * 1024
	maxSnapshotFiles    = 32
	linuxStatfsReadOnly = 1
	inputMarkerFilename = ".ai-security-scanner-input.json"
	inputMarkerSchema   = "ai-security-scanner.local-input/v1"
	profileRepository   = "repository_working_tree"
	profileIaC          = "iac_working_tree"
	profileOCIImage     = "container_image_oci_layout"
	profileKubernetes   = "kubernetes_manifests"
	profileNodeSnapshot = "kubernetes_node_snapshot"
	nodeSnapshotRoot    = "/workspace/node-snapshot"
	nodeSnapshotSchema  = "2.0.0"
	nodeSnapshotProfile = "cis-kubernetes-node-facts"
	nodeSnapshotBench   = "cis-1.11"
)

type invocation struct {
	program        string
	arguments      []string
	environment    []string
	outputPath     string
	stdoutIsOutput bool
	timeout        time.Duration
}

type nodeSnapshot struct {
	SchemaVersion string                `json:"schema_version"`
	Profile       string                `json:"profile"`
	Benchmark     string                `json:"benchmark"`
	CapturedAt    time.Time             `json:"captured_at"`
	Files         []nodeSnapshotFile    `json:"files"`
	Processes     []nodeSnapshotProcess `json:"processes"`
}

type nodeSnapshotFile struct {
	Path       string `json:"path"`
	SourcePath string `json:"source_path"`
	SHA256     string `json:"sha256"`
	Mode       string `json:"mode"`
	Owner      string `json:"owner"`
	Group      string `json:"group"`
}

type nodeSnapshotProcess struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

type localInputMarker struct {
	SchemaVersion string `json:"schema_version"`
	InputProfile  string `json:"input_profile"`
}

type boundedWriter struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		writer.overflow = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		writer.overflow = true
	}
	_, _ = writer.buffer.Write(value)
	return original, nil
}

func main() {
	name := filepath.Base(os.Args[0])
	var err error
	switch name {
	case "ps":
		err = runSnapshotPS(nodeSnapshotRoot, os.Args[1:], os.Stdout)
	case "stat":
		err = runSnapshotStat(nodeSnapshotRoot, os.Args[1:], os.Stdout)
	default:
		err = run(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-local-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engineID := flags.String("engine", "", "fixed engine identifier")
	workspace := flags.String("workspace", "", "read-only assessment snapshot")
	output := flags.String("output", "", "runtime-owned evidence directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if !supportedEngine(*engineID) {
		return errors.New("engine identifier is not allowlisted")
	}
	if *workspace != workspaceMountPath || *output != outputMountPath {
		return errors.New("workspace and output paths must use the runtime-owned mounts")
	}
	if err := validateDirectory(*workspace, "workspace"); err != nil {
		return err
	}
	if err := requireReadOnlyWorkspace(*workspace); err != nil {
		return err
	}
	if err := validateDirectory(*output, "output"); err != nil {
		return err
	}
	inputProfile, err := loadInputProfile(*workspace)
	if err != nil {
		return err
	}
	if err := validateEngineInputProfile(*engineID, inputProfile); err != nil {
		return err
	}
	if err := verifyEngineInputs(*engineID, inputProfile, *workspace); err != nil {
		return err
	}

	planned, err := planInvocations(*engineID, inputProfile)
	if err != nil {
		return err
	}
	for _, item := range planned {
		if err := ensureOutputAbsent(item.outputPath); err != nil {
			return err
		}
	}
	for _, item := range planned {
		if err := execute(item); err != nil {
			removePlannedOutputs(planned)
			return err
		}
		if err := validateEvidence(item.outputPath, *engineID == "trufflehog"); err != nil {
			removePlannedOutputs(planned)
			return err
		}
		if err := os.Chmod(item.outputPath, 0o600); err != nil {
			removePlannedOutputs(planned)
			return err
		}
	}
	return nil
}

func removePlannedOutputs(planned []invocation) {
	for _, item := range planned {
		_ = os.Remove(item.outputPath)
	}
}

func supportedEngine(engineID string) bool {
	switch engineID {
	case "semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench":
		return true
	default:
		return false
	}
}

func validateDirectory(path string, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s directory: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s path must be a real directory", label)
	}
	return nil
}

func requireReadOnlyWorkspace(path string) error {
	if runtime.GOOS == "linux" {
		var filesystem syscall.Statfs_t
		if err := syscall.Statfs(path, &filesystem); err != nil {
			return fmt.Errorf("inspect workspace mount flags: %w", err)
		}
		if filesystem.Flags&linuxStatfsReadOnly == 0 {
			return errors.New("workspace mount is writable; refusing to scan")
		}
		return nil
	}

	// The packaged engines target Linux. Keep the write probe as a fail-closed
	// fallback for development builds on other Unix-like systems.
	probe := filepath.Join(path, fmt.Sprintf(".ai-security-scanner-write-probe-%d", os.Getpid()))
	file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			return nil
		}
		return fmt.Errorf("verify read-only workspace: %w", err)
	}
	_ = file.Close()
	_ = os.Remove(probe)
	return errors.New("workspace mount is writable; refusing to scan")
}

func ensureOutputAbsent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect evidence path: %w", err)
	}
	return fmt.Errorf("evidence path already exists (%s, mode %s)", path, info.Mode())
}

func loadInputProfile(workspace string) (string, error) {
	markerPath := filepath.Join(workspace, inputMarkerFilename)
	info, err := os.Lstat(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return profileRepository, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect local input marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > 4*1024 {
		return "", errors.New("local input marker is not a bounded regular file")
	}
	payload, err := os.ReadFile(markerPath)
	if err != nil {
		return "", fmt.Errorf("read local input marker: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var marker localInputMarker
	if err := decoder.Decode(&marker); err != nil {
		return "", fmt.Errorf("parse local input marker: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return "", fmt.Errorf("parse local input marker: %w", err)
	}
	if marker.SchemaVersion != inputMarkerSchema {
		return "", errors.New("local input marker schema is invalid")
	}
	switch marker.InputProfile {
	case profileIaC, profileOCIImage, profileKubernetes, profileNodeSnapshot:
		return marker.InputProfile, nil
	default:
		return "", errors.New("local input marker profile is invalid")
	}
}

func validateEngineInputProfile(engineID string, inputProfile string) error {
	allowed := map[string]map[string]bool{
		"semgrep":    {profileRepository: true},
		"trufflehog": {profileRepository: true},
		"trivy":      {profileRepository: true, profileIaC: true, profileOCIImage: true},
		"grype":      {profileRepository: true, profileOCIImage: true},
		"kubescape":  {profileKubernetes: true},
		"kube-bench": {profileNodeSnapshot: true},
	}
	if !allowed[engineID][inputProfile] {
		return fmt.Errorf("engine %s cannot consume local input profile %s", engineID, inputProfile)
	}
	return nil
}

func planInvocation(engineID string, inputProfile string) (invocation, error) {
	fixedEnvironment := []string{
		"HOME=/tmp/ai-security-scanner-home",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"NO_COLOR=1",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME=/tmp/ai-security-scanner-cache",
		"XDG_CONFIG_HOME=/tmp/ai-security-scanner-config",
	}
	result := invocation{environment: fixedEnvironment, timeout: time.Hour}
	switch engineID {
	case "semgrep":
		result.program = "/usr/local/bin/semgrep"
		result.outputPath = "/output/semgrep.json"
		result.arguments = []string{
			"scan", "--json", "--output", result.outputPath,
			"--config", semgrepRulePackPath,
			"--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids",
			"--oss-only", "--jobs", "2", "--max-memory", "2048",
			"--timeout", "10", "--timeout-threshold", "3",
			"--max-target-bytes", "10000000", "/workspace",
		}
		result.environment = append(result.environment,
			"SEMGREP_ENABLE_VERSION_CHECK=0", "SEMGREP_SEND_METRICS=off")
	case "trufflehog":
		result.program = "/usr/local/bin/trufflehog"
		result.outputPath = "/output/trufflehog.jsonl"
		result.stdoutIsOutput = true
		result.arguments = []string{
			"filesystem", "/workspace", "--json", "--no-verification",
			"--no-verification-cache", "--no-update", "--concurrency", "4",
		}
	case "trivy":
		result.program = "/usr/local/bin/trivy"
		result.outputPath = "/output/trivy.json"
		if inputProfile == profileOCIImage {
			result.arguments = []string{
				"image", "--input", "/workspace",
				"--cache-dir", "/opt/ai-security-scanner/trivy-cache",
				"--cache-backend", "memory",
				"--skip-db-update", "--skip-java-db-update", "--offline-scan",
				"--pkg-types", "os", "--skip-version-check", "--disable-telemetry",
				"--skip-vex-repo-update", "--scanners", "vuln",
				"--format", "json", "--output", result.outputPath,
			}
		} else {
			result.arguments = []string{
				"filesystem", "--cache-dir", "/opt/ai-security-scanner/trivy-cache",
				"--cache-backend", "memory",
				"--skip-db-update", "--skip-java-db-update", "--offline-scan",
				"--pkg-types", "library", "--skip-version-check", "--disable-telemetry",
				"--skip-vex-repo-update", "--scanners", "vuln",
				"--format", "json", "--output", result.outputPath, "/workspace",
			}
		}
		result.environment = append(result.environment, "TRIVY_DISABLE_VEX_NOTICE=true")
	case "grype":
		result.program = "/usr/local/bin/grype"
		result.outputPath = "/output/grype.json"
		source := "dir:/workspace"
		if inputProfile == profileOCIImage {
			source = "oci-dir:/workspace"
		}
		result.arguments = []string{source, "--output", "json", "--file", result.outputPath}
		result.environment = append(result.environment,
			"GRYPE_CHECK_FOR_APP_UPDATE=false",
			"GRYPE_DB_AUTO_UPDATE=false",
			"GRYPE_DB_CACHE_DIR=/opt/ai-security-scanner/grype-db",
			"GRYPE_DB_REQUIRE_UPDATE_CHECK=false",
			"GRYPE_DB_VALIDATE_AGE=false",
			"GRYPE_DB_VALIDATE_BY_HASH_ON_START=false",
		)
	case "kubescape":
		result.program = "/usr/local/bin/kubescape"
		result.outputPath = "/output/kubescape.json"
		result.arguments = []string{
			"scan", "framework", "nsa", "/workspace",
			"--use-from", "/opt/ai-security-scanner/kubescape-artifacts/nsa.json",
			"--controls-config", "/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json",
			"--exceptions", "/opt/ai-security-scanner/kubescape-artifacts/exceptions.json",
			"--keep-local", "--submit=false", "--host-scan=false",
			"--omit-raw-resources", "--format", "json", "--format-version", "v2",
			"--scan-timeout", "45m", "--control-timeout", "2m", "--output", result.outputPath,
		}
		result.environment = append(result.environment,
			"KS_SUBMIT=false", "OTEL_SDK_DISABLED=true")
	case "kube-bench":
		result.program = "/usr/local/bin/kube-bench"
		result.outputPath = "/output/kube-bench.json"
		result.arguments = []string{
			"run", "--benchmark", nodeSnapshotBench, "--targets", "node",
			"--config-dir", "/opt/ai-security-scanner/kube-bench/cfg",
			"--config", "/opt/ai-security-scanner/kube-bench/cfg/config.yaml",
			"--json", "--outputfile", result.outputPath,
			"--exit-code", "0",
		}
	default:
		return invocation{}, errors.New("engine identifier is not allowlisted")
	}
	return result, nil
}

func planInvocations(engineID string, inputProfile string) ([]invocation, error) {
	primary, err := planInvocation(engineID, inputProfile)
	if err != nil {
		return nil, err
	}
	planned := []invocation{primary}
	if engineID != "trivy" || (inputProfile != profileRepository && inputProfile != profileIaC) {
		return planned, nil
	}

	// Trivy deliberately disables individual-package analyzers such as JARs in
	// filesystem mode, while rootfs deliberately disables lockfile analyzers.
	// Run both upstream-native, non-overlapping profiles for working trees so
	// neither detector family is silently lost or recreated in this wrapper.
	individualPackages := invocation{
		program:     "/usr/local/bin/trivy",
		environment: append([]string(nil), primary.environment...),
		outputPath:  "/output/trivy-individual-packages.json",
		timeout:     time.Hour,
		arguments: []string{
			"rootfs", "--cache-dir", "/opt/ai-security-scanner/trivy-cache",
			"--cache-backend", "memory",
			"--skip-db-update", "--skip-java-db-update", "--offline-scan",
			"--pkg-types", "library", "--skip-version-check", "--disable-telemetry",
			"--skip-vex-repo-update", "--scanners", "vuln",
			"--format", "json", "--output", "/output/trivy-individual-packages.json", "/workspace",
		},
	}
	return append(planned, individualPackages), nil
}

func verifyEngineInputs(engineID string, inputProfile string, workspace string) error {
	switch engineID {
	case "semgrep":
		if err := verifySemgrepRulePack(
			semgrepRulePackPath,
			semgrepRuleManifestPath,
			semgrepRuleManifestSHA256,
			semgrepRuleFileCount,
		); err != nil {
			return err
		}
		return verifyFile(semgrepRuleProvenancePath, semgrepRuleProvenanceSHA256, 2*1024*1024)
	case "trivy":
		if err := verifyFile("/opt/ai-security-scanner/trivy-cache/db/trivy.db", trivyDBSHA256, maxImmutableBytes); err != nil {
			return err
		}
		if err := verifyFile("/opt/ai-security-scanner/trivy-cache/db/metadata.json", trivyMetadataSHA256, 64*1024); err != nil {
			return err
		}
		if inputProfile == profileOCIImage {
			return nil
		}
		if err := verifyFile("/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db", trivyJavaDBSHA256, maxImmutableBytes); err != nil {
			return err
		}
		return verifyFile("/opt/ai-security-scanner/trivy-cache/java-db/metadata.json", trivyJavaMetadataSHA256, 64*1024)
	case "grype":
		return verifyFile("/opt/ai-security-scanner/grype-db/6/vulnerability.db", grypeDBSHA256, maxImmutableBytes)
	case "kubescape":
		for path, digest := range map[string]string{
			"/opt/ai-security-scanner/kubescape-artifacts/nsa.json":             kubescapeNSASHA256,
			"/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json": kubescapeControlsSHA256,
			"/opt/ai-security-scanner/kubescape-artifacts/exceptions.json":      kubescapeExceptionsSHA256,
		} {
			if err := verifyFile(path, digest, 4*1024*1024); err != nil {
				return err
			}
		}
	case "kube-bench":
		return validateNodeSnapshot(filepath.Join(workspace, "node-snapshot"))
	}
	return nil
}

func verifySemgrepRulePack(root string, manifestPath string, expectedManifest string, expectedCount int) error {
	if err := validateDirectory(root, "Semgrep rule pack"); err != nil {
		return err
	}
	if expectedCount < 1 || expectedCount > 10000 {
		return errors.New("Semgrep rule-pack file count is outside its bound")
	}
	if err := verifyFile(manifestPath, expectedManifest, 256*1024); err != nil {
		return err
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read Semgrep rule-pack manifest: %w", err)
	}
	seen := make(map[string]bool, expectedCount)
	previous := ""
	scanner := bufio.NewScanner(bytes.NewReader(manifest))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 68 || line[64:66] != "  " {
			return errors.New("Semgrep rule-pack manifest contains an invalid record")
		}
		digest, relative := line[:64], line[66:]
		if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
			return errors.New("Semgrep rule-pack manifest contains an invalid digest")
		}
		invalidPath := relative == "" || strings.Contains(relative, "\\") || filepath.IsAbs(relative) ||
			filepath.ToSlash(filepath.Clean(relative)) != relative || strings.HasPrefix(relative, "../") ||
			(!strings.HasSuffix(relative, ".yaml") && !strings.HasSuffix(relative, ".yml")) ||
			seen[relative] || (previous != "" && relative <= previous)
		if invalidPath {
			return errors.New("Semgrep rule-pack manifest contains an invalid path")
		}
		seen[relative] = true
		previous = relative
		if err := verifyFile(filepath.Join(root, filepath.FromSlash(relative)), digest, 1024*1024); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Semgrep rule-pack manifest: %w", err)
	}
	if len(seen) != expectedCount {
		return fmt.Errorf("Semgrep rule-pack manifest contains %d files; expected %d", len(seen), expectedCount)
	}
	actualCount := 0
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("Semgrep rule pack contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("Semgrep rule pack contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !seen[filepath.ToSlash(relative)] {
			return errors.New("Semgrep rule pack contains a file outside its immutable manifest")
		}
		actualCount++
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate Semgrep rule pack: %w", err)
	}
	if actualCount != expectedCount {
		return errors.New("Semgrep rule pack does not match its immutable manifest")
	}
	return nil
}

func verifyFile(path string, expected string, maxBytes int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("required immutable input %s is unavailable: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes {
		return fmt.Errorf("required immutable input %s is not a bounded regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open immutable input %s: %w", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, maxBytes+1)); err != nil {
		return fmt.Errorf("hash immutable input %s: %w", path, err)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != expected {
		return fmt.Errorf("immutable input %s does not match its release digest", path)
	}
	return nil
}

func validateNodeSnapshot(root string) error {
	profile, err := loadNodeSnapshot(root)
	if err != nil {
		return err
	}
	for _, file := range profile.Files {
		if err := verifyFile(filepath.Join(root, file.Path), strings.TrimPrefix(file.SHA256, "sha256:"), maxSnapshotBytes); err != nil {
			return err
		}
	}
	return nil
}

func loadNodeSnapshot(root string) (nodeSnapshot, error) {
	if err := validateDirectory(root, "node snapshot"); err != nil {
		return nodeSnapshot{}, err
	}
	manifestPath := filepath.Join(root, "profile.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() < 2 || manifestInfo.Size() > 256*1024 {
		return nodeSnapshot{}, errors.New("node snapshot requires a bounded regular profile.json")
	}
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		return nodeSnapshot{}, fmt.Errorf("read node snapshot profile: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var profile nodeSnapshot
	if err := decoder.Decode(&profile); err != nil {
		return nodeSnapshot{}, fmt.Errorf("parse node snapshot profile: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nodeSnapshot{}, fmt.Errorf("parse node snapshot profile: %w", err)
	}
	if profile.SchemaVersion != nodeSnapshotSchema || profile.Profile != nodeSnapshotProfile ||
		profile.Benchmark != nodeSnapshotBench || profile.CapturedAt.IsZero() {
		return nodeSnapshot{}, errors.New("node snapshot profile identity is invalid")
	}
	allowedFiles := map[string]bool{
		"kubelet-config.yaml": true,
		"kubelet.service":     true,
		"kubelet.conf":        true,
		"kube-proxy.yaml":     true,
		"ca.crt":              true,
	}
	if len(profile.Files) != len(allowedFiles) || len(profile.Files) > maxSnapshotFiles {
		return nodeSnapshot{}, errors.New("node snapshot must contain the complete bounded file fact set")
	}
	seenFiles := map[string]bool{}
	for _, file := range profile.Files {
		if !allowedFiles[file.Path] || seenFiles[file.Path] || !validSHA256(file.SHA256) ||
			!validSnapshotSourcePath(file.SourcePath) || !validSnapshotMode(file.Mode) ||
			!validSnapshotIdentity(file.Owner) || !validSnapshotIdentity(file.Group) {
			return nodeSnapshot{}, fmt.Errorf("node snapshot file inventory contains an invalid entry %q", file.Path)
		}
		seenFiles[file.Path] = true
	}
	allowedProcesses := map[string]bool{"kubelet": true, "kube-proxy": true}
	if len(profile.Processes) != len(allowedProcesses) {
		return nodeSnapshot{}, errors.New("node snapshot must contain the complete bounded process fact set")
	}
	seenProcesses := map[string]bool{}
	for _, process := range profile.Processes {
		if !allowedProcesses[process.Name] || seenProcesses[process.Name] ||
			!validSnapshotCommand(process.Name, process.Command) {
			return nodeSnapshot{}, fmt.Errorf("node snapshot process inventory contains an invalid entry %q", process.Name)
		}
		seenProcesses[process.Name] = true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nodeSnapshot{}, fmt.Errorf("enumerate node snapshot: %w", err)
	}
	if len(entries) != len(profile.Files)+1 {
		return nodeSnapshot{}, errors.New("node snapshot contains files outside its immutable inventory")
	}
	return profile, nil
}

func validSnapshotSourcePath(value string) bool {
	return len(value) > 1 && len(value) <= 4096 && strings.HasPrefix(value, "/") &&
		filepath.Clean(value) == value && !strings.Contains(value, "\\") && !containsControl(value)
}

func validSnapshotMode(value string) bool {
	if len(value) != 3 && len(value) != 4 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '7' {
			return false
		}
	}
	return true
}

func validSnapshotIdentity(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func validSnapshotCommand(name string, value string) bool {
	return len(value) >= len(name) && len(value) <= 8192 && strings.TrimSpace(value) == value &&
		strings.Contains(value, name) && !containsControl(value)
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func runSnapshotStat(root string, arguments []string, output io.Writer) error {
	if len(arguments) != 3 || arguments[0] != "-c" ||
		(arguments[1] != "permissions=%a" && arguments[1] != "%U:%G") {
		return errors.New("arguments do not match the bounded node snapshot stat contract")
	}
	profile, err := loadNodeSnapshot(root)
	if err != nil {
		return err
	}
	for _, file := range profile.Files {
		if arguments[2] != filepath.Join(root, file.Path) {
			continue
		}
		if arguments[1] == "permissions=%a" {
			_, err = fmt.Fprintf(output, "permissions=%s\n", file.Mode)
		} else {
			_, err = fmt.Fprintf(output, "%s:%s\n", file.Owner, file.Group)
		}
		return err
	}
	return errors.New("stat target is outside the bounded node snapshot inventory")
}

func runSnapshotPS(root string, arguments []string, output io.Writer) error {
	profile, err := loadNodeSnapshot(root)
	if err != nil {
		return err
	}
	processes := make(map[string]string, len(profile.Processes))
	for _, process := range profile.Processes {
		processes[process.Name] = rewriteSnapshotPaths(root, profile.Files, process.Command)
	}
	if len(arguments) == 1 && arguments[0] == "-ef" {
		for _, name := range []string{"kubelet", "kube-proxy"} {
			if _, err := fmt.Fprintln(output, processes[name]); err != nil {
				return err
			}
		}
		return nil
	}
	if len(arguments) == 2 && arguments[0] == "-fC" {
		command, ok := processes[arguments[1]]
		if !ok {
			return errors.New("process name is outside the bounded node snapshot inventory")
		}
		_, err = fmt.Fprintln(output, command)
		return err
	}
	if len(arguments) == 5 && arguments[0] == "-C" && arguments[2] == "-o" &&
		arguments[3] == "cmd" && arguments[4] == "--no-headers" {
		command, ok := processes[arguments[1]]
		if !ok {
			return errors.New("process name is outside the bounded node snapshot inventory")
		}
		_, err = fmt.Fprintln(output, command)
		return err
	}
	return errors.New("arguments do not match the bounded node snapshot ps contract")
}

func rewriteSnapshotPaths(root string, files []nodeSnapshotFile, command string) string {
	sorted := append([]nodeSnapshotFile(nil), files...)
	sort.Slice(sorted, func(left int, right int) bool {
		return len(sorted[left].SourcePath) > len(sorted[right].SourcePath)
	})
	for _, file := range sorted {
		command = strings.ReplaceAll(command, file.SourcePath, filepath.Join(root, file.Path))
	}
	return command
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func execute(planned invocation) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, planned.timeout)
	defer cancel()
	command := exec.CommandContext(ctx, planned.program, planned.arguments...)
	command.Env = append([]string(nil), planned.environment...)
	command.Dir = workspaceMountPath
	if runtime.GOOS != "windows" {
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		command.Cancel = func() error {
			if command.Process == nil {
				return nil
			}
			return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
	}
	command.WaitDelay = 5 * time.Second
	logs := &boundedWriter{limit: maxLogBytes}
	command.Stderr = logs
	if planned.stdoutIsOutput {
		output, err := os.OpenFile(planned.outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create evidence file: %w", err)
		}
		command.Stdout = output
		err = command.Run()
		closeErr := output.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return commandError(ctx, err, logs)
		}
	} else {
		command.Stdout = logs
		if err := command.Run(); err != nil {
			return commandError(ctx, err, logs)
		}
	}
	if logs.overflow {
		return errors.New("engine diagnostic output exceeded its bounded capture")
	}
	return nil
}

func commandError(ctx context.Context, err error, logs *boundedWriter) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("engine exceeded its fixed runtime timeout")
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.New("engine execution was cancelled")
	}
	message := strings.TrimSpace(logs.buffer.String())
	if len(message) > 2048 {
		message = message[len(message)-2048:]
	}
	if message == "" {
		return fmt.Errorf("engine failed: %w", err)
	}
	return fmt.Errorf("engine failed: %w (%s)", err, message)
}

func validateEvidence(path string, jsonLines bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect evidence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxEvidenceBytes {
		return errors.New("engine evidence is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence: %w", err)
	}
	defer file.Close()
	if jsonLines {
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			var value map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &value); err != nil || value == nil {
				return errors.New("engine evidence contains an invalid JSON object line")
			}
		}
		return scanner.Err()
	}
	if info.Size() < 2 {
		return errors.New("engine JSON evidence is empty")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxEvidenceBytes+1))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("parse engine JSON evidence: %w", err)
	}
	if value == nil {
		return errors.New("engine JSON evidence is null")
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// These release constants are verified before any scanner starts. They are
// updated together with the corresponding Dockerfile and packaging plan.
const (
	semgrepRulePackPath         = "/opt/ai-security-scanner/semgrep/rules"
	semgrepRuleManifestPath     = "/opt/ai-security-scanner/semgrep/RULES.sha256"
	semgrepRuleManifestSHA256   = "63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040"
	semgrepRuleFileCount        = 1478
	semgrepRuleProvenancePath   = "/opt/ai-security-scanner/semgrep/RULE-PROVENANCE.json"
	semgrepRuleProvenanceSHA256 = "a5f8961abe75a57da4c752f39272baa64ac95ca4181e507c070772c54f5c09bf"
	trivyDBSHA256               = "e58db9fad4ce26f9ad77f4116f7a3b52527eb3a75718484903d930d110dee431"
	trivyMetadataSHA256         = "b253a6f5e90d91bf0e0e4b6f07a6f26cb9169155d0af68309728d9d853ded143"
	trivyJavaDBSHA256           = "7eaa54234967d2dc36f5c60d51c614bdd40997ddadcd13b3815eb8baeb7dc5cb"
	trivyJavaMetadataSHA256     = "856f573fa061b68555b24a06cdd24ab99f9d6a0cd3129a10a620236ffa507d58"
	grypeDBSHA256               = "db6f590412955f6b58cec12bfa4b712b2626eef9a030bffd8f32b9ebce074ff8"
	kubescapeNSASHA256          = "7f7d7bbc6908b9872fd71751dc8d5dd5f543cdd6a684a24d1fb15b686e8344db"
	kubescapeControlsSHA256     = "df4e2431e8f560961ce56aa06e022caf9b2f82f98752de78df1cd0706b42cf3a"
	kubescapeExceptionsSHA256   = "bf44e01e6b212c8e8c0ca0686d1bd84488e3f9ce5375cd36511c8faef3a44e7b"
)

// Keep deterministic ordering available to tests without exposing dynamic
// scanner arguments in production.
func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
