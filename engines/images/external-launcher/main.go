// ai-security-scanner-external-launcher is the non-shell capability boundary
// for the managed Naabu, httpx, and Nuclei images. It translates only the
// immutable per-asset grants written by the desktop application into fixed
// scanner invocations. Every child process is independently bounded by the
// grant that authorized it and can reach the target only through the managed
// SOCKS gateway.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	scopeMountPath               = "/run/ai-security-scanner/scope.json"
	journalPlanMountPath         = "/run/ai-security-scanner/execution-journal-v2.json"
	outputMountPath              = "/output"
	templateRootPath             = "/opt/nuclei-templates"
	templateRevision             = "f938a3dd530c283e9387b518b97911152ff5846c"
	templateRevisionMarker       = "/opt/nuclei-templates/AI_SECURITY_SCANNER_REVISION"
	nucleiWebSafeProfileID       = "nuclei_web_safe_v1"
	nucleiWebSafeTemplateCount   = 4775
	maxScopeBytes                = 4 * 1024 * 1024
	maxEvidenceBytes             = 512 * 1024 * 1024
	maxEvidenceLineBytes         = 16 * 1024 * 1024
	maxTemplateBytes             = 1024 * 1024
	maxTemplateHeaderBytes       = 128 * 1024
	maxAssets                    = 4096
	maxIdentifiers               = 128
	maxGrantsPerAsset            = 16
	maxResolvedAddresses         = 4096
	managedGatewayPort           = "1080"
	naabuProxyRateDivisor        = 2
	scannerProcessAllowance      = 5 * time.Second
	naabuEngineCeiling           = 4 * time.Hour
	httpEngineCeiling            = 2 * time.Hour
	maxNucleiRequestsPerTemplate = 20
	maxNucleiProfileTemplates    = 10_000
	launcherPlanLegacyVersion    = 2
	launcherPlanCurrentVersion   = 3
	launcherJournalSchemaVersion = 2
	maxLauncherLegacyUnits       = 512
	maxLauncherCurrentUnits      = 128
	maxLauncherV2FrozenGrants    = 128
	maxLauncherEndpointPairsUnit = 10_000
	maxLauncherCurrentPairs      = 10_000
	maxLauncherV2JournalBytes    = 4 * 1024 * 1024
	maxLauncherV2RecordBytes     = 1024 * 1024
	maxLauncherV2OpaqueIDBytes   = 128
	maxLauncherV2RelativeBytes   = 512
	maxLauncherV2PlanBytes       = 1024 * 1024
	maxLauncherV2Diagnostics     = 8
	maxLauncherV2DiagnosticBytes = 256
	launcherV2WorkUnitPrefix     = "wu_"
	launcherV2WorkUnitHexChars   = 32
	launcherV2Directory          = "launcher-v2"
	launcherV2JournalName        = "journal.jsonl"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type scopeDocument struct {
	SchemaVersion string       `json:"schema_version"`
	EngineID      string       `json:"engine_id"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Assets        []scopeAsset `json:"assets"`
}

type scopeAsset struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Kind        string       `json:"kind"`
	Provider    *string      `json:"provider"`
	Region      *string      `json:"region"`
	Identifiers []identifier `json:"identifiers"`
	Grants      []scopeGrant `json:"grants"`
}

type identifier struct {
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

type scopeGrant struct {
	ID                     string         `json:"id"`
	Permission             string         `json:"permission"`
	ConfirmedBy            string         `json:"confirmed_by"`
	ConfirmedAt            time.Time      `json:"confirmed_at"`
	ExpiresAt              *time.Time     `json:"expires_at"`
	AuthorizationReference *string        `json:"authorization_reference"`
	ExternalScope          *externalScope `json:"external_scope"`
	ResolvedAddresses      []string       `json:"resolved_addresses"`
}

type externalScope struct {
	ID                     string          `json:"id"`
	CaseID                 string          `json:"case_id"`
	AssetID                string          `json:"asset_id"`
	Target                 canonicalTarget `json:"target"`
	Ports                  []uint16        `json:"ports"`
	Protocol               string          `json:"protocol"`
	Activity               string          `json:"activity"`
	RatePolicy             ratePolicy      `json:"rate_policy"`
	TemplatePolicy         templatePolicy  `json:"template_policy"`
	AssertedAuthority      string          `json:"asserted_authority"`
	ApprovedBy             string          `json:"approved_by"`
	ApprovedAt             time.Time       `json:"approved_at"`
	ExpiresAt              time.Time       `json:"expires_at"`
	AllowSensitiveNetworks bool            `json:"allow_sensitive_networks"`
}

type canonicalTarget struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type ratePolicy struct {
	RequestsPerSecond uint16 `json:"requests_per_second"`
	Concurrency       uint16 `json:"concurrency"`
	TimeoutSeconds    uint32 `json:"timeout_seconds"`
}

type templatePolicy struct {
	Revision               string   `json:"revision"`
	AllowedTemplateIDs     []string `json:"allowed_template_ids"`
	ProfileID              *string  `json:"profile_id,omitempty"`
	AllowHeadless          bool     `json:"allow_headless"`
	AllowOutOfBand         bool     `json:"allow_out_of_band"`
	AllowFuzzing           bool     `json:"allow_fuzzing"`
	AllowFileUpload        bool     `json:"allow_file_upload"`
	AllowDenialOfService   bool     `json:"allow_denial_of_service"`
	AllowCredentialAttacks bool     `json:"allow_credential_attacks"`
}

type scanUnit struct {
	AssetID           string
	Grant             externalScope
	Port              uint16
	ResolvedAddresses []string
}

type invocation struct {
	Program    string
	Args       []string
	Env        []string
	StdoutPath string
	Expiry     time.Time
	Timeout    time.Duration
}

type launcherV2Options struct {
	PlanPath string
}

type launcherV2RequestedUnit struct {
	UnitID      string `json:"unit_id"`
	ScopeSHA256 string `json:"scope_sha256"`
}

type launcherV2Header struct {
	RecordType         string                    `json:"record_type"`
	SchemaVersion      int                       `json:"schema_version"`
	EngineRunID        string                    `json:"engine_run_id"`
	ExecutionAttempt   uint32                    `json:"execution_attempt"`
	RequestedWorkUnits []launcherV2RequestedUnit `json:"requested_work_units"`
}

type launcherV2FrozenGrant struct {
	ScopeGrantID string   `json:"scope_grant_id"`
	Addresses    []string `json:"addresses"`
	Ports        []uint16 `json:"ports"`
}

type launcherV2PlannedUnit struct {
	UnitID                      string `json:"unit_id"`
	ScopeSHA256                 string `json:"scope_sha256"`
	GrantIndex                  uint32 `json:"grant_index"`
	AddressStart                uint32 `json:"address_start"`
	AddressLen                  uint32 `json:"address_len"`
	PortStart                   uint32 `json:"port_start"`
	PortLen                     uint32 `json:"port_len"`
	EndpointPairCount           uint64 `json:"endpoint_pair_count"`
	ConservativeDeadlineSeconds uint64 `json:"conservative_deadline_seconds"`
}

type launcherV2Plan struct {
	SchemaVersion      int                     `json:"schema_version"`
	EngineID           string                  `json:"engine_id"`
	EngineRunID        string                  `json:"engine_run_id"`
	ExecutionAttempt   uint32                  `json:"execution_attempt"`
	FrozenGrants       []launcherV2FrozenGrant `json:"frozen_grants"`
	RequestedWorkUnits []launcherV2PlannedUnit `json:"requested_work_units"`
}

type launcherV2FinalArtifact struct {
	EngineRunID  string `json:"engine_run_id"`
	UnitID       string `json:"unit_id"`
	ScopeSHA256  string `json:"scope_sha256"`
	Attempt      uint32 `json:"attempt"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
	ByteLength   uint64 `json:"byte_length"`
}

type launcherV2AttemptFinished struct {
	RecordType       string                   `json:"record_type"`
	UnitID           string                   `json:"unit_id"`
	ScopeSHA256      string                   `json:"scope_sha256"`
	Attempt          uint32                   `json:"attempt"`
	Outcome          string                   `json:"outcome"`
	IncompleteReason string                   `json:"incomplete_reason,omitempty"`
	FinalArtifact    *launcherV2FinalArtifact `json:"final_artifact,omitempty"`
}

type launcherV2Journal struct {
	file             *os.File
	engineRunID      string
	executionAttempt uint32
	requested        map[string]launcherV2RequestedUnit
	terminalWritten  map[string]bool
	written          int64
	recordsWritten   int
	budget           *launcherV2ByteBudget
}

type launcherV2ByteBudget struct {
	journalUsed int64
	payloadUsed int64
}

// launcherV2Diagnostics stays outside the privacy-safe coverage journal. It is
// returned through the launcher's already captured technical stderr so a
// missing binary, scanner stderr, normalization failure, or quarantine failure
// does not collapse into an unactionable count. Entries are ordinal, bounded,
// and best-effort; they never alter terminal coverage truth.
type launcherV2Diagnostics struct {
	entries []string
	omitted int
}

type launcherV2RunOutcome string

const (
	launcherV2RunSucceeded launcherV2RunOutcome = "succeeded"
	launcherV2RunFailed    launcherV2RunOutcome = "failed"
	launcherV2RunTimedOut  launcherV2RunOutcome = "timed_out"
	launcherV2RunCancelled launcherV2RunOutcome = "cancelled"
)

type launcherV2RunResult struct {
	Outcome launcherV2RunOutcome
	Err     error
}

// launcherV2IncompleteRun means the launcher completed its own contract and
// closed a truthful journal, but one or more scanner work units did not finish
// completely. The process must still exit zero so the host can validate and
// persist completed or partial evidence, then continue the remaining work.
// Fatal launcher, journal, or plan failures use ordinary errors and exit 126.
type launcherV2IncompleteRun struct {
	incompleteUnits    int
	quarantineFailures int
	diagnostics        string
}

func (outcome *launcherV2IncompleteRun) Error() string {
	if outcome == nil {
		return "launcher-v2 finished with incomplete work"
	}
	message := fmt.Sprintf(
		"launcher-v2 finished with %d incomplete work unit(s) and %d raw-evidence quarantine failure(s)",
		outcome.incompleteUnits,
		outcome.quarantineFailures,
	)
	if outcome.diagnostics != "" {
		message += "; bounded technical diagnostics: " + outcome.diagnostics
	}
	return message
}

func launcherOutcomeIsProcessSuccess(err error) bool {
	if err == nil {
		return true
	}
	var incomplete *launcherV2IncompleteRun
	return errors.As(err, &incomplete)
}

var errScannerTimedOut = errors.New("scanner exceeded the frozen total timeout")

type boundedBuffer struct {
	bytes.Buffer
	remaining int
}

var errTemplateIDAbsent = errors.New("template has no bounded id header")

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	originalLength := len(value)
	if len(value) > buffer.remaining {
		value = value[:buffer.remaining]
	}
	written, err := buffer.Buffer.Write(value)
	buffer.remaining -= written
	if err != nil {
		return written, err
	}
	return originalLength, nil
}

func main() {
	if err := run(os.Args[1:], time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "external engine launcher: %v\n", err)
		if !launcherOutcomeIsProcessSuccess(err) {
			os.Exit(126)
		}
	}
}

func run(arguments []string, now time.Time) error {
	flags := flag.NewFlagSet("ai-security-scanner-external-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engineID := flags.String("engine", "", "fixed engine identifier")
	scopePath := flags.String("scope", "", "immutable scope document")
	outputPath := flags.String("output", "", "evidence output directory")
	journalVersion := flags.Int("journal-version", 0, "opt-in execution journal schema")
	journalPlanPath := flags.String("journal-plan", "", "host-frozen execution journal plan")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if !supportedEngine(*engineID) {
		return errors.New("engine identifier is not allowlisted")
	}
	if *scopePath != scopeMountPath || *outputPath != outputMountPath {
		return errors.New("scope and output paths must use the runtime-owned mounts")
	}
	journal, err := validateLauncherV2Options(*journalVersion, *journalPlanPath, *engineID)
	if err != nil {
		return err
	}
	if err := validateOutputDirectory(*outputPath); err != nil {
		return err
	}
	proxy, naabuProxy, err := managedProxy(os.Getenv("AI_SECURITY_SCANNER_PROXY"))
	if err != nil {
		return err
	}
	document, err := loadScope(*scopePath, *engineID)
	if err != nil {
		return err
	}
	units, err := validateAndPlan(document, *engineID, now)
	if err != nil {
		return err
	}
	var journalPlan *launcherV2Plan
	if journal != nil {
		journalPlan, err = loadLauncherV2Plan(journal.PlanPath, *engineID, units)
		if err != nil {
			return err
		}
	}

	temporaryRoot, err := os.MkdirTemp("/tmp", "ai-security-scanner-external-")
	if err != nil {
		return fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		return fmt.Errorf("restrict private temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)

	var templates map[string]string
	if *engineID == "nuclei" {
		if err := verifyTemplateRevision(templateRevisionMarker); err != nil {
			return err
		}
		templates, err = loadTemplateIndex(filepath.Join(templateRootPath, "http"))
		if err != nil {
			return err
		}
	}

	environment := childEnvironment(proxy, temporaryRoot)
	nucleiProxy := nucleiCompatibleProxy(proxy)
	if *engineID == "nuclei" {
		// Nuclei v3.11.1 calls the same remote-name SOCKS5 protocol "socks5";
		// its parser rejects the conventional socks5h URL spelling. The endpoint
		// was already reduced above to the runtime-owned literal bridge IP:1080.
		environment = childEnvironment(nucleiProxy, temporaryRoot)
	}
	if journal != nil {
		return runNaabuLauncherV2(
			*outputPath,
			temporaryRoot,
			journalPlan,
			units,
			naabuProxy,
			environment,
			now,
			runCommandForLauncherV2,
		)
	}
	finalPath := filepath.Join(*outputPath, *engineID+".jsonl")
	final, err := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive evidence file: %w", err)
	}
	complete := false
	defer func() {
		_ = final.Close()
		if !complete {
			_ = os.Remove(finalPath)
		}
	}()
	writer := bufio.NewWriterSize(final, 64*1024)
	written := int64(0)
	var nucleiProfileIDs, nucleiProfilePaths []string

	for index, unit := range units {
		if !now.Before(unit.Grant.ExpiresAt) || !time.Now().UTC().Before(unit.Grant.ExpiresAt) {
			return fmt.Errorf("scope grant %s expired before its independent invocation", unit.Grant.ID)
		}
		temporaryOutput := filepath.Join(temporaryRoot, fmt.Sprintf("result-%06d.jsonl", index))
		var command invocation
		switch *engineID {
		case "naabu":
			command, err = naabuInvocation(
				unit, naabuProxy, temporaryOutput, environment, temporaryRoot, index,
			)
		case "httpx":
			command, err = httpxInvocation(unit, proxy, temporaryOutput, environment)
		case "nuclei":
			var templatePaths []string
			var templateIDs []string
			if unit.Grant.TemplatePolicy.ProfileID != nil && len(nucleiProfileIDs) != 0 {
				templateIDs = nucleiProfileIDs
				templatePaths = nucleiProfilePaths
			} else {
				templateIDs, templatePaths, err = resolvedTemplateSelection(unit.Grant.TemplatePolicy, templates)
				if err == nil && unit.Grant.TemplatePolicy.ProfileID != nil {
					nucleiProfileIDs = templateIDs
					nucleiProfilePaths = templatePaths
				}
			}
			if err == nil {
				// Evidence validation remains an exact-ID check even when the host
				// selected a pinned profile. Resolve the profile inside this
				// read-only launcher, then close both Nuclei and the normalizer over
				// the same immutable ID set.
				unit.Grant.TemplatePolicy.AllowedTemplateIDs = templateIDs
				command, err = nucleiInvocation(unit, nucleiProxy, temporaryOutput, environment, temporaryRoot, index, templatePaths)
			}
		}
		if err != nil {
			return err
		}
		if err := runCommand(command); err != nil {
			return fmt.Errorf("%s grant %s invocation failed: %w", *engineID, unit.Grant.ID, err)
		}
		if err := normalizeEvidence(temporaryOutput, writer, &written, *engineID, unit); err != nil {
			return err
		}
		if err := os.Remove(temporaryOutput); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove normalized temporary evidence: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush evidence: %w", err)
	}
	if err := final.Sync(); err != nil {
		return fmt.Errorf("sync evidence: %w", err)
	}
	if err := final.Close(); err != nil {
		return fmt.Errorf("close evidence: %w", err)
	}
	complete = true
	return nil
}

func validateLauncherV2Options(version int, planPath, engineID string) (*launcherV2Options, error) {
	if version == 0 && planPath == "" {
		return nil, nil
	}
	if version != launcherJournalSchemaVersion || planPath != journalPlanMountPath {
		return nil, errors.New("the current launcher requires its exact journal-v2 host-frozen plan mount")
	}
	if engineID != "naabu" {
		return nil, errors.New("launcher-v2 execution evidence is currently available only for Naabu")
	}
	return &launcherV2Options{PlanPath: planPath}, nil
}

func loadLauncherV2Plan(planPath, expectedEngine string, units []scanUnit) (*launcherV2Plan, error) {
	value, err := readBoundedRegularFile(planPath, maxLauncherV2PlanBytes)
	if err != nil {
		return nil, fmt.Errorf("read launcher-v2 host-frozen plan: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var plan launcherV2Plan
	if err := decoder.Decode(&plan); err != nil || requireJSONEOF(decoder) != nil {
		return nil, errors.New("launcher-v2 host-frozen plan is malformed")
	}
	if _, err := materializeLauncherV2Plan(&plan, expectedEngine, units); err != nil {
		return nil, err
	}
	return &plan, nil
}

type launcherV2Rectangle struct {
	grantIndex               uint32
	addressStart, addressEnd uint64
	portStart, portEnd       uint64
}

// materializeLauncherV2Plan closes the strict host-frozen sidecar over the
// independently validated scope document. The host controls both corpus and
// work-unit order; Go compares sets for authorization, then slices in exactly
// the sidecar order instead of trying to reproduce Rust's ordering rules.
func materializeLauncherV2Plan(plan *launcherV2Plan, expectedEngine string, units []scanUnit) ([]scanUnit, error) {
	if plan == nil ||
		(plan.SchemaVersion != launcherPlanLegacyVersion && plan.SchemaVersion != launcherPlanCurrentVersion) ||
		plan.EngineID != expectedEngine || expectedEngine != "naabu" {
		return nil, errors.New("launcher-v2 host-frozen plan version or engine is invalid")
	}
	if !launcherV2OpaqueID(plan.EngineRunID) {
		return nil, errors.New("launcher-v2 engine run identity is not a bounded opaque identifier")
	}
	if plan.ExecutionAttempt == 0 {
		return nil, errors.New("launcher-v2 execution attempt must be non-zero")
	}
	if len(units) < 1 || len(plan.FrozenGrants) < 1 || len(plan.FrozenGrants) > maxLauncherV2FrozenGrants {
		return nil, errors.New("launcher-v2 requires a bounded non-empty frozen-grant corpus")
	}
	maxRequestedUnits, ok := launcherPlanMaxRequestedUnits(plan.SchemaVersion)
	if !ok || len(plan.RequestedWorkUnits) < 1 || len(plan.RequestedWorkUnits) > maxRequestedUnits {
		return nil, errors.New("launcher-v2 requires a bounded non-empty requested work-unit subset")
	}

	validatedByGrant := make(map[string]scanUnit, len(units))
	for _, unit := range units {
		if unit.Grant.ID == "" {
			return nil, errors.New("launcher-v2 validated Naabu scope contains an empty grant identity")
		}
		if _, exists := validatedByGrant[unit.Grant.ID]; exists {
			return nil, errors.New("launcher-v2 validated Naabu scope contains a duplicate grant identity")
		}
		validatedByGrant[unit.Grant.ID] = unit
	}
	if len(plan.FrozenGrants) != len(validatedByGrant) {
		return nil, errors.New("launcher-v2 frozen grants are not set-equal to the validated Naabu scope")
	}

	frozenUnits := make([]scanUnit, len(plan.FrozenGrants))
	seenFrozenGrants := make(map[string]struct{}, len(plan.FrozenGrants))
	for index, frozen := range plan.FrozenGrants {
		if !safeText(frozen.ScopeGrantID, 256) {
			return nil, errors.New("launcher-v2 frozen grant identity is invalid")
		}
		if _, exists := seenFrozenGrants[frozen.ScopeGrantID]; exists {
			return nil, errors.New("launcher-v2 frozen grant identities are not unique")
		}
		seenFrozenGrants[frozen.ScopeGrantID] = struct{}{}
		validated, exists := validatedByGrant[frozen.ScopeGrantID]
		if !exists {
			return nil, errors.New("launcher-v2 frozen grant is outside the validated Naabu scope")
		}
		if err := validateResolvedAddresses(frozen.Addresses, validated.Grant.Target); err != nil {
			return nil, fmt.Errorf("launcher-v2 frozen grant %d address corpus is invalid: %w", index, err)
		}
		if err := validateLauncherV2Ports(frozen.Ports); err != nil {
			return nil, fmt.Errorf("launcher-v2 frozen grant %d port corpus is invalid: %w", index, err)
		}
		if !sameLauncherV2StringSet(frozen.Addresses, validated.ResolvedAddresses) ||
			!sameLauncherV2PortSet(frozen.Ports, validated.Grant.Ports) {
			return nil, errors.New("launcher-v2 frozen grant corpus changed the validated Naabu scope")
		}
		validated.ResolvedAddresses = append([]string(nil), frozen.Addresses...)
		validated.Grant.Ports = append([]uint16(nil), frozen.Ports...)
		frozenUnits[index] = validated
	}

	materialized := make([]scanUnit, 0, len(plan.RequestedWorkUnits))
	rectangles := make([]launcherV2Rectangle, 0, len(plan.RequestedWorkUnits))
	seenUnitIDs := make(map[string]struct{}, len(plan.RequestedWorkUnits))
	seenScopeHashes := make(map[string]struct{}, len(plan.RequestedWorkUnits))
	var aggregateEndpointPairs uint64
	for ordinal, requested := range plan.RequestedWorkUnits {
		if !launcherV2WorkUnitID(requested.UnitID) || !launcherV2SHA256(requested.ScopeSHA256) {
			return nil, errors.New("launcher-v2 requested work-unit identity is invalid")
		}
		if _, exists := seenUnitIDs[requested.UnitID]; exists {
			return nil, errors.New("launcher-v2 requested work-unit identities are not unique")
		}
		if _, exists := seenScopeHashes[requested.ScopeSHA256]; exists {
			return nil, errors.New("launcher-v2 requested work-unit scope hashes are not unique")
		}
		seenUnitIDs[requested.UnitID] = struct{}{}
		seenScopeHashes[requested.ScopeSHA256] = struct{}{}

		grantIndex := uint64(requested.GrantIndex)
		if grantIndex >= uint64(len(frozenUnits)) {
			return nil, fmt.Errorf("launcher-v2 requested work unit %d refers to a missing frozen grant", ordinal)
		}
		frozen := frozenUnits[grantIndex]
		addressStart := uint64(requested.AddressStart)
		addressLen := uint64(requested.AddressLen)
		portStart := uint64(requested.PortStart)
		portLen := uint64(requested.PortLen)
		addressEnd := addressStart + addressLen
		portEnd := portStart + portLen
		if addressLen == 0 || portLen == 0 || addressEnd > uint64(len(frozen.ResolvedAddresses)) || portEnd > uint64(len(frozen.Grant.Ports)) {
			return nil, fmt.Errorf("launcher-v2 requested work unit %d has an empty or out-of-bounds corpus slice", ordinal)
		}
		endpointPairs := addressLen * portLen
		if endpointPairs == 0 || endpointPairs > maxLauncherEndpointPairsUnit || requested.EndpointPairCount != endpointPairs {
			return nil, fmt.Errorf("launcher-v2 requested work unit %d has an invalid endpoint-pair count", ordinal)
		}
		if plan.SchemaVersion == launcherPlanCurrentVersion && aggregateEndpointPairs > maxLauncherCurrentPairs-endpointPairs {
			return nil, errors.New("launcher-v2 requested work units exceed the aggregate endpoint-pair limit")
		}
		if plan.SchemaVersion == launcherPlanCurrentVersion {
			aggregateEndpointPairs += endpointPairs
		}
		expectedDeadlineSeconds, err := launcherV2ConservativeDeadlineSeconds(frozen.Grant.RatePolicy, endpointPairs)
		if err != nil || requested.ConservativeDeadlineSeconds != expectedDeadlineSeconds {
			return nil, fmt.Errorf("launcher-v2 requested work unit %d has an invalid conservative deadline", ordinal)
		}

		rectangle := launcherV2Rectangle{
			grantIndex:   requested.GrantIndex,
			addressStart: addressStart,
			addressEnd:   addressEnd,
			portStart:    portStart,
			portEnd:      portEnd,
		}
		for _, previous := range rectangles {
			if launcherV2RectanglesOverlap(previous, rectangle) {
				return nil, errors.New("launcher-v2 requested work-unit rectangles overlap")
			}
		}
		rectangles = append(rectangles, rectangle)

		unit := frozen
		unit.ResolvedAddresses = append([]string(nil), frozen.ResolvedAddresses[int(addressStart):int(addressEnd)]...)
		unit.Grant.Ports = append([]uint16(nil), frozen.Grant.Ports[int(portStart):int(portEnd)]...)
		materialized = append(materialized, unit)
	}
	return materialized, nil
}

func launcherPlanMaxRequestedUnits(schemaVersion int) (int, bool) {
	switch schemaVersion {
	case launcherPlanLegacyVersion:
		return maxLauncherLegacyUnits, true
	case launcherPlanCurrentVersion:
		return maxLauncherCurrentUnits, true
	default:
		return 0, false
	}
}

func validateLauncherV2Ports(ports []uint16) error {
	if len(ports) == 0 || len(ports) > 65535 {
		return errors.New("port corpus must be bounded and non-empty")
	}
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			return errors.New("port corpus contains zero")
		}
		if _, exists := seen[port]; exists {
			return errors.New("port corpus contains a duplicate")
		}
		seen[port] = struct{}{}
	}
	return nil
}

func launcherV2ConservativeDeadlineSeconds(policy ratePolicy, endpointPairs uint64) (uint64, error) {
	effectiveRate := uint64(naabuEffectiveProxyRate(policy))
	if effectiveRate == 0 || endpointPairs == 0 || endpointPairs > maxLauncherEndpointPairsUnit {
		return 0, errors.New("launcher-v2 deadline inputs are invalid")
	}
	waves := (endpointPairs + effectiveRate - 1) / effectiveRate
	seconds := waves*(uint64(policy.TimeoutSeconds)+1) + uint64(scannerProcessAllowance/time.Second)
	if seconds == 0 || seconds > uint64(naabuEngineCeiling/time.Second) {
		return 0, errors.New("launcher-v2 deadline exceeds the hard Naabu ceiling")
	}
	return seconds, nil
}

func sameLauncherV2StringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := values[value]; !exists {
			return false
		}
	}
	return true
}

func sameLauncherV2PortSet(left, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[uint16]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := values[value]; !exists {
			return false
		}
	}
	return true
}

func launcherV2RectanglesOverlap(left, right launcherV2Rectangle) bool {
	return left.grantIndex == right.grantIndex &&
		left.addressStart < right.addressEnd && right.addressStart < left.addressEnd &&
		left.portStart < right.portEnd && right.portStart < left.portEnd
}

// runNaabuLauncherV2 is deliberately separate from the legacy aggregate
// writer. The host owns the ordered unit identities and scope digests in the
// sidecar plan. The launcher proves the plan's frozen corpora are set-equal to
// the host-projected scope and executes each exact rectangular slice in
// sidecar order,
// while keeping target names and addresses out of journal IDs.
func runNaabuLauncherV2(
	outputRoot string,
	temporaryRoot string,
	plan *launcherV2Plan,
	units []scanUnit,
	proxy string,
	environment []string,
	now time.Time,
	runner func(invocation) launcherV2RunResult,
) error {
	if plan == nil || runner == nil {
		return errors.New("launcher-v2 execution plan is unavailable or mismatched")
	}
	materialized, err := materializeLauncherV2Plan(plan, "naabu", units)
	if err != nil {
		return err
	}
	budget := &launcherV2ByteBudget{}
	journal, err := createLauncherV2Journal(outputRoot, plan, budget)
	if err != nil {
		return err
	}
	journalOpen := true
	defer func() {
		if journalOpen {
			_ = journal.file.Close()
		}
	}()

	incompleteUnits := 0
	quarantineFailures := 0
	diagnostics := &launcherV2Diagnostics{}
	for planIndex, planned := range plan.RequestedWorkUnits {
		unit := materialized[planIndex]
		requested := launcherV2RequestedUnit{UnitID: planned.UnitID, ScopeSHA256: planned.ScopeSHA256}
		attempt := plan.ExecutionAttempt
		temporaryOutput := filepath.Join(temporaryRoot, fmt.Sprintf("result-%06d.jsonl", planIndex))
		finishWithoutArtifact := func(outcome string, retainRaw bool) error {
			if retainRaw {
				if _, quarantineErr := quarantineLauncherV2Raw(outputRoot, temporaryOutput, planIndex, attempt, budget); quarantineErr != nil {
					quarantineFailures++
					diagnostics.add(planIndex, "raw-evidence quarantine", quarantineErr)
				}
			}
			incompleteUnits++
			return journal.appendAttempt(launcherV2AttemptFinished{
				RecordType:  "attempt_finished",
				UnitID:      requested.UnitID,
				ScopeSHA256: requested.ScopeSHA256,
				Attempt:     attempt,
				Outcome:     outcome,
			})
		}

		if !now.Before(unit.Grant.ExpiresAt) || !time.Now().UTC().Before(unit.Grant.ExpiresAt) {
			diagnostics.add(planIndex, "authorization", errors.New("authorization expired before the unit could start"))
			if err := finishWithoutArtifact("not_tested", false); err != nil {
				return fmt.Errorf("record launcher-v2 unit-%06d outcome: %w", planIndex, err)
			}
			continue
		}
		command, invocationErr := naabuInvocation(
			unit, proxy, temporaryOutput, environment, temporaryRoot, planIndex,
		)
		if invocationErr != nil {
			diagnostics.add(planIndex, "invocation setup", invocationErr)
			if err := finishWithoutArtifact("not_tested", false); err != nil {
				return fmt.Errorf("record launcher-v2 unit-%06d outcome: %w", planIndex, err)
			}
			continue
		}
		command.Timeout = time.Duration(planned.ConservativeDeadlineSeconds) * time.Second
		runResult := runner(command)
		if !validLauncherV2RunOutcome(runResult) {
			runResult = launcherV2RunResult{Outcome: launcherV2RunFailed, Err: errors.New("invalid runner outcome")}
		}
		if runResult.Err != nil {
			diagnostics.add(planIndex, "scanner", runResult.Err)
		}
		allowEmpty := runResult.Outcome == launcherV2RunSucceeded
		artifact, artifactErr := publishLauncherV2FinalArtifact(
			outputRoot,
			temporaryOutput,
			plan.EngineRunID,
			requested,
			planIndex,
			attempt,
			unit,
			allowEmpty,
			budget,
		)
		if artifactErr != nil {
			diagnostics.add(planIndex, "evidence publish", artifactErr)
			outcome := string(runResult.Outcome)
			if runResult.Outcome == launcherV2RunSucceeded {
				outcome = "failed"
			}
			if err := finishWithoutArtifact(outcome, true); err != nil {
				return fmt.Errorf("record launcher-v2 unit-%06d outcome: %w", planIndex, err)
			}
			continue
		}
		outcome := "tested_complete"
		incompleteReason := ""
		if runResult.Outcome != launcherV2RunSucceeded {
			outcome = "tested_partial"
			incompleteReason = string(runResult.Outcome)
			incompleteUnits++
		}
		if err := journal.appendAttempt(launcherV2AttemptFinished{
			RecordType:       "attempt_finished",
			UnitID:           requested.UnitID,
			ScopeSHA256:      requested.ScopeSHA256,
			Attempt:          attempt,
			Outcome:          outcome,
			IncompleteReason: incompleteReason,
			FinalArtifact:    artifact,
		}); err != nil {
			return fmt.Errorf("record launcher-v2 unit-%06d outcome: %w", planIndex, err)
		}
	}
	if err := journal.file.Close(); err != nil {
		return fmt.Errorf("close launcher-v2 journal: %w", err)
	}
	journalOpen = false
	if incompleteUnits > 0 {
		return &launcherV2IncompleteRun{
			incompleteUnits:    incompleteUnits,
			quarantineFailures: quarantineFailures,
			diagnostics:        diagnostics.summary(),
		}
	}
	return nil
}

func createLauncherV2Journal(outputRoot string, plan *launcherV2Plan, budget *launcherV2ByteBudget) (*launcherV2Journal, error) {
	if plan == nil {
		return nil, errors.New("launcher-v2 journal identity plan is invalid")
	}
	maxRequestedUnits, schemaSupported := launcherPlanMaxRequestedUnits(plan.SchemaVersion)
	if !schemaSupported || !launcherV2OpaqueID(plan.EngineRunID) || plan.ExecutionAttempt == 0 || len(plan.RequestedWorkUnits) < 1 || len(plan.RequestedWorkUnits) > maxRequestedUnits {
		return nil, errors.New("launcher-v2 journal identity plan is invalid")
	}
	seenUnits := make(map[string]struct{}, len(plan.RequestedWorkUnits))
	for _, unit := range plan.RequestedWorkUnits {
		if !launcherV2WorkUnitID(unit.UnitID) || !launcherV2SHA256(unit.ScopeSHA256) {
			return nil, errors.New("launcher-v2 journal work-unit identity is invalid")
		}
		if _, exists := seenUnits[unit.UnitID]; exists {
			return nil, errors.New("launcher-v2 journal work-unit identities are not unique")
		}
		seenUnits[unit.UnitID] = struct{}{}
	}
	root := filepath.Join(outputRoot, launcherV2Directory)
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, fmt.Errorf("create exclusive launcher-v2 output directory: %w", err)
	}
	// Persist the new namespace itself before relying on files synced inside it.
	// A crash must not erase every earlier terminal record merely because the
	// parent directory entry was still only in memory.
	if err := syncDirectory(outputRoot); err != nil {
		return nil, err
	}
	journalPath := filepath.Join(root, launcherV2JournalName)
	file, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create exclusive launcher-v2 journal: %w", err)
	}
	requested := make(map[string]launcherV2RequestedUnit, len(plan.RequestedWorkUnits))
	for _, unit := range plan.RequestedWorkUnits {
		requested[unit.UnitID] = launcherV2RequestedUnit{UnitID: unit.UnitID, ScopeSHA256: unit.ScopeSHA256}
	}
	journal := &launcherV2Journal{
		file:             file,
		engineRunID:      plan.EngineRunID,
		executionAttempt: plan.ExecutionAttempt,
		requested:        requested,
		terminalWritten:  make(map[string]bool, len(requested)),
		budget:           budget,
	}
	headerUnits := make([]launcherV2RequestedUnit, 0, len(plan.RequestedWorkUnits))
	for _, unit := range plan.RequestedWorkUnits {
		headerUnits = append(headerUnits, launcherV2RequestedUnit{UnitID: unit.UnitID, ScopeSHA256: unit.ScopeSHA256})
	}
	if err := journal.appendRecord(launcherV2Header{
		RecordType:         "header",
		SchemaVersion:      launcherJournalSchemaVersion,
		EngineRunID:        plan.EngineRunID,
		ExecutionAttempt:   plan.ExecutionAttempt,
		RequestedWorkUnits: headerUnits,
	}); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syncDirectory(root); err != nil {
		_ = file.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *launcherV2Journal) appendAttempt(record launcherV2AttemptFinished) error {
	requested, exists := journal.requested[record.UnitID]
	if !exists || requested.ScopeSHA256 != record.ScopeSHA256 {
		return errors.New("launcher-v2 terminal record does not match a requested work unit")
	}
	if record.Attempt != journal.executionAttempt || journal.terminalWritten[record.UnitID] {
		return errors.New("launcher-v2 permits one terminal outcome per requested unit and host invocation")
	}
	switch record.Outcome {
	case "tested_complete":
		if record.IncompleteReason != "" || record.FinalArtifact == nil || !validLauncherV2FinalArtifact(*record.FinalArtifact, journal.engineRunID, requested, record.Attempt) {
			return errors.New("launcher-v2 completed attempt lacks one exact final artifact")
		}
	case "tested_partial":
		if !launcherV2IncompleteReason(record.IncompleteReason) || record.FinalArtifact == nil || record.FinalArtifact.ByteLength == 0 || !validLauncherV2FinalArtifact(*record.FinalArtifact, journal.engineRunID, requested, record.Attempt) {
			return errors.New("launcher-v2 partial attempt lacks exact non-empty evidence or its bounded reason")
		}
	case "failed", "timed_out", "cancelled", "not_tested":
		if record.IncompleteReason != "" || record.FinalArtifact != nil {
			return errors.New("launcher-v2 untested attempt cannot claim evidence or a partial reason")
		}
	default:
		return errors.New("launcher-v2 terminal outcome is unsupported")
	}
	if record.RecordType != "attempt_finished" {
		return errors.New("launcher-v2 terminal record type is invalid")
	}
	if err := journal.appendRecord(record); err != nil {
		return err
	}
	journal.terminalWritten[record.UnitID] = true
	return nil
}

func (journal *launcherV2Journal) appendRecord(record any) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("encode launcher-v2 journal record")
	}
	if len(encoded) == 0 || len(encoded) > maxLauncherV2RecordBytes {
		return errors.New("launcher-v2 journal record exceeds its bound")
	}
	encoded = append(encoded, '\n')
	if journal.written+int64(len(encoded)) > maxLauncherV2JournalBytes || journal.recordsWritten >= 1+len(journal.requested) {
		return errors.New("launcher-v2 journal exceeds its aggregate bound")
	}
	if journal.budget == nil || !journal.budget.reserveJournal(int64(len(encoded))) {
		return errors.New("launcher-v2 output exceeds its shared aggregate byte budget")
	}
	written, err := journal.file.Write(encoded)
	if err != nil || written != len(encoded) {
		return errors.New("append launcher-v2 journal record")
	}
	if err := journal.file.Sync(); err != nil {
		return fmt.Errorf("sync launcher-v2 journal record: %w", err)
	}
	journal.written += int64(written)
	journal.recordsWritten++
	return nil
}

func (budget *launcherV2ByteBudget) reserveJournal(length int64) bool {
	if length < 0 || budget.journalUsed > maxLauncherV2JournalBytes-int64(length) || budget.journalUsed+budget.payloadUsed > maxEvidenceBytes-length {
		return false
	}
	budget.journalUsed += length
	return true
}

func (budget *launcherV2ByteBudget) reservePayload(length int64) bool {
	if !budget.canReservePayload(length) {
		return false
	}
	budget.payloadUsed += length
	return true
}

func (budget *launcherV2ByteBudget) canReservePayload(length int64) bool {
	maximumPayload := int64(maxEvidenceBytes - maxLauncherV2JournalBytes)
	if length < 0 || budget.payloadUsed > maximumPayload-length || budget.journalUsed+budget.payloadUsed > maxEvidenceBytes-length {
		return false
	}
	return true
}

func (budget *launcherV2ByteBudget) releasePayload(length int64) {
	if length >= 0 && length <= budget.payloadUsed {
		budget.payloadUsed -= length
	}
}

func (diagnostics *launcherV2Diagnostics) add(planIndex int, phase string, cause error) {
	if diagnostics == nil || cause == nil {
		return
	}
	if len(diagnostics.entries) >= maxLauncherV2Diagnostics {
		diagnostics.omitted++
		return
	}
	message := boundedLauncherV2Diagnostic(cause.Error())
	if message == "" {
		message = "no diagnostic text was provided"
	}
	diagnostics.entries = append(
		diagnostics.entries,
		fmt.Sprintf("unit-%06d %s: %s", planIndex, phase, message),
	)
}

func (diagnostics *launcherV2Diagnostics) summary() string {
	if diagnostics == nil || len(diagnostics.entries) == 0 {
		return ""
	}
	value := strings.Join(diagnostics.entries, "; ")
	if diagnostics.omitted > 0 {
		value += fmt.Sprintf("; %d additional diagnostic(s) omitted", diagnostics.omitted)
	}
	return value
}

func boundedLauncherV2Diagnostic(value string) string {
	var cleaned strings.Builder
	lastWasSpace := false
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if character == ' ' {
			if lastWasSpace {
				continue
			}
			lastWasSpace = true
		} else {
			lastWasSpace = false
		}
		encoded := string(character)
		if cleaned.Len()+len(encoded) > maxLauncherV2DiagnosticBytes {
			break
		}
		cleaned.WriteString(encoded)
	}
	return strings.TrimSpace(cleaned.String())
}

func validLauncherV2RunOutcome(result launcherV2RunResult) bool {
	switch result.Outcome {
	case launcherV2RunSucceeded:
		return result.Err == nil
	case launcherV2RunFailed, launcherV2RunTimedOut, launcherV2RunCancelled:
		return result.Err != nil
	default:
		return false
	}
}

func launcherV2IncompleteReason(value string) bool {
	return value == "failed" || value == "timed_out" || value == "cancelled"
}

func publishLauncherV2FinalArtifact(
	outputRoot string,
	scannerOutput string,
	engineRunID string,
	requested launcherV2RequestedUnit,
	planIndex int,
	attempt uint32,
	unit scanUnit,
	allowEmpty bool,
	budget *launcherV2ByteBudget,
) (*launcherV2FinalArtifact, error) {
	relativePath := path.Join(
		launcherV2Directory,
		"units",
		fmt.Sprintf("unit-%06d", planIndex),
		fmt.Sprintf("attempt-%d.jsonl", attempt),
	)
	if !launcherV2RelativePath(relativePath) {
		return nil, errors.New("launcher-v2 final artifact path is unsafe")
	}
	var digest string
	byteLength, err := publishLauncherV2File(outputRoot, relativePath, budget, func(staging *os.File) (int64, error) {
		hasher := sha256.New()
		writer := bufio.NewWriterSize(io.MultiWriter(staging, hasher), 64*1024)
		prospective := int64(maxLauncherV2JournalBytes) + budget.payloadUsed
		if err := normalizeEvidence(scannerOutput, writer, &prospective, "naabu", unit); err != nil {
			return 0, err
		}
		if err := writer.Flush(); err != nil {
			return 0, fmt.Errorf("flush launcher-v2 final artifact: %w", err)
		}
		length := prospective - int64(maxLauncherV2JournalBytes) - budget.payloadUsed
		digest = fmt.Sprintf("%x", hasher.Sum(nil))
		if length == 0 && (!allowEmpty || digest != emptySHA256) {
			return 0, errors.New("launcher-v2 non-successful scanner produced no usable normalized evidence")
		}
		return length, nil
	})
	if err != nil {
		return nil, err
	}
	return &launcherV2FinalArtifact{
		EngineRunID:  engineRunID,
		UnitID:       requested.UnitID,
		ScopeSHA256:  requested.ScopeSHA256,
		Attempt:      attempt,
		RelativePath: relativePath,
		SHA256:       digest,
		ByteLength:   uint64(byteLength),
	}, nil
}

func quarantineLauncherV2Raw(outputRoot, scannerOutput string, planIndex int, attempt uint32, budget *launcherV2ByteBudget) (bool, error) {
	metadata, err := os.Lstat(scannerOutput)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 || metadata.Size() > maxEvidenceBytes {
		return false, errors.New("launcher-v2 raw evidence is not a bounded regular file")
	}
	relativePath := path.Join(
		launcherV2Directory,
		"quarantine",
		fmt.Sprintf("unit-%06d", planIndex),
		fmt.Sprintf("attempt-%d.raw.jsonl", attempt),
	)
	if !launcherV2RelativePath(relativePath) {
		return false, errors.New("launcher-v2 raw-evidence quarantine path is unsafe")
	}
	source, err := os.Open(scannerOutput)
	if err != nil {
		return false, fmt.Errorf("open launcher-v2 raw evidence: %w", err)
	}
	defer source.Close()
	openedMetadata, err := source.Stat()
	if err != nil || !openedMetadata.Mode().IsRegular() || openedMetadata.Size() != metadata.Size() || openedMetadata.Size() > maxEvidenceBytes {
		return false, errors.New("launcher-v2 raw evidence changed before quarantine")
	}
	if !budget.canReservePayload(openedMetadata.Size()) {
		return false, errors.New("launcher-v2 output exceeds its shared aggregate byte budget")
	}
	_, err = publishLauncherV2File(outputRoot, relativePath, budget, func(staging *os.File) (int64, error) {
		written, err := io.Copy(staging, io.LimitReader(source, maxEvidenceBytes+1))
		if err != nil || written != openedMetadata.Size() {
			return 0, errors.New("copy launcher-v2 raw evidence exactly")
		}
		return written, nil
	})
	return err == nil, err
}

func publishLauncherV2File(
	outputRoot, relativePath string,
	budget *launcherV2ByteBudget,
	write func(*os.File) (int64, error),
) (int64, error) {
	finalPath := filepath.Join(outputRoot, filepath.FromSlash(relativePath))
	parent := filepath.Dir(finalPath)
	if err := ensureLauncherV2Directory(parent, outputRoot); err != nil {
		return 0, err
	}
	stagingPath := finalPath + ".partial"
	staging, err := os.OpenFile(stagingPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create launcher-v2 staged output: %w", err)
	}
	published := false
	defer func() {
		_ = staging.Close()
		if !published {
			_ = os.Remove(stagingPath)
		}
	}()
	length, err := write(staging)
	if err != nil {
		return 0, err
	}
	if !budget.reservePayload(length) {
		return 0, errors.New("launcher-v2 output exceeds its shared aggregate byte budget")
	}
	defer func() {
		if !published {
			budget.releasePayload(length)
		}
	}()
	if err := staging.Sync(); err != nil {
		return 0, fmt.Errorf("sync launcher-v2 staged output: %w", err)
	}
	if err := staging.Close(); err != nil {
		return 0, fmt.Errorf("close launcher-v2 staged output: %w", err)
	}
	if _, err := os.Lstat(finalPath); !os.IsNotExist(err) {
		return 0, errors.New("launcher-v2 final output already exists or cannot be inspected")
	}
	if err := os.Rename(stagingPath, finalPath); err != nil {
		return 0, fmt.Errorf("publish launcher-v2 output atomically: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		_ = os.Remove(finalPath)
		return 0, err
	}
	published = true
	return length, nil
}

func ensureLauncherV2Directory(directory, outputRoot string) error {
	root := filepath.Join(outputRoot, launcherV2Directory)
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("launcher-v2 directory escaped its output root")
	}
	current := root
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		created := false
		if err := os.Mkdir(current, 0o700); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("create launcher-v2 private directory: %w", err)
			}
		} else {
			created = true
		}
		metadata, err := os.Lstat(current)
		if err != nil || !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 || metadata.Mode().Perm()&0o077 != 0 {
			return errors.New("launcher-v2 private directory is unsafe")
		}
		if created {
			if err := syncDirectory(filepath.Dir(current)); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open launcher-v2 directory for sync: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync launcher-v2 directory: %w", err)
	}
	return nil
}

func launcherV2OpaqueID(value string) bool {
	if value == "" || len(value) > maxLauncherV2OpaqueIDBytes {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("-_.:", rune(character))) {
			return false
		}
	}
	return true
}

// Work-unit IDs are host-generated 128-bit lowercase hexadecimal values with
// a fixed namespace. A target-shaped IP address or domain is therefore not a
// valid journal identity even though other durable opaque IDs remain backward
// compatible with the wider identifier alphabet.
func launcherV2WorkUnitID(value string) bool {
	if len(value) != len(launcherV2WorkUnitPrefix)+launcherV2WorkUnitHexChars || !strings.HasPrefix(value, launcherV2WorkUnitPrefix) {
		return false
	}
	for _, character := range []byte(value[len(launcherV2WorkUnitPrefix):]) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func launcherV2SHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func launcherV2RelativePath(value string) bool {
	if value == "" || len(value) > maxLauncherV2RelativeBytes || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsAny(value, "\\:") {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("/-_.", rune(character))) {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validLauncherV2FinalArtifact(
	artifact launcherV2FinalArtifact,
	engineRunID string,
	requested launcherV2RequestedUnit,
	attempt uint32,
) bool {
	return artifact.EngineRunID == engineRunID &&
		artifact.UnitID == requested.UnitID &&
		artifact.ScopeSHA256 == requested.ScopeSHA256 &&
		artifact.Attempt == attempt &&
		launcherV2OpaqueID(artifact.EngineRunID) &&
		launcherV2WorkUnitID(artifact.UnitID) &&
		launcherV2SHA256(artifact.ScopeSHA256) &&
		launcherV2RelativePath(artifact.RelativePath) &&
		launcherV2SHA256(artifact.SHA256) &&
		(artifact.ByteLength != 0 || artifact.SHA256 == emptySHA256)
}

func supportedEngine(engineID string) bool {
	return engineID == "naabu" || engineID == "httpx" || engineID == "nuclei"
}

func loadScope(path, expectedEngine string) (*scopeDocument, error) {
	value, err := readBoundedRegularFile(path, maxScopeBytes)
	if err != nil {
		return nil, fmt.Errorf("read immutable scope: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var document scopeDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("scope document is malformed")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errors.New("scope document has trailing data")
	}
	if document.SchemaVersion != "2" || document.EngineID != expectedEngine || len(document.Assets) == 0 || len(document.Assets) > maxAssets {
		return nil, errors.New("scope document version, engine, or asset count is invalid")
	}
	return &document, nil
}

func validateAndPlan(document *scopeDocument, engineID string, now time.Time) ([]scanUnit, error) {
	if document.GeneratedAt.IsZero() || document.GeneratedAt.After(now.Add(5*time.Minute)) {
		return nil, errors.New("scope document timestamp is invalid or future-dated")
	}
	expectedPermission := "low_impact_external_connection"
	expectedActivity := "low_impact_external"
	if engineID == "nuclei" {
		expectedPermission = "active_external_testing"
		expectedActivity = "active_external"
	}
	seenAssets := make(map[string]struct{}, len(document.Assets))
	seenGrants := make(map[string]struct{})
	caseID := ""
	units := make([]scanUnit, 0, len(document.Assets))
	for _, asset := range document.Assets {
		if !safeText(asset.ID, 256) || !safeText(asset.Name, 4096) || !supportedAssetKind(engineID, asset.Kind) {
			return nil, errors.New("scope contains an invalid or unsupported asset")
		}
		if _, exists := seenAssets[asset.ID]; exists {
			return nil, errors.New("scope contains a duplicate asset")
		}
		seenAssets[asset.ID] = struct{}{}
		if asset.Provider != nil || asset.Region != nil || len(asset.Identifiers) == 0 || len(asset.Identifiers) > maxIdentifiers || len(asset.Grants) == 0 || len(asset.Grants) > maxGrantsPerAsset {
			return nil, errors.New("external asset provider, identifier, or grant closure is invalid")
		}
		for _, grant := range asset.Grants {
			if grant.Permission != expectedPermission || grant.ExternalScope == nil {
				return nil, errors.New("scope contains a grant outside the engine permission closure")
			}
			external := *grant.ExternalScope
			if err := validateGrant(asset, grant, external, engineID, expectedActivity, now); err != nil {
				return nil, err
			}
			if _, exists := seenGrants[grant.ID]; exists {
				return nil, errors.New("scope contains a duplicate grant")
			}
			seenGrants[grant.ID] = struct{}{}
			if caseID == "" {
				caseID = external.CaseID
			} else if caseID != external.CaseID {
				return nil, errors.New("one execution cannot combine grants from different cases")
			}
			resolvedAddresses := append([]string(nil), grant.ResolvedAddresses...)
			sort.Strings(resolvedAddresses)
			if engineID == "naabu" {
				// Keep one bounded process per exact grant. Naabu accepts a
				// newline-separated host set, so a normal /24 no longer pays process
				// startup and teardown once for every frozen address. Evidence is
				// still checked against this exact host-side resolution set below.
				units = append(units, scanUnit{
					AssetID: asset.ID, Grant: external,
					ResolvedAddresses: resolvedAddresses,
				})
			} else {
				for _, port := range external.Ports {
					units = append(units, scanUnit{
						AssetID: asset.ID, Grant: external, Port: port,
						ResolvedAddresses: resolvedAddresses,
					})
				}
			}
		}
	}
	sort.Slice(units, func(left, right int) bool {
		if units[left].AssetID != units[right].AssetID {
			return units[left].AssetID < units[right].AssetID
		}
		if units[left].Grant.ID != units[right].Grant.ID {
			return units[left].Grant.ID < units[right].Grant.ID
		}
		if units[left].Port != units[right].Port {
			return units[left].Port < units[right].Port
		}
		return strings.Join(units[left].ResolvedAddresses, ",") < strings.Join(units[right].ResolvedAddresses, ",")
	})
	return units, nil
}

func validateGrant(asset scopeAsset, grant scopeGrant, external externalScope, engineID, expectedActivity string, now time.Time) error {
	if !safeText(grant.ID, 256) || !safeText(grant.ConfirmedBy, 1024) || grant.AuthorizationReference == nil || !safeText(*grant.AuthorizationReference, 1000) {
		return errors.New("external grant identity or written authorization is invalid")
	}
	if external.ID != grant.ID || external.AssetID != asset.ID || !safeText(external.CaseID, 256) || external.ApprovedBy != grant.ConfirmedBy || !safeText(external.AssertedAuthority, 4096) {
		return errors.New("structured external policy does not match its asset grant")
	}
	if grant.ExpiresAt == nil || !grant.ExpiresAt.Equal(external.ExpiresAt) || !grant.ConfirmedAt.Equal(external.ApprovedAt) {
		return errors.New("external policy timestamps diverge from the grant")
	}
	if external.ApprovedAt.IsZero() || external.ApprovedAt.After(now.Add(5*time.Minute)) || !external.ExpiresAt.After(now) || !external.ExpiresAt.After(external.ApprovedAt) || external.ExpiresAt.Sub(external.ApprovedAt) > 30*24*time.Hour {
		return errors.New("external grant is expired, future-dated, or exceeds thirty days")
	}
	if external.Activity != expectedActivity || external.Protocol == "udp" {
		return errors.New("external activity or transport protocol does not match the engine")
	}
	if engineID != "naabu" && external.Protocol != "http" && external.Protocol != "https" {
		return errors.New("HTTP engines require an exact HTTP or HTTPS protocol grant")
	}
	if engineID == "naabu" && external.Protocol != "tcp" && external.Protocol != "tls" && external.Protocol != "http" && external.Protocol != "https" {
		return errors.New("Naabu requires a TCP-based protocol grant")
	}
	canonical, err := validateCanonicalTarget(external.Target)
	if err != nil {
		return err
	}
	if engineID != "naabu" && external.Target.Kind == "network" {
		return errors.New("HTTP engines do not expand network targets")
	}
	for _, identifier := range asset.Identifiers {
		if !safeText(identifier.Namespace, 256) || identifier.Value != canonical {
			return errors.New("asset identifiers are not closed over the canonical external target")
		}
	}
	if err := validatePorts(external.Ports); err != nil {
		return err
	}
	if err := validateResolvedAddresses(grant.ResolvedAddresses, external.Target); err != nil {
		return err
	}
	if err := validateRatePolicy(external.RatePolicy, expectedActivity); err != nil {
		return err
	}
	return validateTemplatePolicy(external.TemplatePolicy, engineID)
}

func supportedAssetKind(engineID, kind string) bool {
	switch engineID {
	case "naabu":
		return kind == "domain" || kind == "host" || kind == "ip_address"
	case "httpx", "nuclei":
		return kind == "domain" || kind == "ip_address" || kind == "web_service"
	default:
		return false
	}
}

func validateCanonicalTarget(target canonicalTarget) (string, error) {
	if !safeText(target.Value, 2048) || strings.Contains(target.Value, "*") {
		return "", errors.New("external target is empty, wildcarded, or malformed")
	}
	switch target.Kind {
	case "hostname":
		if target.Value != strings.ToLower(target.Value) || strings.HasSuffix(target.Value, ".") || len(target.Value) > 253 || (target.Value != "localhost" && !strings.Contains(target.Value, ".")) {
			return "", errors.New("external hostname is not canonical")
		}
		for _, label := range strings.Split(target.Value, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", errors.New("external hostname is malformed")
			}
			for _, character := range label {
				if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
					return "", errors.New("external hostname contains unsupported characters")
				}
			}
		}
		return target.Value, nil
	case "address":
		parsed := net.ParseIP(target.Value)
		if parsed == nil || parsed.String() != target.Value {
			return "", errors.New("external address is not canonical")
		}
		return parsed.String(), nil
	case "network":
		_, network, err := net.ParseCIDR(target.Value)
		if err != nil || network.String() != target.Value {
			return "", errors.New("external network is not canonical")
		}
		return network.String(), nil
	default:
		return "", errors.New("external target kind is unsupported")
	}
}

func validatePorts(ports []uint16) error {
	if len(ports) == 0 || len(ports) > 65535 {
		return errors.New("external grant requires a bounded non-empty port set")
	}
	previous := uint16(0)
	for index, port := range ports {
		if port == 0 || (index > 0 && port <= previous) {
			return errors.New("external ports must be non-zero, unique, and sorted")
		}
		previous = port
	}
	return nil
}

func validateResolvedAddresses(addresses []string, target canonicalTarget) error {
	if len(addresses) == 0 || len(addresses) > maxResolvedAddresses {
		return errors.New("external grant requires a bounded non-empty frozen address set")
	}
	seen := make(map[string]struct{}, len(addresses))
	var targetAddress net.IP
	var targetNetwork *net.IPNet
	if target.Kind == "address" {
		targetAddress = net.ParseIP(target.Value)
	}
	if target.Kind == "network" {
		_, targetNetwork, _ = net.ParseCIDR(target.Value)
	}
	for _, value := range addresses {
		parsed := net.ParseIP(value)
		if parsed == nil || parsed.String() != value {
			return errors.New("frozen address set contains a non-canonical IP address")
		}
		if _, exists := seen[value]; exists {
			return errors.New("frozen address set contains a duplicate IP address")
		}
		seen[value] = struct{}{}
		if targetAddress != nil && !parsed.Equal(targetAddress) {
			return errors.New("frozen address is outside the exact address target")
		}
		if targetNetwork != nil && !targetNetwork.Contains(parsed) {
			return errors.New("frozen address is outside the approved network target")
		}
	}
	return nil
}

func validateRatePolicy(policy ratePolicy, activity string) error {
	maxRate, maxConcurrency, maxTimeout := uint16(25), uint16(10), uint32(1800)
	if activity == "active_external" {
		maxRate, maxConcurrency, maxTimeout = 10, 5, 3600
	}
	if policy.RequestsPerSecond == 0 || policy.RequestsPerSecond > maxRate || policy.Concurrency == 0 || policy.Concurrency > maxConcurrency || policy.TimeoutSeconds == 0 || policy.TimeoutSeconds > maxTimeout {
		return errors.New("external rate, concurrency, or timeout exceeds its activity class")
	}
	return nil
}

func validateTemplatePolicy(policy templatePolicy, engineID string) error {
	if policy.AllowHeadless || policy.AllowOutOfBand || policy.AllowFuzzing || policy.AllowFileUpload || policy.AllowDenialOfService || policy.AllowCredentialAttacks {
		return errors.New("prohibited template capability was enabled")
	}
	if engineID != "nuclei" {
		if policy.Revision != "not_applicable" || len(policy.AllowedTemplateIDs) != 0 || policy.ProfileID != nil {
			return errors.New("non-template engine received a template selection")
		}
		return nil
	}
	if policy.Revision != "nuclei-templates@"+templateRevision {
		return errors.New("Nuclei policy does not match the embedded exact template revision")
	}
	explicitSelection := len(policy.AllowedTemplateIDs) != 0
	profileSelection := policy.ProfileID != nil
	if explicitSelection == profileSelection {
		return errors.New("Nuclei policy must select exactly one pinned profile or explicit template allowlist")
	}
	if profileSelection {
		if *policy.ProfileID != nucleiWebSafeProfileID {
			return errors.New("Nuclei policy selected an unknown pinned profile")
		}
		return nil
	}
	if len(policy.AllowedTemplateIDs) > 1000 {
		return errors.New("Nuclei explicit template allowlist exceeds its bound")
	}
	seen := make(map[string]struct{}, len(policy.AllowedTemplateIDs))
	for _, id := range policy.AllowedTemplateIDs {
		if !safeTemplateID(id) {
			return errors.New("Nuclei template allowlist contains an invalid exact identifier")
		}
		if _, exists := seen[id]; exists {
			return errors.New("Nuclei template allowlist contains a duplicate identifier")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func managedProxy(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5h" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != managedGatewayPort || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("managed SOCKS gateway endpoint is absent or malformed")
	}
	if net.ParseIP(parsed.Hostname()) == nil {
		return "", "", errors.New("managed SOCKS gateway must use the frozen bridge address")
	}
	canonical := "socks5h://" + net.JoinHostPort(parsed.Hostname(), parsed.Port())
	return canonical, net.JoinHostPort(parsed.Hostname(), parsed.Port()), nil
}

func nucleiCompatibleProxy(managed string) string {
	return "socks5://" + strings.TrimPrefix(managed, "socks5h://")
}

func childEnvironment(proxy, temporaryRoot string) []string {
	return []string{
		"AI_SECURITY_SCANNER_PROXY=" + proxy,
		"ALL_PROXY=" + proxy,
		"all_proxy=" + proxy,
		"HTTP_PROXY=" + proxy,
		"http_proxy=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"https_proxy=" + proxy,
		"NO_PROXY=",
		"no_proxy=",
		"DISABLE_STDOUT=1",
		"HOME=" + temporaryRoot,
		"XDG_CACHE_HOME=" + filepath.Join(temporaryRoot, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(temporaryRoot, "config"),
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
}

func naabuInvocation(
	unit scanUnit,
	proxy, output string,
	environment []string,
	temporaryRoot string,
	index int,
) (invocation, error) {
	ports := make([]string, 0, len(unit.Grant.Ports))
	for _, port := range unit.Grant.Ports {
		ports = append(ports, strconv.Itoa(int(port)))
	}
	targetsFile := filepath.Join(temporaryRoot, fmt.Sprintf("targets-%06d.txt", index))
	if err := writeExclusiveLines(targetsFile, unit.ResolvedAddresses); err != nil {
		return invocation{}, err
	}
	effectiveRate := naabuEffectiveProxyRate(unit.Grant.RatePolicy)
	return invocation{
		Program: "/usr/local/bin/naabu",
		Args: []string{
			// A private launcher-owned list keeps the exact host-side frozen set
			// without a second DNS lookup and avoids the operating system's
			// per-argument length limit for a bounded IPv6 range.
			"-list", targetsFile,
			"-port", strings.Join(ports, ","),
			"-scan-type", "c",
			"-proxy", proxy,
			// Pinned Naabu halves its configured rate whenever a proxy is present.
			// Compensate for that fixed behavior so a conservative 1 req/s grant
			// does not collapse into its degenerate zero-rate limiter behavior.
			"-rate", strconv.Itoa(int(effectiveRate) * naabuProxyRateDivisor),
			"-c", strconv.Itoa(int(unit.Grant.RatePolicy.Concurrency)),
			"-timeout", (time.Duration(unit.Grant.RatePolicy.TimeoutSeconds) * time.Second).String(),
			"-retries", "0",
			"-json", "-output", output,
			"-no-stdin", "-disable-update-check", "-silent",
		},
		Env: environment, Expiry: unit.Grant.ExpiresAt,
		Timeout: naabuInvocationTimeout(
			unit.Grant.RatePolicy,
			len(unit.Grant.Ports),
			len(unit.ResolvedAddresses),
		),
	}, nil
}

// Pinned Naabu uses the post-proxy rate as both its connect worker bound and
// its requests-per-second limiter. Keeping the effective rate at or below both
// grant limits preserves the stricter of the two controls.
func naabuEffectiveProxyRate(policy ratePolicy) uint16 {
	if policy.RequestsPerSecond < policy.Concurrency {
		return policy.RequestsPerSecond
	}
	return policy.Concurrency
}

// timeout_seconds is a per-connect deadline in Naabu, not a total-process
// deadline. Bound the child by the finite port workload, its effective proxy
// rate, and a small fixed allowance for process setup and Naabu's final warmup.
func naabuInvocationTimeout(policy ratePolicy, portCount, addressCount int) time.Duration {
	workItems := uint64(portCount) * uint64(addressCount)
	return boundedInvocationTimeout(policy, workItems, naabuEngineCeiling)
}

// Scanner timeout flags are per request or connection, while runCommand needs
// a total child-process deadline. Conservatively budget one timeout plus one
// pacing second per effective-rate wave, add fixed startup/finalization time,
// and saturate at the reviewed engine ceiling before converting to Duration.
func boundedInvocationTimeout(policy ratePolicy, workItems uint64, ceiling time.Duration) time.Duration {
	effectiveRate := uint64(naabuEffectiveProxyRate(policy))
	waves := (workItems + effectiveRate - 1) / effectiveRate
	ceilingSeconds := uint64(ceiling / time.Second)
	allowanceSeconds := uint64(scannerProcessAllowance / time.Second)
	perWaveSeconds := uint64(policy.TimeoutSeconds) + 1
	if waves > (ceilingSeconds-allowanceSeconds)/perWaveSeconds {
		return ceiling
	}
	return time.Duration(waves*perWaveSeconds+allowanceSeconds) * time.Second
}

func httpxInvocation(unit scanUnit, proxy, output string, environment []string) (invocation, error) {
	target, err := targetURL(unit)
	if err != nil {
		return invocation{}, err
	}
	return invocation{
		Program: "/usr/local/bin/httpx",
		Args: []string{
			"-target", target,
			"-proxy", proxy,
			"-rate-limit", strconv.Itoa(int(unit.Grant.RatePolicy.RequestsPerSecond)),
			"-threads", strconv.Itoa(int(unit.Grant.RatePolicy.Concurrency)),
			"-timeout", strconv.Itoa(int(unit.Grant.RatePolicy.TimeoutSeconds)),
			"-retries", "0",
			"-json", "-output", output,
			"-status-code", "-omit-body", "-no-fallback-scheme",
			"-no-stdin", "-disable-update-check", "-silent", "-no-color",
		},
		Env: environment, Expiry: unit.Grant.ExpiresAt,
		Timeout: boundedInvocationTimeout(unit.Grant.RatePolicy, 1, httpEngineCeiling),
	}, nil
}

func nucleiInvocation(unit scanUnit, proxy, output string, environment []string, temporaryRoot string, index int, templatePaths []string) (invocation, error) {
	target, err := targetURL(unit)
	if err != nil {
		return invocation{}, err
	}
	templatesFile := filepath.Join(temporaryRoot, fmt.Sprintf("templates-%06d.txt", index))
	idsFile := filepath.Join(temporaryRoot, fmt.Sprintf("template-ids-%06d.txt", index))
	if err := writeExclusiveLines(templatesFile, templatePaths); err != nil {
		return invocation{}, err
	}
	if err := writeExclusiveLines(idsFile, unit.Grant.TemplatePolicy.AllowedTemplateIDs); err != nil {
		return invocation{}, err
	}
	automaticTemplateRoot := ""
	if unit.Grant.TemplatePolicy.ProfileID != nil {
		automaticTemplateRoot, err = prepareNucleiAutomaticRoot(temporaryRoot, index, templatePaths)
		if err != nil {
			return invocation{}, err
		}
	}
	concurrency := strconv.Itoa(int(unit.Grant.RatePolicy.Concurrency))
	requestBudget := uint64(len(templatePaths) * maxNucleiRequestsPerTemplate)
	if unit.Grant.TemplatePolicy.ProfileID != nil {
		// A technology detector can run once in the detection pass and once
		// again if its product tag is selected. Add the separate Wappalyzer GET.
		requestBudget = requestBudget*2 + 1
	}
	totalTimeout := boundedInvocationTimeout(
		unit.Grant.RatePolicy,
		requestBudget,
		httpEngineCeiling,
	)
	softTimeout := totalTimeout - scannerProcessAllowance
	if softTimeout < time.Second {
		softTimeout = time.Second
	}
	arguments := []string{
		"-target", target,
		"-templates", templatesFile,
		"-template-id", idsFile,
		"-type", "http",
		"-proxy", proxy,
		"-rate-limit", strconv.Itoa(int(unit.Grant.RatePolicy.RequestsPerSecond)),
		"-bulk-size", concurrency,
		"-concurrency", concurrency,
		"-payload-concurrency", "1",
		"-timeout", strconv.Itoa(int(unit.Grant.RatePolicy.TimeoutSeconds)),
		"-max-time", softTimeout.String(),
		"-retries", "0",
		"-response-size-read", strconv.Itoa(4 * 1024 * 1024),
		"-response-size-save", strconv.Itoa(1024 * 1024),
		"-jsonl", "-matcher-status",
		// Upstream clustering reports a shared request's non-match under a
		// synthetic cluster-<hash> ID. Run each admitted template on its own so
		// every record keeps the exact upstream ID the allowlist check expects.
		"-disable-clustering",
		"-no-httpx", "-no-interactsh", "-disable-redirects",
		"-no-stdin", "-disable-update-check",
		"-omit-raw", "-omit-template", "-silent", "-no-color",
	}
	if unit.Grant.TemplatePolicy.ProfileID != nil {
		// Pinned Nuclei automatic scan performs Wappalyzer and template-based
		// technology detection, then applies only matching templates. Both its
		// discovery pass and its applicable-template pass are still filtered by
		// the exact IDs and paths derived from the embedded safe pool above.
		arguments = append(arguments,
			"-automatic-scan",
			"-update-template-dir", automaticTemplateRoot,
		)
	}
	return invocation{
		Program: "/usr/local/bin/nuclei",
		Args:    arguments,
		// Matcher-status non-match records are written by Nuclei's standard
		// writer, not its reporting exporters. Capture that writer's JSONL
		// stdout directly: the pinned writer always terminates stdout records
		// with newlines, while its -o file writer does not.
		Env:        withoutEnvironmentVariable(environment, "DISABLE_STDOUT"),
		StdoutPath: output,
		Expiry:     unit.Grant.ExpiresAt,
		// Every admitted template is independently verified to declare at most
		// twenty read-only requests. Use that upper bound for the child deadline;
		// the reviewed engine ceiling remains the final cap.
		Timeout: totalTimeout,
	}, nil
}

func withoutEnvironmentVariable(environment []string, name string) []string {
	prefix := name + "="
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// Nuclei's upstream automatic scanner always prepends its configured template
// directory to the explicit -templates selection. Point that implicit source at
// a launcher-owned directory containing only one already validated member of
// the selected pool. The explicit path and ID files then add the rest of that
// same pool; no unvalidated template tree is available as a fallback.
func prepareNucleiAutomaticRoot(temporaryRoot string, index int, templatePaths []string) (string, error) {
	if len(templatePaths) == 0 {
		return "", errors.New("Nuclei automatic profile has no validated template anchor")
	}
	root := filepath.Join(temporaryRoot, fmt.Sprintf("automatic-templates-%06d", index))
	if err := os.Mkdir(root, 0o700); err != nil {
		return "", fmt.Errorf("create isolated Nuclei automatic template root: %w", err)
	}
	value, err := readBoundedRegularFile(templatePaths[0], maxTemplateBytes)
	if err != nil {
		return "", fmt.Errorf("read Nuclei automatic template anchor: %w", err)
	}
	anchor := filepath.Join(root, "validated-anchor.yaml")
	file, err := os.OpenFile(anchor, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create Nuclei automatic template anchor: %w", err)
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		_ = os.Remove(anchor)
		return "", fmt.Errorf("write Nuclei automatic template anchor: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(anchor)
		return "", fmt.Errorf("close Nuclei automatic template anchor: %w", err)
	}
	return root, nil
}

func targetURL(unit scanUnit) (string, error) {
	if unit.Port == 0 || (unit.Grant.Protocol != "http" && unit.Grant.Protocol != "https") {
		return "", errors.New("HTTP invocation has no exact protocol and port")
	}
	host := unit.Grant.Target.Value
	if unit.Grant.Target.Kind == "address" && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s://%s:%d", unit.Grant.Protocol, host, unit.Port), nil
}

func runCommand(plan invocation) error {
	remaining := time.Until(plan.Expiry)
	if remaining <= 0 {
		return errors.New("scope grant expired before scanner start")
	}
	timeout := plan.Timeout
	if remaining < timeout {
		timeout = remaining
	}
	commandContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, plan.Program, plan.Args...)
	command.Env = plan.Env
	command.Stdin = nil
	var stdout *os.File
	if plan.StdoutPath == "" {
		command.Stdout = io.Discard
	} else {
		var err error
		stdout, err = os.OpenFile(plan.StdoutPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create exclusive scanner stdout evidence: %w", err)
		}
		command.Stdout = stdout
	}
	stderr := &boundedBuffer{remaining: 64 * 1024}
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 2 * time.Second
	runErr := command.Run()
	if stdout != nil {
		if closeErr := stdout.Close(); runErr == nil && closeErr != nil {
			return fmt.Errorf("close scanner stdout evidence: %w", closeErr)
		}
	}
	if runErr != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return errScannerTimedOut
		}
		if errors.Is(runErr, exec.ErrNotFound) || errors.Is(runErr, os.ErrNotExist) {
			return errors.New("scanner executable is unavailable")
		}
		return fmt.Errorf("scanner exited unsuccessfully%s", sanitizedStderr(stderr.String()))
	}
	return nil
}

func runCommandForLauncherV2(plan invocation) launcherV2RunResult {
	err := runCommand(plan)
	if err == nil {
		return launcherV2RunResult{Outcome: launcherV2RunSucceeded}
	}
	if errors.Is(err, errScannerTimedOut) {
		return launcherV2RunResult{Outcome: launcherV2RunTimedOut, Err: err}
	}
	return launcherV2RunResult{Outcome: launcherV2RunFailed, Err: err}
}

func sanitizedStderr(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var cleaned strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\t' || (character >= 0x20 && character != 0x7f) {
			cleaned.WriteRune(character)
		}
		if cleaned.Len() >= 1024 {
			break
		}
	}
	return ": " + cleaned.String()
}

func normalizeEvidence(path string, destination *bufio.Writer, written *int64, engineID string, unit scanUnit) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open scanner evidence: %w", err)
	}
	defer file.Close()
	metadata, err := file.Stat()
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() > maxEvidenceBytes {
		return errors.New("scanner evidence is not a bounded regular file")
	}
	scanner := bufio.NewScanner(io.LimitReader(file, maxEvidenceBytes+1))
	scanner.Buffer(make([]byte, 64*1024), maxEvidenceLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(line, &object); err != nil || object == nil {
			return errors.New("scanner emitted malformed JSONL evidence")
		}
		if err := validateEvidenceObject(engineID, object, unit); err != nil {
			return err
		}
		assetValue, _ := json.Marshal(unit.AssetID)
		grantValue, _ := json.Marshal(unit.Grant.ID)
		targetValue, _ := json.Marshal(unit.Grant.Target.Value)
		object["asset_id"] = assetValue
		object["scope_grant_id"] = grantValue
		object["scope_target"] = targetValue
		for _, key := range []string{"request", "response", "template", "curl-command", "body", "raw"} {
			delete(object, key)
		}
		if engineID == "httpx" {
			for _, key := range []string{"host_ip", "a", "aaaa", "cname", "resolvers"} {
				delete(object, key)
			}
		}
		normalized, err := json.Marshal(object)
		if err != nil {
			return errors.New("scanner evidence could not be normalized")
		}
		normalized = append(normalized, '\n')
		if *written+int64(len(normalized)) > maxEvidenceBytes {
			return errors.New("normalized scanner evidence exceeds its aggregate limit")
		}
		if _, err := destination.Write(normalized); err != nil {
			return fmt.Errorf("write normalized evidence: %w", err)
		}
		*written += int64(len(normalized))
	}
	if err := scanner.Err(); err != nil {
		return errors.New("scanner evidence contains an overlong or unreadable record")
	}
	return nil
}

func validateEvidenceObject(engineID string, object map[string]json.RawMessage, unit scanUnit) error {
	if existing, ok := object["asset_id"]; ok {
		var assetID string
		if json.Unmarshal(existing, &assetID) != nil || assetID != unit.AssetID {
			return errors.New("scanner attempted to attribute evidence to another asset")
		}
	}
	switch engineID {
	case "naabu":
		port, err := jsonPort(object["port"])
		if err != nil || !containsPort(unit.Grant.Ports, port) {
			return errors.New("Naabu emitted a port outside its independent grant")
		}
		if protocol, ok := jsonString(object["protocol"]); ok && strings.ToLower(protocol) != "tcp" {
			return errors.New("Naabu emitted a non-TCP observation")
		}
		protocol, _ := json.Marshal("tcp")
		object["protocol"] = protocol
		observed, ok := firstJSONString(object, "host", "ip")
		if !ok || !observedFrozenAddressMatches(unit.ResolvedAddresses, observed) {
			return errors.New("Naabu evidence target is outside its independent grant")
		}
	case "httpx":
		observed, ok := firstJSONString(object, "url", "input")
		if !ok || validateObservedURL(observed, unit) != nil {
			return errors.New("httpx evidence target is outside its independent grant")
		}
	case "nuclei":
		id, ok := firstJSONString(object, "template-id", "template_id", "templateID")
		if !ok || !containsString(unit.Grant.TemplatePolicy.AllowedTemplateIDs, id) {
			return errors.New("Nuclei emitted a template outside the frozen allowlist")
		}
		observed, ok := firstJSONString(object, "matched-at", "matched_at", "url", "host")
		if !ok || validateObservedURL(observed, unit) != nil {
			return errors.New("Nuclei evidence target is outside its independent grant")
		}
	default:
		return errors.New("unsupported evidence profile")
	}
	return nil
}

func validateObservedURL(value string, unit scanUnit) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Scheme != unit.Grant.Protocol || parsed.Hostname() == "" {
		return errors.New("observed URL is malformed")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || uint16(parsedPort) != unit.Port || !observedTargetMatches(unit, parsed.Hostname()) {
		return errors.New("observed URL endpoint differs from its frozen target")
	}
	return nil
}

func observedFrozenAddressMatches(expected []string, observed string) bool {
	parsed := net.ParseIP(observed)
	return parsed != nil && parsed.String() == observed && containsString(expected, observed)
}

func observedTargetMatches(unit scanUnit, observed string) bool {
	target := unit.Grant.Target
	if parsed := net.ParseIP(observed); parsed != nil {
		canonical := parsed.String()
		if canonical != observed || !containsString(unit.ResolvedAddresses, canonical) {
			return false
		}
		switch target.Kind {
		case "address":
			return canonical == target.Value
		case "network":
			_, network, err := net.ParseCIDR(target.Value)
			return err == nil && network.Contains(parsed)
		case "hostname":
			return true
		default:
			return false
		}
	}
	switch target.Kind {
	case "hostname":
		return strings.EqualFold(strings.TrimSuffix(observed, "."), target.Value)
	case "address", "network":
		return false
	default:
		return false
	}
}

func verifyTemplateRevision(path string) error {
	value, err := readBoundedRegularFile(path, 256)
	if err != nil || strings.TrimSpace(string(value)) != templateRevision {
		return errors.New("embedded Nuclei template revision marker is absent or mismatched")
	}
	return nil
}

func loadTemplateIndex(root string) (map[string]string, error) {
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("embedded Nuclei template root is unavailable")
	}
	index := make(map[string]string)
	err = filepath.WalkDir(canonicalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("embedded Nuclei template tree contains a symlink")
		}
		if entry.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
			return nil
		}
		metadata, err := entry.Info()
		if err != nil || !metadata.Mode().IsRegular() {
			return errors.New("embedded Nuclei template is not a regular file")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		header, readErr := io.ReadAll(io.LimitReader(file, maxTemplateHeaderBytes))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return errors.New("embedded Nuclei template index could not be read")
		}
		id, err := extractTemplateID(header)
		if err != nil {
			if errors.Is(err, errTemplateIDAbsent) {
				return nil
			}
			return fmt.Errorf("index template %s: %w", filepath.Base(path), err)
		}
		if previous, exists := index[id]; exists && previous != path {
			return fmt.Errorf("embedded Nuclei template id %s is duplicated", id)
		}
		index[id] = path
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("build exact Nuclei template index: %w", err)
	}
	return index, nil
}

func extractTemplateID(value []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(value))
	scanner.Buffer(make([]byte, 4096), maxTemplateHeaderBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "id:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			id = strings.Trim(id, "\"'")
			if safeTemplateID(id) {
				return id, nil
			}
			return "", errors.New("template id is malformed")
		}
	}
	return "", errTemplateIDAbsent
}

func selectedTemplatePaths(policy templatePolicy, index map[string]string) ([]string, error) {
	_, paths, err := resolvedTemplateSelection(policy, index)
	return paths, err
}

func resolvedTemplateSelection(policy templatePolicy, index map[string]string) ([]string, []string, error) {
	if policy.ProfileID != nil {
		if *policy.ProfileID != nucleiWebSafeProfileID || len(policy.AllowedTemplateIDs) != 0 {
			return nil, nil, errors.New("Nuclei profile selection is unknown or mixed with explicit templates")
		}
		ids, paths := deriveNucleiWebSafeProfile(index)
		if len(ids) != nucleiWebSafeTemplateCount || len(ids) > maxNucleiProfileTemplates {
			return nil, nil, fmt.Errorf(
				"embedded Nuclei profile derived %d templates; pinned profile requires %d",
				len(ids), nucleiWebSafeTemplateCount,
			)
		}
		return ids, paths, nil
	}

	ids := append([]string(nil), policy.AllowedTemplateIDs...)
	paths := make([]string, 0, len(ids))
	for _, id := range ids {
		path, exists := index[id]
		if !exists {
			return nil, nil, fmt.Errorf("Nuclei template %s is not in the embedded exact revision", id)
		}
		if err := validateSafeTemplate(path, id); err != nil {
			return nil, nil, fmt.Errorf("Nuclei template %s is prohibited: %w", id, err)
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return ids, paths, nil
}

// deriveNucleiWebSafeProfile keeps product policy mechanical: the pinned
// upstream template snapshot owns detector coverage, while the launcher admits
// every template that fits the same bounded, unauthenticated, exact-origin
// read-only contract. A feed update therefore changes coverage without copying
// vendor or vulnerability selection into this adapter.
func deriveNucleiWebSafeProfile(index map[string]string) ([]string, []string) {
	candidates := make([]string, 0, len(index))
	for id := range index {
		candidates = append(candidates, id)
	}
	sort.Strings(candidates)
	ids := make([]string, 0, len(candidates))
	paths := make([]string, 0, len(candidates))
	for _, id := range candidates {
		path := index[id]
		if validateSafeTemplate(path, id) != nil {
			continue
		}
		ids = append(ids, id)
		paths = append(paths, path)
	}
	return ids, paths
}

func validateSafeTemplate(path, expectedID string) error {
	value, err := readBoundedRegularFile(path, maxTemplateBytes)
	if err != nil {
		return err
	}
	id, err := extractTemplateID(value)
	if err != nil || id != expectedID {
		return errors.New("template identity changed after indexing")
	}
	lower := strings.ToLower(string(value))
	for _, token := range []string{"{{interactsh", "interactsh_", "{{oast", "multipart/form-data", "{{file", "{{env", "race_count:"} {
		if strings.Contains(lower, token) {
			return fmt.Errorf("contains denied capability %q", token)
		}
	}
	deniedTopLevel := map[string]bool{"headless": true, "dns": true, "network": true, "file": true, "javascript": true, "code": true, "ssl": true, "websocket": true, "workflows": true, "flow": true, "self-contained": true}
	deniedTags := map[string]bool{
		"headless": true, "oast": true, "fuzz": true, "fuzzing": true,
		"dast": true, "dos": true, "intrusive": true, "bruteforce": true,
		"brute-force": true, "credential-stuffing": true, "default-login": true,
		"token-spray": true, "file-upload": true, "upload": true,
		// A GET transport is not read-only when its purpose is to make the
		// target execute commands or contact another system.
		"rce": true, "cmdi": true, "command-injection": true, "ssrf": true,
	}
	httpFound, methodFound, maxRequest := false, false, 0
	scanner := bufio.NewScanner(strings.NewReader(lower))
	scanner.Buffer(make([]byte, 64*1024), maxEvidenceLineBytes)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(raw) == len(strings.TrimLeft(raw, " \t")) {
			if separator := strings.IndexByte(trimmed, ':'); separator > 0 {
				key := strings.TrimSpace(trimmed[:separator])
				if deniedTopLevel[key] {
					return fmt.Errorf("uses denied top-level protocol %s", key)
				}
				if key == "http" {
					httpFound = true
				}
			}
		}
		withoutDash := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		for _, prefix := range []string{"payloads:", "attack:", "fuzzing:", "body:", "raw:"} {
			if strings.HasPrefix(withoutDash, prefix) {
				return fmt.Errorf("uses denied request primitive %s", strings.TrimSuffix(prefix, ":"))
			}
		}
		for _, prefix := range []string{"unsafe:", "race:", "iterate-all:", "cookie-reuse:"} {
			if strings.HasPrefix(withoutDash, prefix) && yamlBooleanTrue(strings.TrimSpace(strings.TrimPrefix(withoutDash, prefix))) {
				return fmt.Errorf("enables denied request behavior %s", strings.TrimSuffix(prefix, ":"))
			}
		}
		if strings.HasPrefix(withoutDash, "threads:") {
			return errors.New("sets template-local request concurrency")
		}
		if strings.HasPrefix(withoutDash, "method:") {
			method := strings.Trim(strings.TrimSpace(strings.TrimPrefix(withoutDash, "method:")), "\"'")
			if method != "get" && method != "head" {
				return fmt.Errorf("uses non-read-only HTTP method %s", method)
			}
			methodFound = true
		}
		if strings.HasPrefix(withoutDash, "redirects:") || strings.HasPrefix(withoutDash, "host-redirects:") {
			if yamlBooleanTrue(strings.TrimSpace(strings.SplitN(withoutDash, ":", 2)[1])) {
				return errors.New("enables redirects inside the template")
			}
		}
		if strings.HasPrefix(withoutDash, "max-request:") {
			value := strings.TrimSpace(strings.TrimPrefix(withoutDash, "max-request:"))
			maxRequest, _ = strconv.Atoi(value)
		}
		if strings.HasPrefix(withoutDash, "tags:") {
			for _, tag := range strings.Split(strings.TrimSpace(strings.TrimPrefix(withoutDash, "tags:")), ",") {
				if deniedTags[strings.Trim(strings.TrimSpace(tag), "[]\"'")] {
					return fmt.Errorf("contains denied template tag %s", tag)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("template contains an overlong YAML line")
	}
	if !httpFound || !methodFound || maxRequest < 1 || maxRequest > 20 {
		return errors.New("template is not bounded to GET/HEAD HTTP with max-request 1..20")
	}
	return validateTemplateRequestOrigins(value)
}

func yamlBooleanTrue(value string) bool {
	value = strings.TrimSpace(strings.SplitN(value, "#", 2)[0])
	value = strings.Trim(value, "\"'")
	return strings.EqualFold(value, "true")
}

// validateTemplateRequestOrigins rejects HTTP templates that can directly
// replace the reviewed origin. Relative paths and Nuclei's exact input-origin
// variables remain available; protocol-relative, static, userinfo-shaped, and
// variable-selected origins do not. Raw requests are rejected earlier.
func validateTemplateRequestOrigins(value []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(value))
	scanner.Buffer(make([]byte, 64*1024), maxEvidenceLineBytes)
	inHTTP := false
	pathIndent := -1
	pathCount := 0
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if indent == 0 {
			inHTTP = trimmed == "http:"
			pathIndent = -1
			continue
		}
		if !inHTTP {
			continue
		}
		if pathIndent >= 0 && indent <= pathIndent {
			pathIndent = -1
		}
		withoutDash := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if pathIndent < 0 && (withoutDash == "path:" || withoutDash == "paths:") {
			pathIndent = indent
			continue
		}
		if pathIndent < 0 || !strings.HasPrefix(trimmed, "-") {
			continue
		}
		pathValue, ok := yamlListScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")))
		if !ok || !sameOriginTemplatePath(pathValue) {
			return errors.New("template request path can replace the exact reviewed origin")
		}
		pathCount++
		if pathCount > maxNucleiRequestsPerTemplate {
			return errors.New("template declares more exact-origin paths than the request bound")
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.New("template contains an overlong YAML line")
	}
	if pathCount == 0 {
		return errors.New("template has no exact-origin HTTP request path")
	}
	return nil
}

func yamlListScalar(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		for index := 1; index < len(value); index++ {
			if value[index] != quote || (quote == '"' && index > 0 && value[index-1] == '\\') {
				continue
			}
			if quote == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				index++
				continue
			}
			return value[1:index], true
		}
		return "", false
	}
	if marker := strings.Index(value, " #"); marker >= 0 {
		value = value[:marker]
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func sameOriginTemplatePath(value string) bool {
	if strings.HasPrefix(value, "/") {
		return !strings.HasPrefix(value, "//")
	}
	for _, prefix := range []string{"{{BaseURL}}", "{{RootURL}}", "{{Scheme}}://{{Host}}", "{{Scheme}}://{{Hostname}}"} {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(value, prefix)
		return remainder == "" || strings.ContainsAny(remainder[:1], "/?#")
	}
	return false
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 || metadata.Size() > maximum {
		return nil, errors.New("file is absent, non-regular, symlinked, or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("file exceeds its read limit")
	}
	return value, nil
}

func validateOutputDirectory(path string) error {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 {
		return errors.New("output mount is not a regular directory")
	}
	return nil
}

func writeExclusiveLines(path string, lines []string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private scanner input: %w", err)
	}
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if line == "" || strings.ContainsAny(line, "\r\n\x00") {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("private scanner input contains an unsafe line")
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func safeText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func safeTemplateID(value string) bool {
	if !safeText(value, 256) || value == "*" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._:/-", character) {
			return false
		}
	}
	return true
}

func containsPort(values []uint16, expected uint16) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= expected })
	return index < len(values) && values[index] == expected
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func jsonString(value json.RawMessage) (string, bool) {
	var result string
	if value == nil || json.Unmarshal(value, &result) != nil || result == "" {
		return "", false
	}
	return result, true
}

func firstJSONString(object map[string]json.RawMessage, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := jsonString(object[key]); ok {
			return value, true
		}
	}
	return "", false
}

func jsonPort(value json.RawMessage) (uint16, error) {
	if value == nil {
		return 0, errors.New("port is absent")
	}
	var numeric uint16
	if json.Unmarshal(value, &numeric) == nil && numeric != 0 {
		return numeric, nil
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		parsed, err := strconv.ParseUint(text, 10, 16)
		return uint16(parsed), err
	}
	return 0, errors.New("port is malformed")
}
