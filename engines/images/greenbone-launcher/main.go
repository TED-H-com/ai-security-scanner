// ai-security-scanner-greenbone-launcher is the non-shell boundary around the
// product's bounded upstream-driven Greenbone profile. It accepts only immutable
// active-external grants, starts the unprivileged Rust openvasd scanner, and
// converts bounded API results to the released Greenbone XML adapter format.
//
// Network confinement does not rely on this process alone. The desktop runtime
// attaches the container only to an internal bridge. Per-grant loopback relays
// make TCP-only NASL checks functional through the bridge's exact SOCKS5
// gateway; any direct target connection remains unroutable by construction.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	engineID                 = "greenbone"
	scopeMountPath           = "/run/ai-security-scanner/scope.json"
	outputMountPath          = "/output"
	feedRootPath             = "/opt/greenbone/feed"
	feedMetadataPath         = feedRootPath + "/vt-metadata.json"
	notusRootPath            = "/opt/greenbone/notus"
	openvasdPath             = "/usr/local/bin/openvasd"
	feedRevision             = "a2e53c2e30f1fa5408369cb5cf99653a3e08e9df"
	templateRevision         = "greenbone-community-feed@" + feedRevision
	remoteSafeProfileID      = "greenbone_remote_safe_v1"
	tcpScannerOID            = "1.3.6.1.4.1.25623.1.0.10335"
	tcpScannerFilename       = "2011/openvas_tcp_scanner.nasl"
	openvasdAddress          = "127.0.0.1:3000"
	managedGatewayPort       = "1080"
	maxScopeBytes            = 4 * 1024 * 1024
	maxMetadataBytes         = 256 * 1024 * 1024
	maxAPIResponseBytes      = 512 * 1024 * 1024
	maxEvidenceBytes         = 512 * 1024 * 1024
	maxMessageBytes          = 1024 * 1024
	maxAssets                = 4096
	maxIdentifiers           = 128
	maxGrantsPerAsset        = 16
	maxSelectedVTsPerGrant   = 128
	maxSelectedVTsPerRun     = 512
	maxExplicitVTClosure     = 20000
	maxProfileDerivedVTs     = 100000
	maxProfileVTClosure      = 100000
	maxResultsPerRun         = 100000
	feedReadyTimeout         = 5 * time.Minute
	maximumScanDuration      = 2 * time.Hour
	openvasdShutdownTimeout  = 5 * time.Second
	defaultAPIRequestTimeout = 30 * time.Second
)

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
	AssetID string
	Grant   externalScope
}

type metadataReference struct {
	Class string `json:"class"`
	ID    string `json:"id"`
}

type metadataTag struct {
	CVSSBaseVector string `json:"cvss_base_vector"`
	SeverityVector string `json:"severity_vector"`
	QODType        string `json:"qod_type"`
	Summary        string `json:"summary"`
	Solution       string `json:"solution"`
	Deprecated     bool   `json:"deprecated"`
}

type vtMetadata struct {
	OID          string              `json:"oid"`
	Name         string              `json:"name"`
	Filename     string              `json:"filename"`
	Category     string              `json:"category"`
	Family       string              `json:"family"`
	Dependencies []string            `json:"dependencies"`
	References   []metadataReference `json:"references"`
	Tag          metadataTag         `json:"tag"`
}

type feedIndex struct {
	ByOID      map[string]vtMetadata
	ByFilename map[string]string
}

type scanRequest struct {
	Target          scanTarget       `json:"target"`
	ScanPreferences []scanPreference `json:"scan_preferences"`
	VTs             []scanVT         `json:"vts"`
}

type scanTarget struct {
	Hosts              []string   `json:"hosts"`
	Ports              []scanPort `json:"ports"`
	Credentials        []any      `json:"credentials"`
	AliveTestMethods   []string   `json:"alive_test_methods"`
	ReverseLookupUnify bool       `json:"reverse_lookup_unify"`
	ReverseLookupOnly  bool       `json:"reverse_lookup_only"`
}

type scanPort struct {
	Protocol string      `json:"protocol"`
	Range    []portRange `json:"range"`
}

type portRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type scanPreference struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type scanVT struct {
	OID string `json:"oid"`
}

type scanStatus struct {
	Status string `json:"status"`
}

type scanResult struct {
	ID        int          `json:"id"`
	Type      string       `json:"type"`
	IPAddress string       `json:"ip_address"`
	Hostname  string       `json:"hostname"`
	OID       string       `json:"oid"`
	Port      int          `json:"port"`
	Protocol  string       `json:"protocol"`
	Message   string       `json:"message"`
	Detail    resultDetail `json:"detail"`
}

type resultDetail struct {
	Name   string       `json:"name"`
	Value  string       `json:"value"`
	Source resultSource `json:"source"`
}

type resultSource struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type openvasdClient struct {
	client *http.Client
	key    string
}

type unitRelays struct {
	target          string
	byRelayPort     map[uint16]uint16
	byOriginalPort  map[uint16]uint16
	listeners       []net.Listener
	connections     map[net.Conn]struct{}
	connectionsLock sync.Mutex
	concurrency     chan struct{}
	rateLock        sync.Mutex
	nextDial        time.Time
	dialInterval    time.Duration
	cancel          context.CancelFunc
	wait            sync.WaitGroup
}

type boundedWriter struct {
	writer  io.Writer
	written int64
	limit   int64
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.limit-writer.written {
		return 0, errors.New("Greenbone XML exceeded its bounded evidence limit")
	}
	written, err := writer.writer.Write(value)
	writer.written += int64(written)
	return written, err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "Greenbone engine launcher: %v\n", err)
		if errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		os.Exit(126)
	}
}

func run(ctx context.Context, arguments []string, now time.Time) error {
	flags := flag.NewFlagSet("ai-security-scanner-greenbone-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectedEngine := flags.String("engine", "", "fixed engine identifier")
	scopePath := flags.String("scope", "", "immutable scope document")
	outputPath := flags.String("output", "", "evidence output directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if *selectedEngine != engineID {
		return errors.New("engine identifier is not allowlisted")
	}
	if *scopePath != scopeMountPath || *outputPath != outputMountPath {
		return errors.New("scope and output paths must use the runtime-owned mounts")
	}
	if err := validateOutputDirectory(*outputPath); err != nil {
		return err
	}
	gateway, err := managedProxy(os.Getenv("AI_SECURITY_SCANNER_PROXY"))
	if err != nil {
		return err
	}
	document, err := loadScope(*scopePath)
	if err != nil {
		return err
	}
	units, err := validateAndPlan(document, now)
	if err != nil {
		return err
	}
	index, err := loadFeedIndex(feedMetadataPath)
	if err != nil {
		return err
	}
	closures := make(map[string]map[string]struct{}, len(units))
	selections := make(map[string][]string, len(units))
	profileSelections := make(map[string][]string)
	profileClosures := make(map[string]map[string]struct{})
	for _, unit := range units {
		var selected []string
		var closure map[string]struct{}
		if unit.Grant.TemplatePolicy.ProfileID != nil {
			profileID := *unit.Grant.TemplatePolicy.ProfileID
			selected = profileSelections[profileID]
			closure = profileClosures[profileID]
		}
		if selected == nil || closure == nil {
			var err error
			selected, closure, err = index.resolveTemplateSelection(unit.Grant.TemplatePolicy)
			if err != nil {
				return fmt.Errorf("grant %s template selection: %w", unit.Grant.ID, err)
			}
			if unit.Grant.TemplatePolicy.ProfileID != nil {
				profileID := *unit.Grant.TemplatePolicy.ProfileID
				profileSelections[profileID] = selected
				profileClosures[profileID] = closure
			}
		}
		// openvasd accepts explicit OIDs rather than a profile or family
		// selector. Resolve the pinned product profile from the embedded feed,
		// then preserve the existing request path and upstream applicability
		// behavior for every selected VT.
		selections[unit.Grant.ID] = selected
		closures[unit.Grant.ID] = closure
	}

	temporaryRoot, err := os.MkdirTemp("/tmp", "ai-security-scanner-greenbone-")
	if err != nil {
		return fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		return fmt.Errorf("restrict private temporary directory: %w", err)
	}
	defer os.RemoveAll(temporaryRoot)
	apiKey, err := randomToken(32)
	if err != nil {
		return err
	}
	server, serverExit, err := startOpenvasd(temporaryRoot, apiKey)
	if err != nil {
		return err
	}
	defer stopOpenvasd(server, serverExit)
	api := newOpenvasdClient(apiKey)
	if err := api.waitReady(ctx, serverExit); err != nil {
		return err
	}

	finalPath := filepath.Join(*outputPath, "greenbone.xml")
	final, err := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive Greenbone evidence: %w", err)
	}
	complete := false
	defer func() {
		_ = final.Close()
		if !complete {
			_ = os.Remove(finalPath)
		}
	}()
	buffered := bufio.NewWriterSize(final, 64*1024)
	bounded := &boundedWriter{writer: buffered, limit: maxEvidenceBytes}
	if _, err := io.WriteString(bounded, `<?xml version="1.0" encoding="UTF-8"?><get_reports_response><report><results>`); err != nil {
		return err
	}
	resultCount := 0
	for _, unit := range units {
		if !time.Now().UTC().Before(unit.Grant.ExpiresAt) {
			return fmt.Errorf("scope grant %s expired before its independent scan", unit.Grant.ID)
		}
		relays, err := startUnitRelays(ctx, unit, gateway)
		if err != nil {
			return fmt.Errorf("grant %s managed SOCKS relays failed: %w", unit.Grant.ID, err)
		}
		results, scanErr := api.runUnit(ctx, unit, relays, selections[unit.Grant.ID])
		relays.Close()
		if scanErr != nil {
			return fmt.Errorf("grant %s scan failed: %w", unit.Grant.ID, scanErr)
		}
		for _, result := range results {
			// Ordinary, recognized host lifecycle records without an NVT identity
			// carry no scanner finding or feed evidence. All other result types
			// reach validateResult so missing identities and new upstream result
			// vocabulary fail closed instead of disappearing here.
			if !resultCarriesAdapterEvidence(result) {
				continue
			}
			if resultCount >= maxResultsPerRun {
				return errors.New("Greenbone result count exceeded its bounded limit")
			}
			if err := validateResult(result, unit, relays, closures[unit.Grant.ID], index); err != nil {
				return err
			}
			if err := writeXMLResult(bounded, os.Stderr, resultCount, result, unit, relays, index); err != nil {
				return err
			}
			resultCount++
		}
	}
	if _, err := io.WriteString(bounded, `</results></report></get_reports_response>`); err != nil {
		return err
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("flush Greenbone evidence: %w", err)
	}
	if err := final.Sync(); err != nil {
		return fmt.Errorf("sync Greenbone evidence: %w", err)
	}
	if err := final.Close(); err != nil {
		return fmt.Errorf("close Greenbone evidence: %w", err)
	}
	complete = true
	return nil
}

func loadScope(path string) (*scopeDocument, error) {
	value, err := readBoundedRegularFile(path, maxScopeBytes)
	if err != nil {
		return nil, fmt.Errorf("read immutable scope: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var document scopeDocument
	if err := decoder.Decode(&document); err != nil || requireJSONEOF(decoder) != nil {
		return nil, errors.New("scope document is malformed or has trailing data")
	}
	if document.SchemaVersion != "1" || document.EngineID != engineID || len(document.Assets) == 0 || len(document.Assets) > maxAssets {
		return nil, errors.New("scope document version, engine, or asset count is invalid")
	}
	return &document, nil
}

func validateAndPlan(document *scopeDocument, now time.Time) ([]scanUnit, error) {
	if document.GeneratedAt.IsZero() || document.GeneratedAt.After(now.Add(5*time.Minute)) {
		return nil, errors.New("scope document timestamp is invalid or future-dated")
	}
	seenAssets := make(map[string]struct{}, len(document.Assets))
	seenGrants := make(map[string]struct{})
	caseID := ""
	templateCount := 0
	units := make([]scanUnit, 0, len(document.Assets))
	for _, asset := range document.Assets {
		if !safeText(asset.ID, 256) || !safeText(asset.Name, 4096) || !supportedAssetKind(asset.Kind) {
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
			if grant.Permission != "active_external_testing" || grant.ExternalScope == nil {
				return nil, errors.New("scope contains a grant outside the active-external permission closure")
			}
			external := *grant.ExternalScope
			if err := validateGrant(asset, grant, external, now); err != nil {
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
			if external.TemplatePolicy.ProfileID == nil {
				templateCount += len(external.TemplatePolicy.AllowedTemplateIDs)
				if templateCount > maxSelectedVTsPerRun {
					return nil, errors.New("Greenbone template count exceeds the per-run bound")
				}
			}
			units = append(units, scanUnit{AssetID: asset.ID, Grant: external})
		}
	}
	sort.Slice(units, func(left, right int) bool {
		if units[left].AssetID != units[right].AssetID {
			return units[left].AssetID < units[right].AssetID
		}
		return units[left].Grant.ID < units[right].Grant.ID
	})
	return units, nil
}

func validateGrant(asset scopeAsset, grant scopeGrant, external externalScope, now time.Time) error {
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
	if external.Activity != "active_external" || !containsString([]string{"tcp", "tls", "http", "https"}, external.Protocol) {
		return errors.New("Greenbone requires an exact TCP-based active-external grant")
	}
	canonical, err := validateCanonicalTarget(external.Target)
	if err != nil {
		return err
	}
	if external.Target.Kind == "network" {
		return errors.New("the Greenbone profile does not expand network targets")
	}
	for _, item := range asset.Identifiers {
		if !safeText(item.Namespace, 256) || item.Value != canonical {
			return errors.New("asset identifiers are not closed over the canonical external target")
		}
	}
	if err := validatePorts(external.Ports); err != nil {
		return err
	}
	if external.RatePolicy.RequestsPerSecond == 0 || external.RatePolicy.RequestsPerSecond > 10 || external.RatePolicy.Concurrency == 0 || external.RatePolicy.Concurrency > 5 || external.RatePolicy.TimeoutSeconds == 0 || external.RatePolicy.TimeoutSeconds > 3600 {
		return errors.New("external rate, concurrency, or timeout exceeds the active-external class")
	}
	return validateTemplatePolicy(external.TemplatePolicy)
}

func validateTemplatePolicy(policy templatePolicy) error {
	if policy.AllowHeadless || policy.AllowOutOfBand || policy.AllowFuzzing || policy.AllowFileUpload || policy.AllowDenialOfService || policy.AllowCredentialAttacks {
		return errors.New("prohibited Greenbone template capability was enabled")
	}
	if policy.Revision != templateRevision {
		return errors.New("Greenbone policy does not match the embedded feed revision or bounded allowlist")
	}
	profileSelected := policy.ProfileID != nil
	explicitSelection := len(policy.AllowedTemplateIDs) != 0
	if profileSelected == explicitSelection {
		return errors.New("Greenbone policy requires exactly one profile or explicit OID allowlist")
	}
	if profileSelected {
		if *policy.ProfileID != remoteSafeProfileID {
			return errors.New("Greenbone policy profile is not allowlisted")
		}
		return nil
	}
	if len(policy.AllowedTemplateIDs) > maxSelectedVTsPerGrant {
		return errors.New("Greenbone policy does not match the embedded feed revision or bounded allowlist")
	}
	seen := make(map[string]struct{}, len(policy.AllowedTemplateIDs))
	for _, oid := range policy.AllowedTemplateIDs {
		if !validOID(oid) {
			return errors.New("Greenbone template allowlist contains an invalid exact OID")
		}
		if _, exists := seen[oid]; exists {
			return errors.New("Greenbone template allowlist contains a duplicate OID")
		}
		seen[oid] = struct{}{}
	}
	return nil
}

func supportedAssetKind(kind string) bool {
	return containsString([]string{"domain", "host", "ip_address", "web_service"}, kind)
}

func validateCanonicalTarget(target canonicalTarget) (string, error) {
	if !safeText(target.Value, 2048) || strings.Contains(target.Value, "*") {
		return "", errors.New("external target is empty, wildcarded, or malformed")
	}
	switch target.Kind {
	case "hostname":
		if target.Value != strings.ToLower(target.Value) || strings.HasSuffix(target.Value, ".") || len(target.Value) > 253 || !strings.Contains(target.Value, ".") {
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
	default:
		return "", errors.New("external target kind is unsupported")
	}
}

func validatePorts(ports []uint16) error {
	if len(ports) == 0 || len(ports) > 1024 {
		return errors.New("Greenbone requires a bounded non-empty port set")
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

func managedProxy(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5h" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != managedGatewayPort || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("managed SOCKS gateway endpoint is absent or malformed")
	}
	address := net.ParseIP(parsed.Hostname())
	if address == nil || address.To4() == nil {
		return nil, errors.New("Greenbone relay profile requires the frozen IPv4 bridge address")
	}
	parsed.Host = net.JoinHostPort(address.String(), managedGatewayPort)
	return parsed, nil
}

func loadFeedIndex(path string) (*feedIndex, error) {
	file, err := openBoundedRegularFile(path, maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("open exact Greenbone feed metadata: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxMetadataBytes+1))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errors.New("Greenbone feed metadata is malformed")
	}
	index := &feedIndex{ByOID: make(map[string]vtMetadata), ByFilename: make(map[string]string)}
	for decoder.More() {
		var item vtMetadata
		if err := decoder.Decode(&item); err != nil || !validOID(item.OID) || !safeRelativePath(item.Filename) || !safeText(item.Name, 4096) {
			return nil, errors.New("Greenbone feed metadata contains an invalid VT")
		}
		if _, exists := index.ByOID[item.OID]; exists {
			return nil, errors.New("Greenbone feed metadata contains a duplicate OID")
		}
		if _, exists := index.ByFilename[item.Filename]; exists {
			return nil, errors.New("Greenbone feed metadata contains a duplicate filename")
		}
		index.ByOID[item.OID] = item
		index.ByFilename[item.Filename] = item.OID
		if len(index.ByOID) > 200000 {
			return nil, errors.New("Greenbone feed metadata exceeds its VT count bound")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') || requireJSONEOF(decoder) != nil || len(index.ByOID) == 0 {
		return nil, errors.New("Greenbone feed metadata is incomplete or has trailing data")
	}
	return index, nil
}

func (index *feedIndex) resolveTemplateSelection(policy templatePolicy) ([]string, map[string]struct{}, error) {
	if err := validateTemplatePolicy(policy); err != nil {
		return nil, nil, err
	}
	if policy.ProfileID == nil {
		selected := append([]string(nil), policy.AllowedTemplateIDs...)
		closure, err := index.validateSafeSelection(selected)
		return selected, closure, err
	}
	if *policy.ProfileID != remoteSafeProfileID {
		return nil, nil, errors.New("Greenbone policy profile is not allowlisted")
	}
	selected, err := index.deriveRemoteSafeSelection(maxProfileDerivedVTs)
	if err != nil {
		return nil, nil, err
	}
	closure, err := index.validateSafeSelectionBounded(selected, maxProfileVTClosure)
	if err != nil {
		return nil, nil, err
	}
	return selected, closure, nil
}

func (index *feedIndex) deriveRemoteSafeSelection(maximum int) ([]string, error) {
	selected := make([]string, 0)
	for oid, item := range index.ByOID {
		if item.Category != "gather_info" || item.Tag.Deprecated || excludedRemoteSafeFamily(item.Family) {
			continue
		}
		selected = append(selected, oid)
		if len(selected) > maximum {
			return nil, errors.New("Greenbone remote-safe profile exceeds its derived VT bound")
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("Greenbone remote-safe profile is empty in the exact feed")
	}
	sort.Strings(selected)
	return selected, nil
}

func excludedRemoteSafeFamily(family string) bool {
	if strings.HasSuffix(family, " Local Security Checks") || strings.HasPrefix(family, "Nmap NSE") {
		return true
	}
	switch family {
	case "Brute force attacks", "Default Accounts", "Credentials", "Policy", "Compliance",
		"IT-Grundschutz", "IT-Grundschutz-10", "IT-Grundschutz-11", "Port scanners":
		return true
	default:
		return false
	}
}

func (index *feedIndex) validateSafeSelection(selected []string) (map[string]struct{}, error) {
	return index.validateSafeSelectionBounded(selected, maxExplicitVTClosure)
}

func (index *feedIndex) validateSafeSelectionBounded(selected []string, maximumClosure int) (map[string]struct{}, error) {
	closure := make(map[string]struct{})
	visiting := make(map[string]bool)
	var visit func(string, bool) error
	visit = func(oid string, directlySelected bool) error {
		if _, complete := closure[oid]; complete {
			return nil
		}
		if visiting[oid] {
			return errors.New("feed dependency graph contains a cycle")
		}
		item, exists := index.ByOID[oid]
		if !exists {
			return fmt.Errorf("OID %s is absent from the exact feed", oid)
		}
		if directlySelected && item.Category != "gather_info" {
			return fmt.Errorf("OID %s is category %s; the low-privilege profile permits only gather_info selections", oid, item.Category)
		}
		if !containsString([]string{"gather_info", "settings", "init", "scanner", "end"}, item.Category) {
			return fmt.Errorf("OID %s requires prohibited category %s", oid, item.Category)
		}
		visiting[oid] = true
		for _, filename := range item.Dependencies {
			dependencyOID, exists := index.ByFilename[filename]
			if !exists {
				return fmt.Errorf("OID %s has an unresolved dependency %s", oid, filename)
			}
			if err := visit(dependencyOID, false); err != nil {
				return err
			}
		}
		delete(visiting, oid)
		closure[oid] = struct{}{}
		if len(closure) > maximumClosure {
			return errors.New("Greenbone dependency closure exceeds its bound")
		}
		return nil
	}
	for _, oid := range selected {
		if err := visit(oid, true); err != nil {
			return nil, err
		}
	}
	// A feed selection is not a complete scan configuration by itself.
	// Greenbone scan configs normally include this connect()-based scanner as
	// a fixed prerequisite; without it the downstream gather-info scripts see
	// no Ports/tcp/* knowledge. Pin both its OID and filename so a future feed
	// cannot silently replace this low-privilege, non-raw-socket boundary.
	scanner, exists := index.ByOID[tcpScannerOID]
	if !exists || scanner.Filename != tcpScannerFilename || scanner.Category != "scanner" {
		return nil, errors.New("exact unprivileged TCP scanner prerequisite is absent from the feed")
	}
	if err := visit(tcpScannerOID, false); err != nil {
		return nil, err
	}
	return closure, nil
}

func startUnitRelays(parent context.Context, unit scanUnit, gateway *url.URL) (*unitRelays, error) {
	relayContext, cancel := context.WithDeadline(parent, unit.Grant.ExpiresAt)
	relays := &unitRelays{
		// Keep each original destination port visible to NASL. Greenbone's
		// service discovery and dependency graph use port semantics (for
		// example, issuing an HTTP probe on 8080). A separate loopback address
		// avoids the openvasd API on 127.0.0.1 while retaining those semantics.
		target:         "127.0.0.2",
		byRelayPort:    make(map[uint16]uint16, len(unit.Grant.Ports)),
		byOriginalPort: make(map[uint16]uint16, len(unit.Grant.Ports)),
		connections:    make(map[net.Conn]struct{}),
		concurrency:    make(chan struct{}, int(unit.Grant.RatePolicy.Concurrency)),
		dialInterval:   time.Second / time.Duration(unit.Grant.RatePolicy.RequestsPerSecond),
		cancel:         cancel,
	}
	for _, originalPort := range unit.Grant.Ports {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 2),
			Port: int(originalPort),
		})
		if err != nil {
			relays.Close()
			return nil, fmt.Errorf("bind exact loopback relay port %d: %w", originalPort, err)
		}
		relayPort := uint16(listener.Addr().(*net.TCPAddr).Port)
		if relayPort != originalPort {
			_ = listener.Close()
			relays.Close()
			return nil, errors.New("operating system changed an exact relay port")
		}
		if _, duplicate := relays.byRelayPort[relayPort]; duplicate {
			_ = listener.Close()
			relays.Close()
			return nil, errors.New("operating system assigned a duplicate relay port")
		}
		relays.byRelayPort[relayPort] = originalPort
		relays.byOriginalPort[originalPort] = relayPort
		relays.listeners = append(relays.listeners, listener)
		relays.wait.Add(1)
		go relays.serve(relayContext, listener, gateway, unit.Grant.Target, originalPort, unit.Grant.RatePolicy)
	}
	return relays, nil
}

func (relays *unitRelays) serve(ctx context.Context, listener net.Listener, gateway *url.URL, target canonicalTarget, port uint16, policy ratePolicy) {
	defer relays.wait.Done()
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		remote, ok := client.RemoteAddr().(*net.TCPAddr)
		if !ok || !remote.IP.IsLoopback() {
			_ = client.Close()
			continue
		}
		select {
		case relays.concurrency <- struct{}{}:
		case <-ctx.Done():
			_ = client.Close()
			return
		}
		relays.track(client)
		relays.wait.Add(1)
		go func() {
			defer relays.wait.Done()
			defer func() { <-relays.concurrency }()
			defer relays.closeTracked(client)
			if err := relays.waitForDial(ctx); err != nil {
				return
			}
			upstream, err := dialManagedSOCKS(ctx, gateway, target, port, time.Duration(policy.TimeoutSeconds)*time.Second)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Greenbone managed relay: exact SOCKS CONNECT for port %d failed: %v\n", port, err)
				return
			}
			relays.track(upstream)
			defer relays.closeTracked(upstream)
			relayBidirectional(ctx, client, upstream)
		}()
	}
}

func (relays *unitRelays) waitForDial(ctx context.Context) error {
	relays.rateLock.Lock()
	now := time.Now()
	reserved := now
	if relays.nextDial.After(reserved) {
		reserved = relays.nextDial
	}
	relays.nextDial = reserved.Add(relays.dialInterval)
	relays.rateLock.Unlock()
	wait := time.Until(reserved)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (relays *unitRelays) track(connection net.Conn) {
	relays.connectionsLock.Lock()
	relays.connections[connection] = struct{}{}
	relays.connectionsLock.Unlock()
}

func (relays *unitRelays) closeTracked(connection net.Conn) {
	relays.connectionsLock.Lock()
	delete(relays.connections, connection)
	relays.connectionsLock.Unlock()
	_ = connection.Close()
}

func (relays *unitRelays) Close() {
	if relays == nil || relays.cancel == nil {
		return
	}
	relays.cancel()
	for _, listener := range relays.listeners {
		_ = listener.Close()
	}
	relays.connectionsLock.Lock()
	for connection := range relays.connections {
		_ = connection.Close()
	}
	relays.connectionsLock.Unlock()
	relays.wait.Wait()
	relays.cancel = nil
}

func dialManagedSOCKS(ctx context.Context, gateway *url.URL, target canonicalTarget, port uint16, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp4", gateway.Host)
	if err != nil {
		return nil, errors.New("connect to exact managed SOCKS gateway")
	}
	fail := func(message string) (net.Conn, error) {
		_ = connection.Close()
		return nil, errors.New(message)
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fail("set managed SOCKS handshake deadline")
	}
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return fail("write managed SOCKS greeting")
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 5 || response[1] != 0 {
		return fail("managed SOCKS gateway rejected authentication")
	}
	request := []byte{5, 1, 0}
	switch target.Kind {
	case "hostname":
		if len(target.Value) > 253 {
			return fail("managed SOCKS hostname is oversized")
		}
		request = append(request, 3, byte(len(target.Value)))
		request = append(request, target.Value...)
	case "address":
		address := net.ParseIP(target.Value)
		if address == nil {
			return fail("managed SOCKS address is malformed")
		}
		if ipv4 := address.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, address.To16()...)
		}
	default:
		return fail("managed SOCKS target kind is unsupported")
	}
	request = append(request, byte(port>>8), byte(port))
	if _, err := connection.Write(request); err != nil {
		return fail("write exact managed SOCKS CONNECT")
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return fail("managed SOCKS gateway denied the frozen destination")
	}
	addressBytes := 0
	switch header[3] {
	case 1:
		addressBytes = 4
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil || length[0] == 0 {
			return fail("managed SOCKS gateway returned a malformed hostname")
		}
		addressBytes = int(length[0])
	case 4:
		addressBytes = 16
	default:
		return fail("managed SOCKS gateway returned an unknown address type")
	}
	bound := make([]byte, addressBytes+2)
	if _, err := io.ReadFull(connection, bound); err != nil {
		return fail("read managed SOCKS CONNECT response")
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fail("clear managed SOCKS handshake deadline")
	}
	return connection, nil
}

func relayBidirectional(ctx context.Context, client, upstream net.Conn) {
	completed := make(chan struct{}, 2)
	copyOneWay := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		completed <- struct{}{}
	}
	go copyOneWay(upstream, client)
	go copyOneWay(client, upstream)
	select {
	case <-ctx.Done():
	case <-completed:
	}
	_ = client.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	select {
	case <-completed:
	case <-time.After(time.Second):
	}
}

func startOpenvasd(temporaryRoot, apiKey string) (*exec.Cmd, <-chan error, error) {
	for _, path := range []string{openvasdPath, feedMetadataPath} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("required Greenbone runtime input is unavailable: %s", path)
		}
	}
	command := exec.Command(openvasdPath,
		"--scanner-type", "openvasd",
		// Upstream's inmemory mode now uses a SQLite database in /dev/shm.
		// Keep that transient database inside the task's bounded /tmp mount.
		"--storage-type", "fs",
		"--storage-path", filepath.Join(temporaryRoot, "openvasd.db"),
		"--feed-path", feedRootPath,
		"--lock-file-dir", temporaryRoot,
		"--advisories", filepath.Join(notusRootPath, "advisories"),
		"--products", filepath.Join(notusRootPath, "products"),
		"--listening", openvasdAddress,
		"--feed-check-interval", "86400",
		"--max-running-scans", "1",
		"--max-queued-scans", "1",
		"--check_interval", "1",
		"--api-key", apiKey,
		"--log-level", "WARN",
		"--feed-signature-check",
	)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + temporaryRoot,
		"TMPDIR=" + temporaryRoot,
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, nil, fmt.Errorf("start unprivileged openvasd: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	return command, exited, nil
}

func stopOpenvasd(command *exec.Cmd, exited <-chan error) {
	stopProcessGroup(command, exited, openvasdShutdownTimeout, syscall.Kill)
}

func stopProcessGroup(command *exec.Cmd, exited <-chan error, shutdownTimeout time.Duration, signalGroup func(int, syscall.Signal) error) {
	if command == nil || command.Process == nil {
		return
	}
	processGroupID := -command.Process.Pid
	_ = signalGroup(processGroupID, syscall.SIGTERM)
	select {
	case <-exited:
		return
	case <-time.After(shutdownTimeout):
		_ = signalGroup(processGroupID, syscall.SIGKILL)
		<-exited
	}
}

func newOpenvasdClient(key string) *openvasdClient {
	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   false,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &openvasdClient{client: &http.Client{Transport: transport, Timeout: defaultAPIRequestTimeout}, key: key}
}

func (api *openvasdClient) waitReady(ctx context.Context, serverExit <-chan error) error {
	readyContext, cancel := context.WithTimeout(ctx, feedReadyTimeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		// GET /vts is deliberately used as the readiness barrier: openvasd
		// returns 503 until both the signed NASL and advisory feeds are ready.
		// HEAD can succeed before the feed synchronization has completed.
		status, err := api.request(readyContext, http.MethodGet, "/vts", nil, nil)
		if err == nil && status == http.StatusOK {
			return nil
		}
		select {
		case <-readyContext.Done():
			return fmt.Errorf("Greenbone signed feed did not become ready: %w", readyContext.Err())
		case serverError := <-serverExit:
			return fmt.Errorf("openvasd exited before feed readiness: %v", serverError)
		case <-ticker.C:
		}
	}
}

func (api *openvasdClient) runUnit(ctx context.Context, unit scanUnit, relays *unitRelays, selected []string) ([]scanResult, error) {
	remaining := time.Until(unit.Grant.ExpiresAt)
	if remaining <= 0 {
		return nil, errors.New("grant expired")
	}
	if remaining > maximumScanDuration {
		remaining = maximumScanDuration
	}
	scanContext, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	request := buildScanRequest(unit, relays, selected)
	var scanID string
	status, err := api.request(scanContext, http.MethodPost, "/scans", request, &scanID)
	if err != nil || status != http.StatusCreated || !validUUID(scanID) {
		return nil, fmt.Errorf("create bounded scan: HTTP %d: %w", status, err)
	}
	started := false
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if started && scanContext.Err() != nil {
			_, _ = api.request(cleanupContext, http.MethodPost, "/scans/"+scanID, map[string]string{"action": "stop"}, nil)
		}
		_, _ = api.request(cleanupContext, http.MethodDelete, "/scans/"+scanID, nil, nil)
	}()
	status, err = api.request(scanContext, http.MethodPost, "/scans/"+scanID, map[string]string{"action": "start"}, nil)
	if err != nil || status != http.StatusNoContent {
		return nil, fmt.Errorf("start bounded scan: HTTP %d: %w", status, err)
	}
	started = true
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var state scanStatus
		status, err = api.request(scanContext, http.MethodGet, "/scans/"+scanID+"/status", nil, &state)
		if err != nil || status != http.StatusOK {
			return nil, fmt.Errorf("poll bounded scan: HTTP %d: %w", status, err)
		}
		switch state.Status {
		case "succeeded":
			return api.results(scanContext, scanID)
		case "failed", "stopped":
			return nil, fmt.Errorf("openvasd ended in %s state", state.Status)
		case "stored", "requested", "running":
		default:
			return nil, errors.New("openvasd returned an unknown scan state")
		}
		select {
		case <-scanContext.Done():
			return nil, scanContext.Err()
		case <-ticker.C:
		}
	}
}

func buildScanRequest(unit scanUnit, relays *unitRelays, selected []string) scanRequest {
	relayPorts := make([]int, 0, len(relays.byRelayPort))
	for port := range relays.byRelayPort {
		relayPorts = append(relayPorts, int(port))
	}
	sort.Ints(relayPorts)
	ranges := make([]portRange, 0, len(relayPorts))
	for _, value := range relayPorts {
		port := uint16(value)
		ranges = append(ranges, portRange{Start: port, End: port})
	}
	requestOIDs := append([]string(nil), selected...)
	requestOIDs = append(requestOIDs, tcpScannerOID)
	sort.Strings(requestOIDs)
	vts := make([]scanVT, 0, len(requestOIDs))
	for _, oid := range requestOIDs {
		vts = append(vts, scanVT{OID: oid})
	}
	requestDelay := int(math.Ceil(1000.0 / float64(unit.Grant.RatePolicy.RequestsPerSecond)))
	timeout := strconv.FormatUint(uint64(unit.Grant.RatePolicy.TimeoutSeconds), 10)
	preferences := []scanPreference{
		{ID: "auto_enable_dependencies", Value: "yes"},
		{ID: "safe_checks", Value: "yes"},
		{ID: "max_hosts", Value: "1"},
		{ID: "max_checks", Value: strconv.FormatUint(uint64(unit.Grant.RatePolicy.Concurrency), 10)},
		{ID: "checks_read_timeout", Value: timeout},
		{ID: "open_sock_max_attempts", Value: "1"},
		{ID: "timeout_retry", Value: "0"},
		{ID: "optimize_test", Value: "yes"},
		// Keep the grant's per-request timeout on network reads only. Greenbone's
		// plugins_timeout preferences bound an entire VT lifetime, so reusing this
		// value there would terminate legitimate upstream checks prematurely. The
		// pinned scanner defaults apply instead, inside runUnit's bounded context.
		{ID: "time_between_request", Value: strconv.Itoa(requestDelay)},
		{ID: "unscanned_closed", Value: "yes"},
		{ID: "unscanned_closed_udp", Value: "yes"},
		{ID: "expand_vhosts", Value: "no"},
		{ID: "test_empty_vhost", Value: "no"},
		{ID: "test_alive_hosts_only", Value: "no"},
		{ID: "table_driven_lsc", Value: "no"},
		{ID: "dry_run", Value: "no"},
		{ID: "max_mem_kb", Value: "128"},
	}
	return scanRequest{
		Target: scanTarget{
			Hosts:              []string{relays.target},
			Ports:              []scanPort{{Protocol: "tcp", Range: ranges}},
			Credentials:        []any{},
			AliveTestMethods:   []string{"consider_alive"},
			ReverseLookupUnify: false,
			ReverseLookupOnly:  false,
		},
		ScanPreferences: preferences,
		VTs:             vts,
	}
}

func (api *openvasdClient) results(ctx context.Context, scanID string) ([]scanResult, error) {
	var raw json.RawMessage
	status, err := api.request(ctx, http.MethodGet, "/scans/"+scanID+"/results", nil, &raw)
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("retrieve bounded scan results: HTTP %d: %w", status, err)
	}
	var results []scanResult
	if err := json.Unmarshal(raw, &results); err == nil {
		if len(results) > maxResultsPerRun {
			return nil, errors.New("openvasd result count exceeds its bound")
		}
		return results, nil
	}
	var envelope struct {
		Items *[]scanResult `json:"items"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Items == nil || len(*envelope.Items) > maxResultsPerRun {
		return nil, errors.New("openvasd returned malformed or oversized results")
	}
	return *envelope.Items, nil
}

func (api *openvasdClient) request(ctx context.Context, method, path string, body any, output any) (int, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return 0, errors.New("invalid local API path")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+openvasdAddress+path, reader)
	if err != nil {
		return 0, err
	}
	request.Header.Set("X-API-KEY", api.key)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := api.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	value, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponseBytes+1))
	if err != nil {
		return response.StatusCode, err
	}
	if len(value) > maxAPIResponseBytes {
		return response.StatusCode, errors.New("openvasd API response exceeded its bound")
	}
	if response.StatusCode >= 400 {
		return response.StatusCode, fmt.Errorf("openvasd rejected the request")
	}
	if output != nil && len(value) > 0 {
		if raw, ok := output.(*json.RawMessage); ok {
			*raw = append((*raw)[:0], value...)
		} else if err := json.Unmarshal(value, output); err != nil {
			return response.StatusCode, errors.New("openvasd API response was malformed")
		}
	}
	return response.StatusCode, nil
}

func validateResult(result scanResult, unit scanUnit, relays *unitRelays, closure map[string]struct{}, index *feedIndex) error {
	if result.ID < 0 || !containsString([]string{"alarm", "log", "error", "host_start", "host_end", "host_stop", "dead_host", "host_detail"}, result.Type) {
		return errors.New("openvasd returned an invalid result identity or type")
	}
	if len(result.Message) > maxMessageBytes {
		return errors.New("openvasd returned an oversized result message")
	}
	if result.IPAddress != "" && result.IPAddress != relays.target {
		return errors.New("openvasd result escaped the loopback relay target")
	}
	if (result.Type == "dead_host" || result.Type == "error") && result.OID == "" {
		return nil
	}
	if result.OID == "" || !validOID(result.OID) {
		return errors.New("openvasd returned a result without a valid NVT identity")
	}
	metadata, exists := index.ByOID[result.OID]
	if !exists {
		return errors.New("openvasd result OID is absent from the exact feed")
	}
	if !containsString([]string{"gather_info", "settings", "init", "scanner", "end"}, metadata.Category) {
		return fmt.Errorf("openvasd result OID %s has prohibited category %s", result.OID, metadata.Category)
	}
	if result.Type == "alarm" {
		if _, exists := closure[result.OID]; !exists {
			return fmt.Errorf("openvasd alarm OID %s escaped the validated template closure", result.OID)
		}
		if result.Port <= 0 || result.Port > 65535 || relays.byRelayPort[uint16(result.Port)] == 0 || result.Protocol != "tcp" {
			return fmt.Errorf("openvasd alarm escaped the exact OID, TCP, or port closure (oid=%s port=%d protocol=%q)", result.OID, result.Port, result.Protocol)
		}
	}
	return nil
}

func resultCarriesAdapterEvidence(result scanResult) bool {
	if result.OID != "" || result.Type == "dead_host" || result.Type == "error" {
		return true
	}
	return !containsString([]string{"log", "host_start", "host_end", "host_stop", "host_detail"}, result.Type)
}

func writeXMLResult(writer io.Writer, warnings io.Writer, indexNumber int, result scanResult, unit scanUnit, relays *unitRelays, feed *feedIndex) error {
	metadata := feed.ByOID[result.OID]
	name := metadata.Name
	if name == "" {
		name = "Greenbone " + result.Type
	}
	severity := 0.0
	threat := "Log"
	if result.Type == "alarm" {
		// Alarm is the authoritative upstream result type. A missing, newer, or
		// otherwise unparseable feed vector leaves severity unrated; it must not
		// turn the vulnerability result into a benign log record.
		threat = "Unknown"
		severity = cvssBaseScore(metadata.Tag.SeverityVector)
		if severity == 0 {
			severity = cvss2BaseScore(metadata.Tag.CVSSBaseVector)
		}
		if severity > 0 {
			threat = threatForScore(severity)
		}
	}
	qod, hasQOD := qodForType(metadata.Tag.QODType)
	if !hasQOD && metadata.Tag.QODType != "" {
		_, _ = fmt.Fprintf(warnings, "Greenbone engine launcher warning: unrecognized QoD type %s; detection quality was omitted\n", metadata.Tag.QODType)
	}
	relayPort := result.Port
	port := 0
	if relayPort > 0 && relayPort <= 65535 {
		port = int(relays.byRelayPort[uint16(relayPort)])
	}
	resultID := fmt.Sprintf("%s-%06d-%06d", unit.Grant.ID, indexNumber, result.ID)
	if _, err := fmt.Fprintf(writer, `<result id="%s">`, xmlEscape(resultID)); err != nil {
		return err
	}
	fields := [][2]string{
		{"name", name},
		{"host", unit.Grant.Target.Value},
		{"port", fmt.Sprintf("%d/tcp", port)},
		{"result_type", result.Type},
		{"severity", strconv.FormatFloat(severity, 'f', 1, 64)},
		{"threat", threat},
		{"asset_id", unit.AssetID},
		// Summary and solution come from the exact pinned Greenbone feed entry,
		// while description is the scan result message and may contain target
		// material. Keeping them as separate XML fields lets the adapter expose
		// upstream rule guidance without presenting target-controlled evidence as
		// remediation.
		{"summary", boundedText(metadata.Tag.Summary, 64*1024)},
		{"description", boundedText(result.Message, maxMessageBytes)},
		{"solution", boundedText(metadata.Tag.Solution, 64*1024)},
		{"raw_host", result.IPAddress},
		{"raw_port", fmt.Sprintf("%d/tcp", relayPort)},
		{"relay_mapping", fmt.Sprintf("managed-socks5:%s:%d -> %s:%d", relays.target, relayPort, unit.Grant.Target.Value, port)},
		{"scope_grant_id", unit.Grant.ID},
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(writer, "<%s>%s</%s>", field[0], xmlEscape(field[1]), field[0]); err != nil {
			return err
		}
	}
	if result.OID == "" {
		_, err := io.WriteString(writer, "</result>")
		return err
	}
	if hasQOD {
		if _, err := fmt.Fprintf(writer, "<qod><value>%d</value></qod>", qod); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "<nvt oid=\"%s\"><name>%s</name><family>%s</family><refs>", xmlEscape(result.OID), xmlEscape(name), xmlEscape(metadata.Family)); err != nil {
		return err
	}
	seen := make(map[string]struct{})
	for _, reference := range metadata.References {
		if strings.EqualFold(reference.Class, "cve") && validCVE(reference.ID) {
			if _, exists := seen[reference.ID]; exists {
				continue
			}
			seen[reference.ID] = struct{}{}
			if len(seen) > 32 {
				break
			}
			if _, err := fmt.Fprintf(writer, `<ref type="cve" id="%s"/>`, xmlEscape(strings.ToUpper(reference.ID))); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(writer, "</refs></nvt></result>")
	return err
}

func cvssBaseScore(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0
	}
	metrics := parseVector(vector)
	av := mapValue(metrics["AV"], map[string]float64{"N": .85, "A": .62, "L": .55, "P": .2})
	ac := mapValue(metrics["AC"], map[string]float64{"L": .77, "H": .44})
	ui := mapValue(metrics["UI"], map[string]float64{"N": .85, "R": .62})
	scope := metrics["S"]
	prValues := map[string]float64{"N": .85, "L": .62, "H": .27}
	if scope == "C" {
		prValues = map[string]float64{"N": .85, "L": .68, "H": .5}
	}
	pr := mapValue(metrics["PR"], prValues)
	c := mapValue(metrics["C"], map[string]float64{"H": .56, "L": .22, "N": 0})
	i := mapValue(metrics["I"], map[string]float64{"H": .56, "L": .22, "N": 0})
	a := mapValue(metrics["A"], map[string]float64{"H": .56, "L": .22, "N": 0})
	if av < 0 || ac < 0 || ui < 0 || pr < 0 || c < 0 || i < 0 || a < 0 || (scope != "U" && scope != "C") {
		return 0
	}
	impactSubscore := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * impactSubscore
	if scope == "C" {
		impact = 7.52*(impactSubscore-.029) - 3.25*math.Pow(impactSubscore-.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	score := impact + exploitability
	if scope == "C" {
		score *= 1.08
	}
	if score > 10 {
		score = 10
	}
	return math.Ceil(score*10) / 10
}

func cvss2BaseScore(vector string) float64 {
	metrics := parseVector(vector)
	av := mapValue(metrics["AV"], map[string]float64{"L": .395, "A": .646, "N": 1})
	ac := mapValue(metrics["AC"], map[string]float64{"H": .35, "M": .61, "L": .71})
	au := mapValue(metrics["AU"], map[string]float64{"M": .45, "S": .56, "N": .704})
	c := mapValue(metrics["C"], map[string]float64{"N": 0, "P": .275, "C": .66})
	i := mapValue(metrics["I"], map[string]float64{"N": 0, "P": .275, "C": .66})
	a := mapValue(metrics["A"], map[string]float64{"N": 0, "P": .275, "C": .66})
	if av < 0 || ac < 0 || au < 0 || c < 0 || i < 0 || a < 0 {
		return 0
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	if impact == 0 {
		return 0
	}
	exploitability := 20 * av * ac * au
	score := ((.6 * impact) + (.4 * exploitability) - 1.5) * 1.176
	return math.Round(score*10) / 10
}

func parseVector(vector string) map[string]string {
	metrics := make(map[string]string)
	for _, component := range strings.Split(vector, "/") {
		parts := strings.SplitN(strings.ToUpper(component), ":", 2)
		if len(parts) == 2 {
			metrics[parts[0]] = parts[1]
		}
	}
	return metrics
}

func mapValue(key string, values map[string]float64) float64 {
	value, exists := values[key]
	if !exists {
		return -1
	}
	return value
}

func threatForScore(score float64) string {
	switch {
	case score >= 9:
		return "Critical"
	case score >= 7:
		return "High"
	case score >= 4:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Log"
	}
}

func qodForType(value string) (int, bool) {
	switch value {
	case "exploit":
		return 100, true
	case "remote_vul":
		return 99, true
	case "remote_active":
		return 95, true
	case "package":
		return 97, true
	case "remote_banner":
		return 80, true
	case "remote_banner_unreliable":
		return 30, true
	default:
		return 0, false
	}
}

func validateOutputDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output mount is not a real directory")
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	file, err := openBoundedRegularFile(path, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("file is unreadable or oversized")
	}
	return value, nil
}

func openBoundedRegularFile(path string, maximum int64) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("path is not a bounded regular file")
	}
	return os.Open(path)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func randomToken(byteLength int) (string, error) {
	value := make([]byte, byteLength)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("operating-system random source failed")
	}
	return hex.EncodeToString(value), nil
}

func safeText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}

func boundedText(value string, maximum int) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}

func safeRelativePath(value string) bool {
	return safeText(value, 4096) && !filepath.IsAbs(value) && filepath.Clean(value) == value && value != "." && !strings.HasPrefix(value, "..")
}

func validOID(value string) bool {
	if len(value) < 3 || len(value) > 128 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, segment := range strings.Split(value, ".") {
		if segment == "" {
			return false
		}
		for _, character := range segment {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validCVE(value string) bool {
	parts := strings.Split(strings.ToUpper(value), "-")
	if len(parts) != 3 || parts[0] != "CVE" || len(parts[1]) != 4 || len(parts[2]) < 4 || len(parts[2]) > 12 {
		return false
	}
	for _, value := range parts[1:] {
		for _, character := range value {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
		} else if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsPort(values []uint16, expected uint16) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= expected })
	return index < len(values) && values[index] == expected
}

func xmlEscape(value string) string {
	var output strings.Builder
	_ = xml.EscapeText(&output, []byte(value))
	return output.String()
}
