package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureDocument(engineID string, now time.Time) *scopeDocument {
	permission := "low_impact_external_connection"
	activity := "low_impact_external"
	template := templatePolicy{Revision: "not_applicable"}
	kind := "web_service"
	if engineID == "naabu" {
		kind = "host"
	}
	if engineID == "nuclei" {
		permission = "active_external_testing"
		activity = "active_external"
		template = templatePolicy{
			Revision:           "nuclei-templates@" + templateRevision,
			AllowedTemplateIDs: []string{"safe-template"},
		}
	}
	makeAsset := func(assetID, grantID, target string, ports []uint16) scopeAsset {
		approved := now.Add(-time.Minute)
		expires := now.Add(time.Hour)
		resolvedAddress := "192.0.2.10"
		if assetID == "asset-b" {
			resolvedAddress = "192.0.2.20"
		}
		return scopeAsset{
			ID: assetID, Name: target, Kind: kind,
			Identifiers: []identifier{{Namespace: "dns:name", Value: target}},
			Grants: []scopeGrant{{
				ID: grantID, Permission: permission, ConfirmedBy: "owner@example.test",
				ConfirmedAt: approved, ExpiresAt: &expires,
				AuthorizationReference: stringPointer("ticket SEC-1042"),
				ResolvedAddresses:      []string{resolvedAddress},
				ExternalScope: &externalScope{
					ID: grantID, CaseID: "case-1", AssetID: assetID,
					Target: canonicalTarget{Kind: "hostname", Value: target}, Ports: ports,
					Protocol: "https", Activity: activity,
					RatePolicy:     ratePolicy{RequestsPerSecond: 2, Concurrency: 2, TimeoutSeconds: 30},
					TemplatePolicy: template, AssertedAuthority: "ticket SEC-1042",
					ApprovedBy: "owner@example.test", ApprovedAt: approved, ExpiresAt: expires,
				},
			}},
		}
	}
	return &scopeDocument{
		SchemaVersion: "2", EngineID: engineID, GeneratedAt: now,
		Assets: []scopeAsset{
			makeAsset("asset-a", "grant-a", "a.example.test", []uint16{443, 8443}),
			makeAsset("asset-b", "grant-b", "b.example.test", []uint16{9443}),
		},
	}
}

func stringPointer(value string) *string { return &value }

func testNaabuInvocation(t *testing.T, unit scanUnit, environment []string) invocation {
	t.Helper()
	plan, err := naabuInvocation(
		unit,
		"172.30.0.1:1080",
		filepath.Join(t.TempDir(), "naabu.jsonl"),
		environment,
		t.TempDir(),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPlansEachGrantWithoutTargetPortCrossProduct(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	httpUnits, err := validateAndPlan(fixtureDocument("httpx", now), "httpx", now)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(httpUnits))
	for _, unit := range httpUnits {
		got = append(got, unit.Grant.Target.Value+":"+portText(unit.Port))
	}
	want := []string{"a.example.test:443", "a.example.test:8443", "b.example.test:9443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("grant-local plans differ: got %v want %v", got, want)
	}

	naabuUnits, err := validateAndPlan(fixtureDocument("naabu", now), "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(naabuUnits) != 2 || !reflect.DeepEqual(naabuUnits[0].ResolvedAddresses, []string{"192.0.2.10"}) || !reflect.DeepEqual(naabuUnits[0].Grant.Ports, []uint16{443, 8443}) || !reflect.DeepEqual(naabuUnits[1].ResolvedAddresses, []string{"192.0.2.20"}) || !reflect.DeepEqual(naabuUnits[1].Grant.Ports, []uint16{9443}) {
		t.Fatalf("Naabu grants were combined: %#v", naabuUnits)
	}
}

func TestNaabuPlansEveryHostSideFrozenAddressWithoutDNS(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	document := fixtureDocument("naabu", now)
	document.Assets[0].Grants[0].ResolvedAddresses = []string{"192.0.2.10", "2001:db8::10"}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(units))
	for _, unit := range units {
		got = append(got, unit.Grant.Target.Value+"="+strings.Join(unit.ResolvedAddresses, ","))
	}
	want := []string{
		"a.example.test=192.0.2.10,2001:db8::10",
		"b.example.test=192.0.2.20",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Naabu did not preserve the exact frozen hostname mapping: got %v want %v", got, want)
	}
}

func TestNaabuAcceptsDomainAssetsAndScansOnlyFrozenAddresses(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	document := fixtureDocument("naabu", now)
	document.Assets[0].Kind = "domain"
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	if units[0].Grant.Target.Kind != "hostname" || !reflect.DeepEqual(units[0].ResolvedAddresses, []string{"192.0.2.10"}) {
		t.Fatalf("domain asset escaped its host-frozen target: %#v", units[0])
	}
	invocation := testNaabuInvocation(t, units[0], nil)
	joined := " " + strings.Join(invocation.Args, " ") + " "
	targetsPath, ok := argumentValue(invocation.Args, "-list")
	if !ok || strings.TrimSpace(string(mustReadFile(t, targetsPath))) != "192.0.2.10" || strings.Contains(joined, "a.example.test") {
		t.Fatalf("Naabu domain invocation performed a second DNS lookup: %s", joined)
	}
}

func TestNaabuHostnameContractAcceptsExactLocalhostButRejectsOtherSingleLabels(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	document := fixtureDocument("naabu", now)
	asset := &document.Assets[0]
	asset.Name = "localhost"
	asset.Identifiers[0].Value = "localhost"
	asset.Grants[0].ResolvedAddresses = []string{"127.0.0.1"}
	asset.Grants[0].ExternalScope.Target = canonicalTarget{Kind: "hostname", Value: "localhost"}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatalf("exact localhost must match the Rust target contract: %v", err)
	}
	if !reflect.DeepEqual(units[0].ResolvedAddresses, []string{"127.0.0.1"}) {
		t.Fatalf("localhost did not retain its frozen loopback address: %#v", units[0])
	}

	asset.Name = "router"
	asset.Identifiers[0].Value = "router"
	asset.Grants[0].ExternalScope.Target.Value = "router"
	if _, err := validateAndPlan(document, "naabu", now); err == nil {
		t.Fatal("an arbitrary single-label hostname escaped the canonical target contract")
	}
}

func TestFrozenAddressSetIsCanonicalBoundedAndInsideStaticTarget(t *testing.T) {
	valid := []struct {
		addresses []string
		target    canonicalTarget
	}{
		{[]string{"192.0.2.10", "2001:db8::10"}, canonicalTarget{Kind: "hostname", Value: "a.example.test"}},
		{[]string{"192.0.2.10"}, canonicalTarget{Kind: "address", Value: "192.0.2.10"}},
		{[]string{"192.0.2.10"}, canonicalTarget{Kind: "network", Value: "192.0.2.0/24"}},
	}
	for _, fixture := range valid {
		if err := validateResolvedAddresses(fixture.addresses, fixture.target); err != nil {
			t.Fatalf("valid frozen set rejected: %v", err)
		}
	}
	invalid := []struct {
		addresses []string
		target    canonicalTarget
	}{
		{nil, canonicalTarget{Kind: "hostname", Value: "a.example.test"}},
		{[]string{"192.0.2.10", "192.0.2.10"}, canonicalTarget{Kind: "hostname", Value: "a.example.test"}},
		{[]string{"192.0.2.010"}, canonicalTarget{Kind: "hostname", Value: "a.example.test"}},
		{[]string{"192.0.2.11"}, canonicalTarget{Kind: "address", Value: "192.0.2.10"}},
		{[]string{"198.51.100.10"}, canonicalTarget{Kind: "network", Value: "192.0.2.0/24"}},
	}
	for _, fixture := range invalid {
		if err := validateResolvedAddresses(fixture.addresses, fixture.target); err == nil {
			t.Fatalf("unsafe frozen set accepted: %#v for %#v", fixture.addresses, fixture.target)
		}
	}
}

func TestStaticInvocationsCarryEveryFrozenLimit(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("httpx", now)
	units, err := validateAndPlan(document, "httpx", now)
	if err != nil {
		t.Fatal(err)
	}
	environment := childEnvironment("socks5h://172.30.0.1:1080", "/tmp/private")
	httpx, err := httpxInvocation(units[0], "socks5h://172.30.0.1:1080", "/tmp/out", environment)
	if err != nil {
		t.Fatal(err)
	}
	joined := " " + strings.Join(httpx.Args, " ") + " "
	for _, exact := range []string{
		" -target https://a.example.test:443 ", " -proxy socks5h://172.30.0.1:1080 ",
		" -rate-limit 2 ", " -threads 2 ", " -timeout 30 ", " -retries 0 ",
		" -no-fallback-scheme ", " -no-stdin ", " -disable-update-check ",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("httpx invocation lacks %q: %s", exact, joined)
		}
	}
	if httpx.Timeout != 36*time.Second {
		t.Fatalf("HTTPx total deadline must include process allowance: %s", httpx.Timeout)
	}

	nucleiProxy := nucleiCompatibleProxy("socks5h://172.30.0.1:1080")
	if nucleiProxy != "socks5://172.30.0.1:1080" {
		t.Fatalf("Nuclei proxy compatibility spelling changed: %s", nucleiProxy)
	}
	nucleiDocument := fixtureDocument("nuclei", now)
	nucleiUnits, err := validateAndPlan(nucleiDocument, "nuclei", now)
	if err != nil {
		t.Fatal(err)
	}
	nucleiEnvironment := childEnvironment(nucleiProxy, "/tmp/private")
	nuclei, err := nucleiInvocation(
		nucleiUnits[0], nucleiProxy, "/tmp/out", nucleiEnvironment, t.TempDir(), 0,
		[]string{"/opt/nuclei-templates/http/safe-template.yaml"},
	)
	if err != nil {
		t.Fatal(err)
	}
	joined = " " + strings.Join(nuclei.Args, " ") + " "
	for _, exact := range []string{
		" -target https://a.example.test:443 ", " -proxy socks5://172.30.0.1:1080 ",
		" -rate-limit 2 ", " -bulk-size 2 ", " -concurrency 2 ", " -timeout 30 ",
		" -no-httpx ", " -no-interactsh ", " -disable-redirects ", " -no-stdin ",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("Nuclei invocation lacks %q: %s", exact, joined)
		}
	}
	if strings.Contains(strings.Join(nuclei.Env, "\n"), "socks5h://") {
		t.Fatal("Nuclei child environment retained a proxy spelling its parser rejects")
	}
	if nuclei.Timeout != 315*time.Second {
		t.Fatalf("Nuclei total deadline must cover its bounded template requests: %s", nuclei.Timeout)
	}

	naabuDocument := fixtureDocument("naabu", now)
	naabuUnits, err := validateAndPlan(naabuDocument, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	naabu := testNaabuInvocation(t, naabuUnits[0], environment)
	joined = " " + strings.Join(naabu.Args, " ") + " "
	for _, exact := range []string{
		" -list ", " -port 443,8443 ", " -scan-type c ",
		" -proxy 172.30.0.1:1080 ", " -rate 4 ", " -c 2 ", " -timeout 30s ",
	} {
		if !strings.Contains(joined, exact) {
			t.Fatalf("Naabu invocation lacks %q: %s", exact, joined)
		}
	}
	if strings.Contains(joined, " -dns-order ") || strings.Contains(joined, "a.example.test") {
		t.Fatalf("Naabu invocation retained a second DNS lookup path: %s", joined)
	}
	targetsPath, ok := argumentValue(naabu.Args, "-list")
	if !ok || string(mustReadFile(t, targetsPath)) != "192.0.2.10\n" {
		t.Fatalf("Naabu target list did not preserve the exact frozen address: %s", joined)
	}
}

func TestNaabuProxyRateNeverFallsToZeroOrExceedsGrant(t *testing.T) {
	for _, fixture := range []struct {
		policy     ratePolicy
		configured int
		effective  int
	}{
		{ratePolicy{RequestsPerSecond: 1, Concurrency: 1, TimeoutSeconds: 60}, 2, 1},
		{ratePolicy{RequestsPerSecond: 25, Concurrency: 10, TimeoutSeconds: 60}, 20, 10},
		{ratePolicy{RequestsPerSecond: 2, Concurrency: 1, TimeoutSeconds: 60}, 2, 1},
	} {
		unit := scanUnit{Grant: externalScope{
			Ports: []uint16{9001}, ExpiresAt: time.Now().UTC().Add(time.Hour),
			RatePolicy: fixture.policy,
		}, ResolvedAddresses: []string{"192.0.2.10"}}
		plan := testNaabuInvocation(t, unit, nil)
		configured, ok := argumentValue(plan.Args, "-rate")
		if !ok || configured != strconv.Itoa(fixture.configured) {
			t.Fatalf("unexpected Naabu proxy rate: got %q want %d", configured, fixture.configured)
		}
		// Pinned Naabu applies RateLimitWithProxy(rate) == rate / 2.
		effective := fixture.configured / naabuProxyRateDivisor
		if effective != fixture.effective || effective < 1 || effective > int(fixture.policy.RequestsPerSecond) || effective > int(fixture.policy.Concurrency) {
			t.Fatalf("effective proxy rate escaped its grant: %d for %#v", effective, fixture.policy)
		}
	}
}

func TestNaabuTotalDeadlineCoversTheBoundedPortWorkload(t *testing.T) {
	policy := ratePolicy{RequestsPerSecond: 1, Concurrency: 1, TimeoutSeconds: 60}
	ports := []uint16{21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 3389, 8080, 8443}
	unit := scanUnit{Grant: externalScope{
		Ports: ports, ExpiresAt: time.Now().UTC().Add(time.Hour), RatePolicy: policy,
	}, ResolvedAddresses: []string{"192.0.2.10"}}
	plan := testNaabuInvocation(t, unit, nil)
	want := 17*60*time.Second + 17*time.Second + scannerProcessAllowance
	if plan.Timeout != want {
		t.Fatalf("Naabu total deadline does not cover every frozen port attempt: got %s want %s", plan.Timeout, want)
	}
	if plan.Timeout <= time.Duration(policy.TimeoutSeconds)*time.Second {
		t.Fatal("Naabu reused its per-connect timeout as the total child deadline")
	}
}

func TestNaabuBatchesOneGrantWithoutWeakeningItsAggregateDeadline(t *testing.T) {
	policy := ratePolicy{RequestsPerSecond: 25, Concurrency: 10, TimeoutSeconds: 3}
	unit := scanUnit{
		Grant: externalScope{
			Ports: []uint16{80, 443}, ExpiresAt: time.Now().UTC().Add(time.Hour),
			RatePolicy: policy,
		},
		ResolvedAddresses: []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"},
	}
	plan := testNaabuInvocation(t, unit, nil)
	joined := " " + strings.Join(plan.Args, " ") + " "
	targetsPath, ok := argumentValue(plan.Args, "-list")
	if !ok || string(mustReadFile(t, targetsPath)) != "192.0.2.10\n192.0.2.11\n192.0.2.12\n" {
		t.Fatalf("Naabu grant was not batched over its frozen addresses: %s", joined)
	}
	// Six probes at effective rate ten are one timeout/pacing wave.
	if plan.Timeout != 9*time.Second {
		t.Fatalf("batched deadline does not cover its aggregate workload: %s", plan.Timeout)
	}
}

func TestNaabuSinglePortEndpointKeepsASeparateTotalDeadline(t *testing.T) {
	policy := ratePolicy{RequestsPerSecond: 1, Concurrency: 1, TimeoutSeconds: 60}
	unit := scanUnit{Grant: externalScope{
		Ports: []uint16{9001}, ExpiresAt: time.Now().UTC().Add(time.Hour), RatePolicy: policy,
	}, ResolvedAddresses: []string{"192.0.2.10"}}
	plan := testNaabuInvocation(t, unit, nil)
	if plan.Timeout != 66*time.Second {
		t.Fatalf("single-port endpoint total deadline lost its fixed process allowance: %s", plan.Timeout)
	}
}

func TestNaabuDeadlineSaturatesBeforeDurationArithmeticCanOverflow(t *testing.T) {
	policy := ratePolicy{RequestsPerSecond: 1, Concurrency: 1, TimeoutSeconds: 1800}
	if got := naabuInvocationTimeout(policy, 65_535, maxResolvedAddresses); got != naabuEngineCeiling {
		t.Fatalf("oversized bounded workload escaped the reviewed engine ceiling: %s", got)
	}
}

func TestNaabuLargeIPv6SetUsesAPrivateListInsteadOfOneOversizedArgument(t *testing.T) {
	addresses := make([]string, 0, maxResolvedAddresses)
	for index := 0; index < maxResolvedAddresses; index++ {
		addresses = append(addresses, fmt.Sprintf("2001:db8::%x", index))
	}
	unit := scanUnit{
		Grant: externalScope{
			Ports: []uint16{443}, ExpiresAt: time.Now().UTC().Add(time.Hour),
			RatePolicy: ratePolicy{RequestsPerSecond: 25, Concurrency: 10, TimeoutSeconds: 3},
		},
		ResolvedAddresses: addresses,
	}
	plan := testNaabuInvocation(t, unit, nil)
	targetsPath, ok := argumentValue(plan.Args, "-list")
	if !ok {
		t.Fatal("Naabu invocation has no private target list")
	}
	if got := strings.Count(string(mustReadFile(t, targetsPath)), "\n"); got != maxResolvedAddresses {
		t.Fatalf("private target list lost addresses: got %d want %d", got, maxResolvedAddresses)
	}
	if len(strings.Join(plan.Args, "\x00")) >= 128*1024 {
		t.Fatal("Naabu invocation still risks the operating system per-argument limit")
	}
}

func argumentValue(arguments []string, flag string) (string, bool) {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == flag {
			return arguments[index+1], true
		}
	}
	return "", false
}

func TestManagedProxyRequiresExactBridgeSocksEndpoint(t *testing.T) {
	canonical, naabu, err := managedProxy("socks5h://172.31.0.1:1080")
	if err != nil || canonical != "socks5h://172.31.0.1:1080" || naabu != "172.31.0.1:1080" {
		t.Fatalf("managed proxy rejected: %q %q %v", canonical, naabu, err)
	}
	for _, value := range []string{
		"", "http://172.31.0.1:1080", "socks5://172.31.0.1:1080",
		"socks5h://user:pass@172.31.0.1:1080", "socks5h://gateway:1080",
		"socks5h://172.31.0.1:1081", "socks5h://172.31.0.1:1080/path",
	} {
		if _, _, err := managedProxy(value); err == nil {
			t.Fatalf("unsafe proxy endpoint accepted: %s", value)
		}
	}
}

func TestNucleiTemplateIndexAllowsOnlyBoundedReadOnlyHTTP(t *testing.T) {
	root := t.TempDir()
	safe := `id: safe-template
info:
  name: Safe fixture
  severity: info
  metadata:
    max-request: 1
  tags: misconfig
http:
  - method: GET
    path:
      - "{{BaseURL}}/security.txt"
`
	unsafe := strings.Replace(safe, "method: GET", "method: POST\n    body: data", 1)
	if err := os.WriteFile(filepath.Join(root, "safe.yaml"), []byte(safe), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unsafe.yaml"), []byte(strings.Replace(unsafe, "safe-template", "unsafe-template", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := loadTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"safe-template"}}, index)
	if err != nil || len(paths) != 1 {
		t.Fatalf("safe template rejected: %v", err)
	}
	if _, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"unsafe-template"}}, index); err == nil {
		t.Fatal("POST/body template was accepted")
	}
	if _, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: []string{"missing"}}, index); err == nil {
		t.Fatal("template outside exact embedded revision was accepted")
	}
}

func writeNucleiTemplate(t *testing.T, root, name, id, extraInfo, request string) string {
	t.Helper()
	value := fmt.Sprintf(`id: %s
info:
  name: %s
  severity: info
  metadata:
    max-request: 1
  tags: tech,discovery%s
http:
%s
`, id, id, extraInfo, request)
	path := filepath.Join(root, name+".yaml")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNucleiWebSafeProfileIsMechanicalBroadAndRejectsSideEffects(t *testing.T) {
	root := t.TempDir()
	first := writeNucleiTemplate(t, root, "z-safe", "z-safe", "", `  - method: GET
    path:
      - "{{BaseURL}}/version"
`)
	second := writeNucleiTemplate(t, root, "a-safe", "a-safe", "", `  - method: HEAD
    path:
      - "/health"
`)
	writeNucleiTemplate(t, root, "post", "post", "", `  - method: POST
    path:
      - "{{BaseURL}}/login"
    body: data
`)
	writeNucleiTemplate(t, root, "credential", "credential", ",token-spray", `  - method: GET
    path:
      - "{{BaseURL}}/login"
`)
	writeNucleiTemplate(t, root, "execution", "execution", ",rce", `  - method: GET
    path:
      - "{{BaseURL}}/run?cmd=id"
`)
	writeNucleiTemplate(t, root, "off-origin", "off-origin", "", `  - method: GET
    path:
      - "https://elsewhere.example.test/status"
`)
	writeNucleiTemplate(t, root, "dynamic", "dynamic", "", `  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"
    iterate-all: true
`)
	writeNucleiTemplate(t, root, "redirect", "redirect", "", `  - method: GET
    path:
      - "{{BaseURL}}/"
    host-redirects: true
`)
	writeNucleiTemplate(t, root, "oob", "oob", "", `  - method: GET
    path:
      - "{{BaseURL}}/fetch?url={{interactsh-url}}"
`)
	writeNucleiTemplate(t, root, "upload", "upload", ",file-upload", `  - method: GET
    path:
      - "{{BaseURL}}/upload"
`)
	writeNucleiTemplate(t, root, "self-contained", "self-contained", "\nself-contained: true", `  - method: GET
    path:
      - "{{BaseURL}}/"
`)

	index, err := loadTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	ids, paths := deriveNucleiWebSafeProfile(index)
	if !reflect.DeepEqual(ids, []string{"a-safe", "z-safe"}) {
		t.Fatalf("profile derivation admitted a denied template or lost deterministic ordering: %v", ids)
	}
	wantPaths := []string{second, first}
	sort.Strings(wantPaths)
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("profile paths are not the exact sorted safe pool: got %v want %v", paths, wantPaths)
	}
}

func TestNucleiProfilePolicyRequiresExactlyOneKnownSelectionMode(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("nuclei", now)
	policy := &document.Assets[0].Grants[0].ExternalScope.TemplatePolicy
	profile := nucleiWebSafeProfileID
	policy.AllowedTemplateIDs = nil
	policy.ProfileID = &profile
	if _, err := validateAndPlan(document, "nuclei", now); err != nil {
		t.Fatalf("known pinned Nuclei profile was rejected: %v", err)
	}

	policy.AllowedTemplateIDs = []string{"safe-template"}
	if _, err := validateAndPlan(document, "nuclei", now); err == nil {
		t.Fatal("mixed profile and explicit Nuclei selection was accepted")
	}
	policy.AllowedTemplateIDs = nil
	unknown := "nuclei_web_safe_v2"
	policy.ProfileID = &unknown
	if _, err := validateAndPlan(document, "nuclei", now); err == nil {
		t.Fatal("unknown Nuclei profile was accepted")
	}
	policy.ProfileID = nil
	if _, err := validateAndPlan(document, "nuclei", now); err == nil {
		t.Fatal("Nuclei policy without a selection was accepted")
	}

	httpx := fixtureDocument("httpx", now)
	httpx.Assets[0].Grants[0].ExternalScope.TemplatePolicy.ProfileID = &profile
	if _, err := validateAndPlan(httpx, "httpx", now); err == nil {
		t.Fatal("non-template engine accepted a Nuclei profile")
	}
}

func TestNucleiAutomaticProfileHasNoFullTreeFallback(t *testing.T) {
	root := t.TempDir()
	first := writeNucleiTemplate(t, root, "a-safe", "a-safe", "", `  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	second := writeNucleiTemplate(t, root, "b-safe", "b-safe", "", `  - method: GET
    path:
      - "{{BaseURL}}/version"
`)
	profile := nucleiWebSafeProfileID
	unit := scanUnit{
		Grant: externalScope{
			Target: canonicalTarget{Kind: "hostname", Value: "a.example.test"},
			Ports:  []uint16{443}, Protocol: "https",
			RatePolicy: ratePolicy{RequestsPerSecond: 2, Concurrency: 2, TimeoutSeconds: 30},
			TemplatePolicy: templatePolicy{
				AllowedTemplateIDs: []string{"a-safe", "b-safe"}, ProfileID: &profile,
			},
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		},
		Port: 443,
	}
	temporaryRoot := t.TempDir()
	plan, err := nucleiInvocation(
		unit, "socks5://172.30.0.1:1080", filepath.Join(t.TempDir(), "result.jsonl"),
		[]string{"DISABLE_STDOUT=1", "HOME=/tmp/private"}, temporaryRoot, 7, []string{first, second},
	)
	if err != nil {
		t.Fatal(err)
	}
	joined := " " + strings.Join(plan.Args, " ") + " "
	for _, required := range []string{
		" -automatic-scan ", " -update-template-dir ", " -template-id ",
		" -jsonl ", " -matcher-status ", " -disable-clustering ",
		" -response-size-read 4194304 ", " -payload-concurrency 1 ", " -max-time ",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("automatic profile invocation lacks %q: %s", required, joined)
		}
	}
	profileRoot, ok := argumentValue(plan.Args, "-update-template-dir")
	if !ok || profileRoot == templateRootPath {
		t.Fatalf("automatic scan can fall back to the full embedded tree: %q", profileRoot)
	}
	relative, err := filepath.Rel(temporaryRoot, profileRoot)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		t.Fatalf("automatic root escaped the private launcher directory: %q", profileRoot)
	}
	entries, err := os.ReadDir(profileRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "validated-anchor.yaml" || entries[0].Type()&os.ModeSymlink != 0 {
		t.Fatalf("automatic default root contains something beyond one validated anchor: %#v", entries)
	}
	if !bytes.Equal(mustReadFile(t, filepath.Join(profileRoot, entries[0].Name())), mustReadFile(t, first)) {
		t.Fatal("automatic root anchor differs from the validated pool")
	}
	idsPath, ok := argumentValue(plan.Args, "-template-id")
	if !ok || string(mustReadFile(t, idsPath)) != "a-safe\nb-safe\n" {
		t.Fatal("automatic scan did not retain its exact ID filter")
	}
	templatesPath, ok := argumentValue(plan.Args, "-templates")
	if !ok || string(mustReadFile(t, templatesPath)) != first+"\n"+second+"\n" {
		t.Fatal("automatic scan did not retain its exact validated path filter")
	}
	if plan.StdoutPath == "" {
		t.Fatal("Nuclei standard-writer JSONL is not captured as scanner evidence")
	}
	if strings.Contains(joined, " -jsonl-export ") || strings.Contains(joined, " -output ") {
		t.Fatalf("Nuclei invocation still uses a result-only or newline-unsafe file writer: %s", joined)
	}
	if containsString(plan.Env, "DISABLE_STDOUT=1") {
		t.Fatal("Nuclei standard-writer output was disabled")
	}
	if !containsString(plan.Env, "HOME=/tmp/private") {
		t.Fatal("filtering the Nuclei stdout override removed unrelated environment")
	}

	unit.Grant.TemplatePolicy.ProfileID = nil
	legacy, err := nucleiInvocation(
		unit, "socks5://172.30.0.1:1080", filepath.Join(t.TempDir(), "legacy.jsonl"),
		nil, t.TempDir(), 0, []string{first, second},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(legacy.Args, " "), "automatic-scan") {
		t.Fatal("legacy explicit-template mode was silently changed to automatic scan")
	}
	if !containsString(legacy.Args, "-disable-clustering") {
		t.Fatal("legacy explicit-template mode can report synthetic cluster IDs")
	}
}

func TestRunCommandCapturesStdoutWithoutOverwritingEvidence(t *testing.T) {
	output := filepath.Join(t.TempDir(), "stdout.jsonl")
	plan := invocation{
		Program:    "/bin/sh",
		Args:       []string{"-c", `printf '%s\n' '{"matcher-status":false}'`},
		Env:        []string{"PATH=/usr/bin:/bin"},
		StdoutPath: output,
		Expiry:     time.Now().UTC().Add(time.Minute),
		Timeout:    time.Second,
	}
	if err := runCommand(plan); err != nil {
		t.Fatal(err)
	}
	if got := string(mustReadFile(t, output)); got != "{\"matcher-status\":false}\n" {
		t.Fatalf("captured stdout differs: %q", got)
	}
	if err := runCommand(plan); err == nil || !strings.Contains(err.Error(), "exclusive scanner stdout evidence") {
		t.Fatalf("existing evidence was overwritten or returned the wrong error: %v", err)
	}
}

func TestPinnedNucleiTemplateTreeWhenProvided(t *testing.T) {
	root := os.Getenv("NUCLEI_TEMPLATE_ROOT")
	if root == "" {
		t.Skip("exact template tree is supplied by the image smoke")
	}
	index, err := loadTemplateIndex(filepath.Join(root, "http"))
	if err != nil {
		t.Fatalf("index exact template tree: %v", err)
	}
	if len(index) < 1000 {
		t.Fatalf("exact template tree unexpectedly small: %d", len(index))
	}
	profileIDs := []string{"CVE-2018-16671"}
	paths, err := selectedTemplatePaths(templatePolicy{AllowedTemplateIDs: profileIDs}, index)
	if err != nil || len(paths) != len(profileIDs) {
		t.Fatalf("known bounded GET templates failed conservative policy: %v", err)
	}
	profile := nucleiWebSafeProfileID
	profileIDs, profilePaths, err := resolvedTemplateSelection(templatePolicy{ProfileID: &profile}, index)
	if err != nil {
		t.Fatalf("derive pinned automatic profile: %v", err)
	}
	t.Logf("pinned Nuclei safe profile: templates=%d", len(profileIDs))
	// The upstream PHP crash probe must remain outside this read-only profile.
	// Inspect the upstream definition; never execute the denial-of-service probe.
	crashID := "CVE-2026-109618"
	crashPath, ok := index[crashID]
	if !ok {
		t.Fatalf("pinned tree is missing expected upstream crash template %s", crashID)
	}
	if err := validateSafeTemplate(crashPath, crashID); err == nil {
		t.Fatal("upstream PHP crash template passed the read-only policy")
	} else {
		t.Logf("upstream PHP crash template excluded: %v", err)
	}
	for _, id := range profileIDs {
		if id == crashID {
			t.Fatal("upstream PHP crash template entered the automatic profile")
		}
	}
	if len(profileIDs) != nucleiWebSafeTemplateCount || len(profileIDs) != len(profilePaths) {
		t.Fatalf("pinned automatic profile is not materially broad and closed: ids=%d paths=%d", len(profileIDs), len(profilePaths))
	}
}

func TestEvidenceIsReattributedAndOutOfScopeRecordsFail(t *testing.T) {
	unit := scanUnit{
		AssetID: "asset-a",
		Grant: externalScope{
			ID: "grant-a", Target: canonicalTarget{Kind: "hostname", Value: "a.example.test"},
			Ports: []uint16{443}, Protocol: "https",
			TemplatePolicy: templatePolicy{AllowedTemplateIDs: []string{"safe-template"}},
		},
		Port: 443, ResolvedAddresses: []string{"192.0.2.10"},
	}
	path := filepath.Join(t.TempDir(), "httpx.jsonl")
	if err := os.WriteFile(path, []byte(`{"url":"https://a.example.test:443/","status_code":200,"body":"discard me","host_ip":"192.0.2.10","a":["192.0.2.10"],"aaaa":["2001:db8::10"],"cname":["edge.example.test"],"resolvers":["198.51.100.53"]}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	written := int64(0)
	if err := normalizeEvidence(path, writer, &written, "httpx", unit); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record["asset_id"] != "asset-a" || record["scope_grant_id"] != "grant-a" || record["body"] != nil {
		t.Fatalf("unexpected normalized evidence: %#v", record)
	}
	for _, key := range []string{"host_ip", "a", "aaaa", "cname", "resolvers"} {
		if _, exists := record[key]; exists {
			t.Fatalf("non-authoritative live DNS field %s survived normalization: %#v", key, record)
		}
	}

	if err := os.WriteFile(path, []byte(`{"url":"https://b.example.test:443/","status_code":200}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer = bufio.NewWriter(&bytes.Buffer{})
	written = 0
	if err := normalizeEvidence(path, writer, &written, "httpx", unit); err == nil {
		t.Fatal("out-of-scope evidence was accepted")
	}
}

func TestEvidenceIPMustBelongToTheHostSideFrozenSet(t *testing.T) {
	unit := scanUnit{
		AssetID: "asset-a",
		Grant: externalScope{
			ID: "grant-a", Target: canonicalTarget{Kind: "hostname", Value: "a.example.test"},
			Ports: []uint16{443}, Protocol: "https",
		},
		Port: 443, ResolvedAddresses: []string{"192.0.2.10", "2001:db8::10"},
	}
	for _, observed := range []string{
		"https://a.example.test:443/",
		"https://192.0.2.10:443/",
		"https://[2001:db8::10]:443/",
	} {
		if err := validateObservedURL(observed, unit); err != nil {
			t.Fatalf("frozen observation %s rejected: %v", observed, err)
		}
	}
	if err := validateObservedURL("https://198.51.100.10:443/", unit); err == nil {
		t.Fatal("hostname evidence accepted an IP outside the host-side DNS snapshot")
	}

	naabuRecord := func(host string) map[string]json.RawMessage {
		value, err := json.Marshal(map[string]any{"host": host, "port": 443, "protocol": "tcp"})
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]json.RawMessage
		if err := json.Unmarshal(value, &record); err != nil {
			t.Fatal(err)
		}
		return record
	}
	if err := validateEvidenceObject("naabu", naabuRecord("192.0.2.10"), unit); err != nil {
		t.Fatalf("Naabu frozen IP evidence rejected: %v", err)
	}
	if err := validateEvidenceObject("naabu", naabuRecord("198.51.100.10"), unit); err == nil {
		t.Fatal("Naabu accepted evidence from a different address")
	}
}

func TestScopeDecoderRejectsUnknownFields(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("httpx", now)
	value, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	value = bytes.Replace(value, []byte(`"engine_id":"httpx"`), []byte(`"engine_id":"httpx","unexpected":true`), 1)
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path, "httpx"); err == nil {
		t.Fatal("unknown scope field was accepted")
	}
}

func TestScopeDecoderRequiresWireVersionTwoForEveryExternalEngine(t *testing.T) {
	now := time.Now().UTC()
	for _, engineID := range []string{"naabu", "httpx", "nuclei"} {
		document := fixtureDocument(engineID, now)
		path := filepath.Join(t.TempDir(), engineID+"-scope.json")
		write := func() {
			value, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, value, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write()
		if _, err := loadScope(path, engineID); err != nil {
			t.Fatalf("%s rejected exact external wire schema 2: %v", engineID, err)
		}
		for _, incompatible := range []string{"1", "3", "2.0"} {
			document.SchemaVersion = incompatible
			write()
			if _, err := loadScope(path, engineID); err == nil {
				t.Fatalf("%s accepted incompatible external wire schema %s", engineID, incompatible)
			}
		}
	}
}

func portText(port uint16) string { return strconv.Itoa(int(port)) }

const (
	launcherV2ScopeA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	launcherV2ScopeB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	launcherV2UnitA  = "wu_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	launcherV2UnitB  = "wu_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// LAUNCHER_V2_RUST_GOLDEN_START
const launcherV2RustGoldenJournal = `{"record_type":"header","schema_version":2,"engine_run_id":"run-opaque","execution_attempt":7,"requested_work_units":[{"unit_id":"wu_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scope_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
{"record_type":"attempt_finished","unit_id":"wu_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scope_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attempt":7,"outcome":"tested_partial","incomplete_reason":"timed_out","final_artifact":{"engine_run_id":"run-opaque","unit_id":"wu_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scope_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attempt":7,"relative_path":"launcher-v2/units/unit-000000/attempt-7.jsonl","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","byte_length":12}}
`

// LAUNCHER_V2_RUST_GOLDEN_END

func launcherV2TestPlan(attempt uint32, units ...launcherV2PlannedUnit) *launcherV2Plan {
	return &launcherV2Plan{
		SchemaVersion:    launcherPlanCurrentVersion,
		EngineID:         "naabu",
		EngineRunID:      "run-opaque-1",
		ExecutionAttempt: attempt,
		FrozenGrants: []launcherV2FrozenGrant{
			{ScopeGrantID: "grant-a", Addresses: []string{"192.0.2.10"}, Ports: []uint16{443, 8443}},
			{ScopeGrantID: "grant-b", Addresses: []string{"192.0.2.20"}, Ports: []uint16{9443}},
		},
		RequestedWorkUnits: units,
	}
}

func launcherV2TestPlannedUnit(grantIndex uint32, unitID, scopeSHA256 string) launcherV2PlannedUnit {
	return launcherV2PlannedUnit{
		UnitID:                      unitID,
		ScopeSHA256:                 scopeSHA256,
		GrantIndex:                  grantIndex,
		AddressStart:                0,
		AddressLen:                  1,
		PortStart:                   0,
		PortLen:                     1,
		EndpointPairCount:           1,
		ConservativeDeadlineSeconds: 36,
	}
}

func writeLauncherV2TestPlan(t *testing.T, plan *launcherV2Plan) string {
	t.Helper()
	value, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "execution-journal-v2.json")
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cloneLauncherV2TestPlan(t *testing.T, plan *launcherV2Plan) *launcherV2Plan {
	t.Helper()
	value, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var cloned launcherV2Plan
	if err := json.Unmarshal(value, &cloned); err != nil {
		t.Fatal(err)
	}
	return &cloned
}

func launcherV2TestUnits(t *testing.T, now time.Time) []scanUnit {
	t.Helper()
	units, err := validateAndPlan(fixtureDocument("naabu", now), "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	return units
}

func launcherV2Records(t *testing.T, outputRoot string) []map[string]any {
	t.Helper()
	file, err := os.Open(filepath.Join(outputRoot, launcherV2Directory, launcherV2JournalName))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var records []map[string]any
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestLauncherV2SameGrantQuickAndFullUseExactSidecarSlicesInOrder(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("naabu", now)
	document.Assets[0].Grants[0].ResolvedAddresses = []string{"192.0.2.10", "192.0.2.11"}
	document.Assets[0].Grants[0].ExternalScope.Ports = []uint16{22, 443}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	plan := launcherV2TestPlan(4,
		launcherV2PlannedUnit{
			UnitID: launcherV2UnitA, ScopeSHA256: launcherV2ScopeA, GrantIndex: 0,
			AddressStart: 0, AddressLen: 1, PortStart: 0, PortLen: 1,
			EndpointPairCount: 1, ConservativeDeadlineSeconds: 36,
		},
		launcherV2PlannedUnit{
			UnitID: launcherV2UnitB, ScopeSHA256: launcherV2ScopeB, GrantIndex: 0,
			AddressStart: 0, AddressLen: 2, PortStart: 1, PortLen: 1,
			EndpointPairCount: 2, ConservativeDeadlineSeconds: 36,
		},
	)
	// scope.json uses numeric port order. The frozen sidecar deliberately uses a
	// different, host-authoritative order while remaining set-equal.
	plan.FrozenGrants[0] = launcherV2FrozenGrant{
		ScopeGrantID: "grant-a",
		Addresses:    []string{"192.0.2.11", "192.0.2.10"},
		Ports:        []uint16{443, 22},
	}
	loaded, err := loadLauncherV2Plan(writeLauncherV2TestPlan(t, plan), "naabu", units)
	if err != nil {
		t.Fatalf("same-grant quick and full slices were rejected: %v", err)
	}

	var targetLists, ports, outputNames []string
	var deadlines []time.Duration
	runner := func(command invocation) launcherV2RunResult {
		targetsPath, ok := argumentValue(command.Args, "-list")
		if !ok {
			t.Fatal("Naabu invocation has no exact target-list path")
		}
		portList, ok := argumentValue(command.Args, "-port")
		if !ok {
			t.Fatal("Naabu invocation has no exact port list")
		}
		outputPath, ok := argumentValue(command.Args, "-output")
		if !ok {
			t.Fatal("Naabu invocation has no output path")
		}
		targetLists = append(targetLists, strings.TrimSpace(string(mustReadFile(t, targetsPath))))
		ports = append(ports, portList)
		outputNames = append(outputNames, filepath.Base(outputPath))
		deadlines = append(deadlines, command.Timeout)
		return launcherV2RunResult{Outcome: launcherV2RunSucceeded}
	}
	outputRoot := t.TempDir()
	if err := runNaabuLauncherV2(outputRoot, t.TempDir(), loaded, units, "172.30.0.1:1080", nil, now, runner); err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.11", "192.0.2.11\n192.0.2.10"}; !reflect.DeepEqual(targetLists, want) {
		t.Fatalf("launcher changed sidecar address slices or order: got %v want %v", targetLists, want)
	}
	if want := []string{"443", "22"}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("launcher changed sidecar port slices or order: got %v want %v", ports, want)
	}
	if want := []string{"result-000000.jsonl", "result-000001.jsonl"}; !reflect.DeepEqual(outputNames, want) {
		t.Fatalf("launcher did not use requested ordinals for temporary output: got %v want %v", outputNames, want)
	}
	if want := []time.Duration{36 * time.Second, 36 * time.Second}; !reflect.DeepEqual(deadlines, want) {
		t.Fatalf("launcher did not preserve exact conservative deadlines: got %v want %v", deadlines, want)
	}
	records := launcherV2Records(t, outputRoot)
	for index, record := range records[1:] {
		artifact := record["final_artifact"].(map[string]any)
		want := fmt.Sprintf("launcher-v2/units/unit-%06d/attempt-4.jsonl", index)
		if artifact["relative_path"] != want {
			t.Fatalf("final artifact did not use requested ordinal: got %v want %s", artifact["relative_path"], want)
		}
	}
	journal := mustReadFile(t, filepath.Join(outputRoot, launcherV2Directory, launcherV2JournalName))
	for _, target := range []string{"grant-a", "192.0.2.10", "192.0.2.11", "443", "22"} {
		if bytes.Contains(journal, []byte(target)) {
			t.Fatalf("target-free journal exposed sidecar material %q", target)
		}
	}
}

func TestLauncherV3RequiresCompactAttemptPortsToEqualTheScope(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("naabu", now)
	document.Assets = document.Assets[:1]
	document.Assets[0].Grants[0].ExternalScope.Ports = []uint16{8443}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	plan := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	plan.FrozenGrants = []launcherV2FrozenGrant{{
		ScopeGrantID: "grant-a",
		Addresses:    []string{"192.0.2.10"},
		Ports:        []uint16{8443},
	}}

	materialized, err := materializeLauncherV2Plan(plan, "naabu", units)
	if err != nil {
		t.Fatalf("compact authorized attempt corpus was rejected: %v", err)
	}
	if len(materialized) != 1 || !reflect.DeepEqual(materialized[0].Grant.Ports, []uint16{8443}) {
		t.Fatalf("compact attempt ports were not preserved exactly: %#v", materialized)
	}
}

func TestLauncherAcceptsLegacyFullCorpusPlanUnderStableJournalV2Command(t *testing.T) {
	now := time.Now().UTC()
	units := launcherV2TestUnits(t, now)
	plan := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	plan.SchemaVersion = launcherPlanLegacyVersion
	if _, err := materializeLauncherV2Plan(plan, "naabu", units); err != nil {
		t.Fatalf("legacy full-corpus schema-2 plan was rejected: %v", err)
	}
	if _, err := validateLauncherV2Options(launcherJournalSchemaVersion, journalPlanMountPath, "naabu"); err != nil {
		t.Fatalf("stable journal-v2 command rejected an exact legacy plan path: %v", err)
	}
}

func TestLauncherV3RejectsMoreThan128RequestedUnitsAndAggregateAbove10000Pairs(t *testing.T) {
	now := time.Now().UTC()
	base := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	tooMany := cloneLauncherV2TestPlan(t, base)
	tooMany.RequestedWorkUnits = make([]launcherV2PlannedUnit, maxLauncherCurrentUnits+1)
	for index := range tooMany.RequestedWorkUnits {
		tooMany.RequestedWorkUnits[index] = launcherV2TestPlannedUnit(
			0,
			fmt.Sprintf("wu_%032x", index+1),
			fmt.Sprintf("%064x", index+1),
		)
	}
	if _, err := materializeLauncherV2Plan(tooMany, "naabu", launcherV2TestUnits(t, now)); err == nil {
		t.Fatal("launcher accepted 129 requested work units")
	}

	document := fixtureDocument("naabu", now)
	document.Assets = document.Assets[:1]
	grant := document.Assets[0].Grants[0].ExternalScope
	grant.RatePolicy = ratePolicy{RequestsPerSecond: 10, Concurrency: 10, TimeoutSeconds: 1}
	grant.Ports = make([]uint16, 102)
	for index := range grant.Ports {
		grant.Ports[index] = uint16(index + 1)
	}
	document.Assets[0].Grants[0].ResolvedAddresses = make([]string, 100)
	for index := range document.Assets[0].Grants[0].ResolvedAddresses {
		document.Assets[0].Grants[0].ResolvedAddresses[index] = fmt.Sprintf("192.0.2.%d", index+1)
	}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := launcherV2ConservativeDeadlineSeconds(grant.RatePolicy, 5_100)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := &launcherV2Plan{
		SchemaVersion:    launcherPlanCurrentVersion,
		EngineID:         "naabu",
		EngineRunID:      "run-opaque-aggregate",
		ExecutionAttempt: 1,
		FrozenGrants: []launcherV2FrozenGrant{{
			ScopeGrantID: "grant-a",
			Addresses:    append([]string(nil), document.Assets[0].Grants[0].ResolvedAddresses...),
			Ports:        append([]uint16(nil), grant.Ports...),
		}},
		RequestedWorkUnits: []launcherV2PlannedUnit{
			{
				UnitID: launcherV2UnitA, ScopeSHA256: launcherV2ScopeA,
				GrantIndex: 0, AddressStart: 0, AddressLen: 100, PortStart: 0, PortLen: 51,
				EndpointPairCount: 5_100, ConservativeDeadlineSeconds: deadline,
			},
			{
				UnitID: launcherV2UnitB, ScopeSHA256: launcherV2ScopeB,
				GrantIndex: 0, AddressStart: 0, AddressLen: 100, PortStart: 51, PortLen: 51,
				EndpointPairCount: 5_100, ConservativeDeadlineSeconds: deadline,
			},
		},
	}
	if _, err := materializeLauncherV2Plan(aggregate, "naabu", units); err == nil {
		t.Fatal("launcher-v3 accepted more than 10,000 aggregate endpoint pairs")
	}
	aggregate.SchemaVersion = launcherPlanLegacyVersion
	if materialized, err := materializeLauncherV2Plan(aggregate, "naabu", units); err != nil || len(materialized) != 2 {
		t.Fatalf("legacy launcher rejected historically valid per-unit-bounded work: units=%d err=%v", len(materialized), err)
	}
}

func TestLegacyLauncherAndJournalRetainTheHistorical512UnitBound(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("naabu", now)
	document.Assets = document.Assets[:1]
	document.Assets[0].Grants[0].ExternalScope.Ports = make([]uint16, maxLauncherCurrentUnits+1)
	for index := range document.Assets[0].Grants[0].ExternalScope.Ports {
		document.Assets[0].Grants[0].ExternalScope.Ports[index] = uint16(index + 1)
	}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := launcherV2ConservativeDeadlineSeconds(
		document.Assets[0].Grants[0].ExternalScope.RatePolicy,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := &launcherV2Plan{
		SchemaVersion:    launcherPlanLegacyVersion,
		EngineID:         "naabu",
		EngineRunID:      "run-opaque-legacy-many",
		ExecutionAttempt: 1,
		FrozenGrants: []launcherV2FrozenGrant{{
			ScopeGrantID: "grant-a",
			Addresses:    []string{"192.0.2.10"},
			Ports:        append([]uint16(nil), document.Assets[0].Grants[0].ExternalScope.Ports...),
		}},
		RequestedWorkUnits: make([]launcherV2PlannedUnit, maxLauncherCurrentUnits+1),
	}
	for index := range plan.RequestedWorkUnits {
		plan.RequestedWorkUnits[index] = launcherV2PlannedUnit{
			UnitID: fmt.Sprintf("wu_%032x", index+1), ScopeSHA256: fmt.Sprintf("%064x", index+1),
			GrantIndex: 0, AddressStart: 0, AddressLen: 1, PortStart: uint32(index), PortLen: 1,
			EndpointPairCount: 1, ConservativeDeadlineSeconds: deadline,
		}
	}

	materialized, err := materializeLauncherV2Plan(plan, "naabu", units)
	if err != nil || len(materialized) != maxLauncherCurrentUnits+1 {
		t.Fatalf("legacy launcher rejected 129 disjoint historical units: units=%d err=%v", len(materialized), err)
	}
	journalRoot := t.TempDir()
	journal, err := createLauncherV2Journal(journalRoot, plan, &launcherV2ByteBudget{})
	if err != nil {
		t.Fatalf("legacy journal rejected 129 requested units: %v", err)
	}
	for _, unit := range plan.RequestedWorkUnits {
		if err := journal.appendAttempt(launcherV2AttemptFinished{
			RecordType: "attempt_finished", UnitID: unit.UnitID, ScopeSHA256: unit.ScopeSHA256,
			Attempt: plan.ExecutionAttempt, Outcome: "failed",
		}); err != nil {
			t.Fatalf("legacy journal rejected a plan-bounded terminal record: %v", err)
		}
	}
	if err := journal.file.Close(); err != nil {
		t.Fatal(err)
	}
	if records := launcherV2Records(t, journalRoot); len(records) != 1+len(plan.RequestedWorkUnits) {
		t.Fatalf("legacy journal record bound drifted: got %d want %d", len(records), 1+len(plan.RequestedWorkUnits))
	}

	tooMany := cloneLauncherV2TestPlan(t, plan)
	tooMany.RequestedWorkUnits = make([]launcherV2PlannedUnit, maxLauncherLegacyUnits+1)
	if _, err := materializeLauncherV2Plan(tooMany, "naabu", units); err == nil {
		t.Fatal("legacy launcher accepted more than 512 requested units")
	}
	if journal, err := createLauncherV2Journal(t.TempDir(), tooMany, &launcherV2ByteBudget{}); err == nil {
		_ = journal.file.Close()
		t.Fatal("legacy journal accepted more than 512 requested units")
	}
}

func TestLauncherV2RejectsAlteredCorpusSliceDeadlineOverlapAndDuplicates(t *testing.T) {
	units := launcherV2TestUnits(t, time.Now().UTC())
	valid := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	tests := []struct {
		name   string
		mutate func(*launcherV2Plan)
	}{
		{
			name: "altered address corpus",
			mutate: func(plan *launcherV2Plan) {
				plan.FrozenGrants[0].Addresses[0] = "192.0.2.99"
			},
		},
		{
			name: "altered port corpus",
			mutate: func(plan *launcherV2Plan) {
				plan.FrozenGrants[0].Ports[0] = 80
			},
		},
		{
			name: "duplicate frozen address",
			mutate: func(plan *launcherV2Plan) {
				plan.FrozenGrants[0].Addresses = []string{"192.0.2.10", "192.0.2.10"}
			},
		},
		{
			name: "out of bounds slice",
			mutate: func(plan *launcherV2Plan) {
				plan.RequestedWorkUnits[0].AddressStart = 1
			},
		},
		{
			name: "empty slice",
			mutate: func(plan *launcherV2Plan) {
				plan.RequestedWorkUnits[0].PortLen = 0
				plan.RequestedWorkUnits[0].EndpointPairCount = 0
			},
		},
		{
			name: "wrong endpoint pair count",
			mutate: func(plan *launcherV2Plan) {
				plan.RequestedWorkUnits[0].EndpointPairCount = 2
			},
		},
		{
			name: "wrong conservative deadline",
			mutate: func(plan *launcherV2Plan) {
				plan.RequestedWorkUnits[0].ConservativeDeadlineSeconds++
			},
		},
		{
			name: "overlapping same-grant rectangles",
			mutate: func(plan *launcherV2Plan) {
				plan.RequestedWorkUnits = append(plan.RequestedWorkUnits,
					launcherV2TestPlannedUnit(0, launcherV2UnitB, launcherV2ScopeB))
			},
		},
		{
			name: "duplicate frozen grant",
			mutate: func(plan *launcherV2Plan) {
				plan.FrozenGrants[1] = plan.FrozenGrants[0]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := cloneLauncherV2TestPlan(t, valid)
			test.mutate(plan)
			if _, err := loadLauncherV2Plan(writeLauncherV2TestPlan(t, plan), "naabu", units); err == nil {
				t.Fatal("invalid launcher-v2 sidecar was accepted")
			}
		})
	}
}

func TestLauncherAllowsCrossGrantPartialOverlapAsExactEndpointUnion(t *testing.T) {
	now := time.Now().UTC()
	document := fixtureDocument("naabu", now)
	document.Assets[0].Grants[0].ExternalScope.Ports = []uint16{80, 443}
	document.Assets[1].Grants[0].ExternalScope.Ports = []uint16{443, 8443}
	document.Assets[1].Grants[0].ResolvedAddresses = []string{"192.0.2.10"}
	units, err := validateAndPlan(document, "naabu", now)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := launcherV2ConservativeDeadlineSeconds(
		document.Assets[0].Grants[0].ExternalScope.RatePolicy,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := &launcherV2Plan{
		SchemaVersion:    launcherPlanCurrentVersion,
		EngineID:         "naabu",
		EngineRunID:      "cross-grant-partial-overlap",
		ExecutionAttempt: 1,
		FrozenGrants: []launcherV2FrozenGrant{
			{ScopeGrantID: "grant-a", Addresses: []string{"192.0.2.10"}, Ports: []uint16{80, 443}},
			{ScopeGrantID: "grant-b", Addresses: []string{"192.0.2.10"}, Ports: []uint16{443, 8443}},
		},
		RequestedWorkUnits: []launcherV2PlannedUnit{
			{
				UnitID: "wu_33333333333333333333333333333333", ScopeSHA256: strings.Repeat("3", 64),
				GrantIndex: 0, AddressStart: 0, AddressLen: 1, PortStart: 0, PortLen: 2,
				EndpointPairCount: 2, ConservativeDeadlineSeconds: deadline,
			},
			{
				UnitID: "wu_44444444444444444444444444444444", ScopeSHA256: strings.Repeat("4", 64),
				GrantIndex: 1, AddressStart: 0, AddressLen: 1, PortStart: 0, PortLen: 2,
				EndpointPairCount: 2, ConservativeDeadlineSeconds: deadline,
			},
		},
	}
	materialized, err := materializeLauncherV2Plan(plan, "naabu", units)
	if err != nil {
		t.Fatalf("cross-grant partial overlap was rejected: %v", err)
	}
	union := make(map[string]struct{})
	for _, unit := range materialized {
		for _, address := range unit.ResolvedAddresses {
			for _, port := range unit.Grant.Ports {
				union[address+":"+strconv.Itoa(int(port))] = struct{}{}
			}
		}
	}
	want := map[string]struct{}{
		"192.0.2.10:80": {}, "192.0.2.10:443": {}, "192.0.2.10:8443": {},
	}
	if !reflect.DeepEqual(union, want) {
		t.Fatalf("cross-grant overlap widened or narrowed the exact endpoint union: got %#v want %#v", union, want)
	}
}

func TestLauncherV2PlanDecoderRejectsUnknownFieldsAndOversizeInput(t *testing.T) {
	units := launcherV2TestUnits(t, time.Now().UTC())
	plan := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	value, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(value, []byte(`{"schema_version":3,`), []byte(`{"schema_version":3,"unexpected":true,`), 1)
	if bytes.Equal(unknown, value) {
		t.Fatal("test could not inject an unknown launcher-v2 field")
	}
	unknownPath := filepath.Join(t.TempDir(), "execution-journal-v2.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLauncherV2Plan(unknownPath, "naabu", units); err == nil {
		t.Fatal("launcher-v2 decoder accepted an unknown field")
	}

	oversizePath := filepath.Join(t.TempDir(), "execution-journal-v2.json")
	if err := os.WriteFile(oversizePath, bytes.Repeat([]byte{' '}, maxLauncherV2PlanBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLauncherV2Plan(oversizePath, "naabu", units); err == nil {
		t.Fatal("launcher-v2 decoder accepted a plan larger than one MiB")
	}
}

func TestLauncherV2ReadsTheSharedRustWireFixture(t *testing.T) {
	document := fixtureDocument("naabu", time.Now().UTC())
	document.Assets = document.Assets[:1]
	document.Assets[0].Grants[0].ExternalScope.Ports = []uint16{443}
	units, err := validateAndPlan(document, "naabu", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "naabu-launcher-plan-v3.json")
	plan, err := loadLauncherV2Plan(path, "naabu", units)
	if err != nil {
		t.Fatalf("shared Rust launcher-v2 fixture was rejected: %v", err)
	}
	materialized, err := materializeLauncherV2Plan(plan, "naabu", units)
	if err != nil {
		t.Fatalf("shared Rust launcher-v2 fixture could not be materialized: %v", err)
	}
	if plan.EngineRunID != "run-opaque" || plan.ExecutionAttempt != 7 {
		t.Fatalf("shared fixture identity drifted: %#v", plan)
	}
	if len(materialized) != 1 ||
		!reflect.DeepEqual(materialized[0].ResolvedAddresses, []string{"192.0.2.10"}) ||
		!reflect.DeepEqual(materialized[0].Grant.Ports, []uint16{443}) {
		t.Fatalf("shared fixture did not preserve the exact first rectangle: %#v", materialized)
	}
}

func TestLauncherReadsFrozenLegacyV2FixtureWithoutChangingItsBytes(t *testing.T) {
	path := filepath.Join("testdata", "naabu-launcher-plan-v2.json")
	fixture, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(fixture)), "855eedf40c787b2d31a75b5bb9a33665afca087dd768028980eddd1baeb2f844"; got != want {
		t.Fatalf("legacy launcher fixture digest drifted: got %s want %s", got, want)
	}
	units := launcherV2TestUnits(t, time.Now().UTC())
	plan, err := loadLauncherV2Plan(path, "naabu", units)
	if err != nil {
		t.Fatalf("frozen legacy launcher fixture was rejected: %v", err)
	}
	materialized, err := materializeLauncherV2Plan(plan, "naabu", units)
	if err != nil {
		t.Fatalf("frozen legacy launcher fixture could not be materialized: %v", err)
	}
	if plan.SchemaVersion != launcherPlanLegacyVersion || len(plan.FrozenGrants) != 2 {
		t.Fatalf("legacy fixture identity drifted: %#v", plan)
	}
	if len(materialized) != 1 ||
		!reflect.DeepEqual(materialized[0].ResolvedAddresses, []string{"192.0.2.10"}) ||
		!reflect.DeepEqual(materialized[0].Grant.Ports, []uint16{443}) {
		t.Fatalf("legacy fixture did not preserve its exact selected rectangle: %#v", materialized)
	}
}

func TestLauncherV2KeepsCompletedSiblingWhenLaterUnitFails(t *testing.T) {
	now := time.Now().UTC()
	units := launcherV2TestUnits(t, now)
	plan := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
		launcherV2TestPlannedUnit(1, launcherV2UnitB, launcherV2ScopeB),
	)
	outputRoot := t.TempDir()
	temporaryRoot := t.TempDir()
	calls := 0
	runner := func(command invocation) launcherV2RunResult {
		calls++
		output, ok := argumentValue(command.Args, "-output")
		if !ok {
			t.Fatal("Naabu invocation has no output path")
		}
		if calls == 1 {
			value := []byte(`{"host":"192.0.2.10","port":443,"protocol":"tcp"}` + "\n")
			if err := os.WriteFile(output, value, 0o600); err != nil {
				t.Fatal(err)
			}
			return launcherV2RunResult{Outcome: launcherV2RunSucceeded}
		}
		return launcherV2RunResult{Outcome: launcherV2RunFailed, Err: errors.New("fixture failure")}
	}
	err := runNaabuLauncherV2(outputRoot, temporaryRoot, plan, units, "172.30.0.1:1080", nil, now, runner)
	if err == nil {
		t.Fatal("partial launcher-v2 invocation lost its diagnostic outcome")
	}
	if !launcherOutcomeIsProcessSuccess(err) {
		t.Fatalf("a closed partial journal must remain available to the host: %v", err)
	}
	if !strings.Contains(err.Error(), "unit-000001 scanner: fixture failure") {
		t.Fatalf("bounded technical diagnostics lost the actionable scanner error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("later work units did not continue after a failure: %d calls", calls)
	}
	records := launcherV2Records(t, outputRoot)
	if len(records) != 3 || records[0]["execution_attempt"] != float64(1) || records[1]["outcome"] != "tested_complete" || records[2]["outcome"] != "failed" {
		t.Fatalf("unexpected launcher-v2 lifecycle: %#v", records)
	}
	journalBytes := mustReadFile(t, filepath.Join(outputRoot, launcherV2Directory, launcherV2JournalName))
	for _, secret := range []string{"a.example.test", "b.example.test", "192.0.2.10", "192.0.2.20", "fixture failure"} {
		if bytes.Contains(journalBytes, []byte(secret)) {
			t.Fatalf("journal exposed target material %q", secret)
		}
	}
	artifact := records[1]["final_artifact"].(map[string]any)
	relative := artifact["relative_path"].(string)
	if relative != "launcher-v2/units/unit-000000/attempt-1.jsonl" {
		t.Fatalf("final artifact path used identity data instead of its ordinal: %s", relative)
	}
	if _, err := os.Stat(filepath.Join(outputRoot, filepath.FromSlash(relative))); err != nil {
		t.Fatalf("completed sibling artifact was lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputRoot, launcherV2Directory, "units", "unit-000001", "attempt-1.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("failed unit claimed a final artifact: %v", err)
	}
}

func TestLauncherV2PublishesCompletedEmptyEvidenceWithExactDigest(t *testing.T) {
	now := time.Now().UTC()
	units := launcherV2TestUnits(t, now)
	plan := launcherV2TestPlan(^uint32(0),
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	runner := func(invocation) launcherV2RunResult {
		return launcherV2RunResult{Outcome: launcherV2RunSucceeded}
	}
	outputRoot := t.TempDir()
	if err := runNaabuLauncherV2(outputRoot, t.TempDir(), plan, units, "172.30.0.1:1080", nil, now, runner); err != nil {
		t.Fatal(err)
	}
	records := launcherV2Records(t, outputRoot)
	artifact := records[1]["final_artifact"].(map[string]any)
	if artifact["sha256"] != emptySHA256 || artifact["byte_length"] != float64(0) || artifact["attempt"] != float64(^uint32(0)) {
		t.Fatalf("completed-empty identity is not exact: %#v", artifact)
	}
	path := filepath.Join(outputRoot, filepath.FromSlash(artifact["relative_path"].(string)))
	if metadata, err := os.Stat(path); err != nil || metadata.Size() != 0 {
		t.Fatalf("completed-empty artifact is not an exact zero-byte file: %v %#v", err, metadata)
	}
}

func TestLauncherV2PreservesValidObservationsFromFailedScannerAsTestedPartial(t *testing.T) {
	now := time.Now().UTC()
	units := launcherV2TestUnits(t, now)
	plan := launcherV2TestPlan(3,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	runner := func(command invocation) launcherV2RunResult {
		output, _ := argumentValue(command.Args, "-output")
		value := []byte(`{"host":"192.0.2.10","port":443,"protocol":"tcp"}` + "\n")
		if err := os.WriteFile(output, value, 0o600); err != nil {
			t.Fatal(err)
		}
		return launcherV2RunResult{Outcome: launcherV2RunTimedOut, Err: errors.New("fixture timeout")}
	}
	outputRoot := t.TempDir()
	if err := runNaabuLauncherV2(outputRoot, t.TempDir(), plan, units, "172.30.0.1:1080", nil, now, runner); err == nil {
		t.Fatal("tested-partial invocation lost its diagnostic outcome")
	} else if !launcherOutcomeIsProcessSuccess(err) {
		t.Fatalf("tested-partial evidence must reach host normalization: %v", err)
	}
	records := launcherV2Records(t, outputRoot)
	if records[1]["outcome"] != "tested_partial" || records[1]["incomplete_reason"] != "timed_out" || records[1]["final_artifact"] == nil {
		t.Fatalf("valid partial observations were discarded: %#v", records[1])
	}
	if _, err := os.Stat(filepath.Join(outputRoot, launcherV2Directory, "quarantine", "unit-000000", "attempt-3.raw.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("valid partial evidence was also misclassified as quarantine: %v", err)
	}
}

func TestLauncherV2DoesNotClaimEmptyInterruptedRunAsTestedPartial(t *testing.T) {
	now := time.Now().UTC()
	plan := launcherV2TestPlan(2,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	runner := func(invocation) launcherV2RunResult {
		return launcherV2RunResult{Outcome: launcherV2RunTimedOut, Err: errors.New("fixture timeout")}
	}
	outputRoot := t.TempDir()
	if err := runNaabuLauncherV2(outputRoot, t.TempDir(), plan, launcherV2TestUnits(t, now), "172.30.0.1:1080", nil, now, runner); err == nil {
		t.Fatal("empty interrupted invocation lost its diagnostic outcome")
	} else if !launcherOutcomeIsProcessSuccess(err) {
		t.Fatalf("an exact timed-out outcome must reach host continuation: %v", err)
	}
	record := launcherV2Records(t, outputRoot)[1]
	if record["outcome"] != "timed_out" || record["final_artifact"] != nil || record["incomplete_reason"] != nil {
		t.Fatalf("empty interrupted invocation claimed tested coverage: %#v", record)
	}
}

func TestLauncherV2QuarantinesExactRawOutputWhenNormalizationFails(t *testing.T) {
	now := time.Now().UTC()
	units := launcherV2TestUnits(t, now)
	plan := launcherV2TestPlan(1,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	raw := []byte("not-json\n")
	runner := func(command invocation) launcherV2RunResult {
		output, _ := argumentValue(command.Args, "-output")
		if err := os.WriteFile(output, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return launcherV2RunResult{Outcome: launcherV2RunSucceeded}
	}
	outputRoot := t.TempDir()
	if err := runNaabuLauncherV2(outputRoot, t.TempDir(), plan, units, "172.30.0.1:1080", nil, now, runner); err == nil {
		t.Fatal("malformed evidence did not retain its diagnostic outcome")
	} else if !launcherOutcomeIsProcessSuccess(err) {
		t.Fatalf("a journaled failed unit must still reach host continuation: %v", err)
	}
	records := launcherV2Records(t, outputRoot)
	if records[1]["outcome"] != "failed" || records[1]["final_artifact"] != nil {
		t.Fatalf("malformed evidence claimed tested coverage: %#v", records[1])
	}
	quarantine := filepath.Join(outputRoot, launcherV2Directory, "quarantine", "unit-000000", "attempt-1.raw.jsonl")
	if got := mustReadFile(t, quarantine); !bytes.Equal(got, raw) {
		t.Fatalf("raw quarantine changed scanner bytes: %q", got)
	}
}

func TestLauncherFatalErrorsStillUseTheFailureExitContract(t *testing.T) {
	if launcherOutcomeIsProcessSuccess(errors.New("fatal launcher failure")) {
		t.Fatal("ordinary launcher errors must retain the nonzero process contract")
	}
}

func TestLauncherV2HeaderAloneModelsInterruptionWithoutInventedTerminal(t *testing.T) {
	plan := launcherV2TestPlan(7,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	outputRoot := t.TempDir()
	journal, err := createLauncherV2Journal(outputRoot, plan, &launcherV2ByteBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.file.Close(); err != nil {
		t.Fatal(err)
	}
	records := launcherV2Records(t, outputRoot)
	if len(records) != 1 || records[0]["record_type"] != "header" || records[0]["execution_attempt"] != float64(7) {
		t.Fatalf("interrupted journal invented terminal truth: %#v", records)
	}
}

func TestLauncherV2EmitsTheRustGoldenJournalContract(t *testing.T) {
	plan := launcherV2TestPlan(7,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	plan.EngineRunID = "run-opaque"
	outputRoot := t.TempDir()
	journal, err := createLauncherV2Journal(outputRoot, plan, &launcherV2ByteBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.appendAttempt(launcherV2AttemptFinished{
		RecordType:       "attempt_finished",
		UnitID:           launcherV2UnitA,
		ScopeSHA256:      launcherV2ScopeA,
		Attempt:          7,
		Outcome:          "tested_partial",
		IncompleteReason: "timed_out",
		FinalArtifact: &launcherV2FinalArtifact{
			EngineRunID:  "run-opaque",
			UnitID:       launcherV2UnitA,
			ScopeSHA256:  launcherV2ScopeA,
			Attempt:      7,
			RelativePath: "launcher-v2/units/unit-000000/attempt-7.jsonl",
			SHA256:       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			ByteLength:   12,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.file.Close(); err != nil {
		t.Fatal(err)
	}

	actual := string(mustReadFile(t, filepath.Join(outputRoot, launcherV2Directory, launcherV2JournalName)))
	if actual != launcherV2RustGoldenJournal {
		t.Fatalf("Go journal bytes drifted from the Rust golden contract:\n%s", actual)
	}
}

func TestLauncherV2OneJournalCannotAmbiguouslyMergeHostRetries(t *testing.T) {
	plan := launcherV2TestPlan(7,
		launcherV2TestPlannedUnit(0, launcherV2UnitA, launcherV2ScopeA),
	)
	journal, err := createLauncherV2Journal(t.TempDir(), plan, &launcherV2ByteBudget{})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.file.Close()
	terminal := launcherV2AttemptFinished{
		RecordType: "attempt_finished", UnitID: launcherV2UnitA, ScopeSHA256: launcherV2ScopeA,
		Attempt: 7, Outcome: "failed",
	}
	if err := journal.appendAttempt(terminal); err != nil {
		t.Fatal(err)
	}
	if err := journal.appendAttempt(terminal); err == nil {
		t.Fatal("one invocation journal accepted a duplicate terminal")
	}
	terminal.Attempt = 8
	if err := journal.appendAttempt(terminal); err == nil {
		t.Fatal("one invocation journal accepted a different host retry attempt")
	}
}

func TestLauncherV2PlanAndPathsRequireGeneratedWorkUnitIdentity(t *testing.T) {
	units := launcherV2TestUnits(t, time.Now().UTC())
	if !launcherV2OpaqueID("unit:opaque") {
		t.Fatal("backward-compatible generic opaque colon ID was rejected")
	}
	if !launcherV2WorkUnitID(launcherV2UnitA) {
		t.Fatal("generated work-unit identity was rejected")
	}
	for _, unsafe := range []string{"", "target/name", "target name", strings.Repeat("a", maxLauncherV2OpaqueIDBytes+1)} {
		if launcherV2OpaqueID(unsafe) {
			t.Fatalf("unsafe opaque identity accepted: %q", unsafe)
		}
	}
	for _, unsafe := range []string{"../result.jsonl", "/absolute.jsonl", "unit:opaque/result.jsonl", "units//result.jsonl", `units\result.jsonl`} {
		if launcherV2RelativePath(unsafe) {
			t.Fatalf("unsafe relative path accepted: %q", unsafe)
		}
	}

	valid := launcherV2TestPlan(^uint32(0),
		launcherV2TestPlannedUnit(1, launcherV2UnitA, launcherV2ScopeA),
	)
	if _, err := loadLauncherV2Plan(writeLauncherV2TestPlan(t, valid), "naabu", units); err != nil {
		t.Fatalf("valid host-frozen subset rejected: %v", err)
	}
	invalidID := *valid
	invalidID.RequestedWorkUnits = append([]launcherV2PlannedUnit(nil), valid.RequestedWorkUnits...)
	invalidID.RequestedWorkUnits[0].UnitID = "a.example.test"
	if _, err := loadLauncherV2Plan(writeLauncherV2TestPlan(t, &invalidID), "naabu", units); err == nil {
		t.Fatal("target-shaped unsafe unit identity was accepted")
	}
	invalidGrant := *valid
	invalidGrant.RequestedWorkUnits = append([]launcherV2PlannedUnit(nil), valid.RequestedWorkUnits...)
	invalidGrant.RequestedWorkUnits[0].GrantIndex = uint32(len(valid.FrozenGrants))
	if _, err := loadLauncherV2Plan(writeLauncherV2TestPlan(t, &invalidGrant), "naabu", units); err == nil {
		t.Fatal("host sidecar grant index outside the frozen corpus was accepted")
	}
}

func TestLauncherV2SharedBudgetRejectsRawArtifactBeforePartialPublish(t *testing.T) {
	outputRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(outputRoot, launcherV2Directory), 0o700); err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(t.TempDir(), "raw.jsonl")
	if err := os.WriteFile(rawPath, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	maximumPayload := int64(maxEvidenceBytes - maxLauncherV2JournalBytes)
	budget := &launcherV2ByteBudget{payloadUsed: maximumPayload - 2}
	if published, err := quarantineLauncherV2Raw(outputRoot, rawPath, 0, 1, budget); err == nil || published {
		t.Fatalf("aggregate overflow was published: published=%v err=%v", published, err)
	}
	if budget.payloadUsed != maximumPayload-2 {
		t.Fatalf("rejected artifact consumed budget: %d", budget.payloadUsed)
	}
	final := filepath.Join(outputRoot, launcherV2Directory, "quarantine", "unit-000000", "attempt-1.raw.jsonl")
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatalf("aggregate overflow left a final artifact: %v", err)
	}
	if _, err := os.Stat(final + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("aggregate overflow left a staged artifact: %v", err)
	}
}

func TestLauncherV2IsExplicitlyOptInAndLegacyArgumentsRemainDisabled(t *testing.T) {
	options, err := validateLauncherV2Options(0, "", "naabu")
	if err != nil || options != nil {
		t.Fatalf("legacy launcher unexpectedly enabled v2: %#v %v", options, err)
	}
	if _, err := validateLauncherV2Options(launcherPlanCurrentVersion, journalPlanMountPath, "naabu"); err == nil {
		t.Fatal("plan schema version was incorrectly accepted as the journal opt-in")
	}
	if _, err := validateLauncherV2Options(launcherJournalSchemaVersion, journalPlanMountPath, "httpx"); err == nil {
		t.Fatal("launcher-v2 was enabled for an unimplemented engine")
	}
	if _, err := validateLauncherV2Options(launcherJournalSchemaVersion, "/tmp/untrusted.json", "naabu"); err == nil {
		t.Fatal("launcher-v2 accepted an arbitrary host path")
	}
	if options, err := validateLauncherV2Options(launcherJournalSchemaVersion, journalPlanMountPath, "naabu"); err != nil || options == nil {
		t.Fatalf("current launcher opt-in was rejected: %#v %v", options, err)
	}
}

func TestLauncherV2ReportsMissingScannerAsActionableTechnicalDiagnostic(t *testing.T) {
	result := runCommandForLauncherV2(invocation{
		Program: filepath.Join(t.TempDir(), "missing-naabu"),
		Expiry:  time.Now().Add(time.Minute),
		Timeout: time.Second,
	})
	if result.Outcome != launcherV2RunFailed || result.Err == nil || !strings.Contains(result.Err.Error(), "scanner executable is unavailable") {
		t.Fatalf("missing scanner collapsed into a generic failure: %#v", result)
	}
}

func TestLauncherV2TechnicalDiagnosticsAreBoundedAndSingleLine(t *testing.T) {
	diagnostics := &launcherV2Diagnostics{}
	for index := 0; index < maxLauncherV2Diagnostics+3; index++ {
		diagnostics.add(index, "scanner", errors.New(strings.Repeat("x", maxLauncherV2DiagnosticBytes+20)+"\nprivate continuation"))
	}
	summary := diagnostics.summary()
	if strings.Contains(summary, "\n") || strings.Contains(summary, "private continuation") {
		t.Fatalf("diagnostic control or overflow text escaped its bound: %q", summary)
	}
	if len(diagnostics.entries) != maxLauncherV2Diagnostics || diagnostics.omitted != 3 || !strings.Contains(summary, "3 additional diagnostic(s) omitted") {
		t.Fatalf("diagnostic entry bound drifted: %#v %q", diagnostics, summary)
	}
}
