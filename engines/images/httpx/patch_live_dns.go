// patch_live_dns applies the single reviewed source change used by the
// managed httpx image. The pinned upstream source hash and the resulting hash
// make source drift fail closed before compilation.
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	expectedSourcePath = "/src/httpx/runner/runner.go"
	expectedSourceSHA  = "649a47aac12f176000b3ea26fb62e1a395e30d6009fd2bee3fb5285b9943daa2"
	expectedPatchedSHA = "712382a9145071c020ee4f75ac71218e8bb9687dbab5980a813a1e59a00b6cfe"
	maximumSourceBytes = 4 * 1024 * 1024
)

const liveDNSBlock = `	var onlyHost string
	onlyHost, _, err = net.SplitHostPort(URL.Host)
	if err != nil {
		onlyHost = URL.Host
	}
	allIps, cnames, resolvers, err := getDNSData(hp, onlyHost)
	if err != nil {
		allIps = append(allIps, ip)
	}

	var ips4, ips6 []string
	for _, ip := range allIps {
		switch {
		case iputil.IsIPv4(ip):
			ips4 = append(ips4, ip)
		case iputil.IsIPv6(ip):
			ips6 = append(ips6, ip)
		}
	}
`

const frozenDNSBlock = `	// The managed image deliberately leaves DNS-derived result fields empty.
	// The request hostname still travels unchanged through the configured SOCKS
	// proxy, preserving the approved HTTP Host value and TLS SNI.
	var ips4, ips6, cnames, resolvers []string
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "managed httpx source patch failed")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 2 || arguments[0] != "--source" || arguments[1] != expectedSourcePath {
		return errors.New("arguments do not match the fixed source-patch contract")
	}
	return patchFile(arguments[1])
}

func patchFile(path string) error {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() <= 0 || metadata.Size() > maximumSourceBytes {
		return errors.New("pinned source is absent, non-regular, or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("pinned source could not be opened")
	}
	source, readErr := io.ReadAll(io.LimitReader(file, maximumSourceBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(source) > maximumSourceBytes {
		return errors.New("pinned source could not be read within its bound")
	}
	patched, err := patchPinnedSource(source)
	if err != nil {
		return err
	}

	temporary := filepath.Join(filepath.Dir(path), ".ai-security-scanner-runner.go.tmp")
	output, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, metadata.Mode().Perm())
	if err != nil {
		return errors.New("private patched source could not be created")
	}
	writeErr := func() error {
		if _, err := output.Write(patched); err != nil {
			return err
		}
		return output.Sync()
	}()
	closeErr = output.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		return errors.New("patched source could not be written")
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return errors.New("patched source could not replace the verified input")
	}
	return nil
}

func patchPinnedSource(source []byte) ([]byte, error) {
	if digest(source) != expectedSourceSHA {
		return nil, errors.New("pinned source pre-patch hash differs from the reviewed revision")
	}
	patched, err := replaceReviewedBlock(source)
	if err != nil {
		return nil, err
	}
	if digest(patched) != expectedPatchedSHA {
		return nil, errors.New("patched source hash differs from the reviewed result")
	}
	return patched, nil
}

func replaceReviewedBlock(source []byte) ([]byte, error) {
	if bytes.Count(source, []byte(liveDNSBlock)) != 1 || bytes.Contains(source, []byte(frozenDNSBlock)) {
		return nil, errors.New("reviewed live-DNS source block is absent, duplicated, or already changed")
	}
	return bytes.Replace(source, []byte(liveDNSBlock), []byte(frozenDNSBlock), 1), nil
}

func digest(value []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(value))
}
