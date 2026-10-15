package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	databaseVersion = "14.19.0"
	databaseDigest  = "sha256:84264ef41853178707bccb091f5450c22e835f8a98f9961592c75690321093d9"
	fdwVersion      = "2.2.7"
	fdwDigest       = "sha256:28756ddfef21169f73e94129cabd51ef15ef81a266eaee8b302f5ec7cc1d8f4b"
	maxTreeBytes    = int64(512 * 1024 * 1024)
)

type installedVersion struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ImageDigest     string `json:"image_digest"`
	InstalledFrom   string `json:"installed_from"`
	LastCheckedDate string `json:"last_checked_date"`
	InstallDate     string `json:"install_date"`
	StructVersion   int    `json:"struct_version"`
}

type databaseVersions struct {
	FdwExtension  installedVersion `json:"fdw_extension"`
	EmbeddedDB    installedVersion `json:"embedded_db"`
	StructVersion int              `json:"struct_version"`
}

type provenance struct {
	SchemaVersion     string `json:"schema_version"`
	SteampipeRevision string `json:"steampipe_revision"`
	AWSPluginRevision string `json:"aws_plugin_revision"`
	FDWRevision       string `json:"fdw_revision"`
	DatabaseDigest    string `json:"database_digest"`
	FDWDigest         string `json:"fdw_digest"`
	AWSPluginSHA256   string `json:"aws_plugin_sha256"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "steampipe install preparation: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 3 {
		return errors.New("expected INSTALL_ROOT PLUGIN_BINARY SOURCE_DATE_EPOCH")
	}
	root, err := filepath.Abs(arguments[0])
	if err != nil || root != "/opt/seed" {
		return errors.New("install root is not the build-owned seed directory")
	}
	plugin, err := filepath.Abs(arguments[1])
	if err != nil || plugin != "/opt/input/steampipe-plugin-aws.plugin" {
		return errors.New("plugin path is not the build-owned input")
	}
	epochSeconds, err := parsePositiveInt64(arguments[2])
	if err != nil {
		return errors.New("source date epoch is invalid")
	}
	epoch := time.Unix(epochSeconds, 0).UTC()

	if err := verifyDownloadedVersions(root); err != nil {
		return err
	}
	if err := verifySignature(root); err != nil {
		return err
	}
	for _, relative := range []string{
		"config", "internal", "logs", "plugins", "backups",
		filepath.Join("db", databaseVersion, "data"),
	} {
		if err := os.RemoveAll(filepath.Join(root, relative)); err != nil {
			return fmt.Errorf("remove nondeterministic %s: %w", relative, err)
		}
	}
	if err := materializeSymlinks(filepath.Join(root, "db", databaseVersion, "postgres")); err != nil {
		return err
	}
	pluginDestination := filepath.Join(root, "plugins", "local", "aws", "steampipe-plugin-aws.plugin")
	pluginDigest, err := copyPlugin(plugin, pluginDestination)
	if err != nil {
		return err
	}
	if err := writeStableVersions(root, epoch); err != nil {
		return err
	}
	metadata := provenance{
		SchemaVersion:     "1.0.0",
		SteampipeRevision: "5c62651887b3e1d127049722e7216b915d4b075d",
		AWSPluginRevision: "d9a877878061013a49799c17b932616ee0ea415b",
		FDWRevision:       "290169e3e104eca604e9013159423027f6477d21",
		DatabaseDigest:    databaseDigest,
		FDWDigest:         fdwDigest,
		AWSPluginSHA256:   pluginDigest,
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "ai-security-scanner-provenance.json"), encoded, 0o444); err != nil {
		return err
	}
	if err := validateTree(root); err != nil {
		return err
	}
	return normalizeTimes(root, epoch)
}

func verifyDownloadedVersions(root string) error {
	path := filepath.Join(root, "db", "versions.json")
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open database versions: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	var versions databaseVersions
	if err := decoder.Decode(&versions); err != nil {
		return fmt.Errorf("parse database versions: %w", err)
	}
	if versions.StructVersion != 20220411 ||
		versions.EmbeddedDB.ImageDigest != databaseDigest ||
		versions.EmbeddedDB.InstalledFrom != "ghcr.io/turbot/steampipe/db:14.19.0" ||
		versions.FdwExtension.Version != fdwVersion ||
		versions.FdwExtension.ImageDigest != fdwDigest ||
		versions.FdwExtension.InstalledFrom != "ghcr.io/turbot/steampipe/fdw:2.2.7" {
		return errors.New("downloaded database or FDW provenance is not the exact release closure")
	}
	return nil
}

func verifySignature(root string) error {
	path := filepath.Join(root, "db", databaseVersion, "postgres", "signature")
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	expected := databaseDigest + "|" + fdwDigest
	if string(content) != expected {
		return errors.New("database binary signature does not match pinned OCI digests")
	}
	return nil
}

func materializeSymlinks(root string) error {
	var links []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			links = append(links, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(links)
	for _, link := range links {
		target, err := filepath.EvalSymlinks(link)
		if err != nil {
			return fmt.Errorf("resolve database symlink: %w", err)
		}
		relative, err := filepath.Rel(root, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("database symlink escapes the pinned install tree")
		}
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxTreeBytes {
			return errors.New("database symlink target is not a bounded regular file")
		}
		content, err := os.ReadFile(target)
		if err != nil {
			return err
		}
		if err := os.Remove(link); err != nil {
			return err
		}
		if err := os.WriteFile(link, content, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func copyPlugin(source, destination string) (string, error) {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1024 || info.Size() > maxTreeBytes {
		return "", errors.New("source-built AWS plugin is not a bounded regular binary")
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	if len(content) < 4 || string(content[:4]) != "\x7fELF" {
		return "", errors.New("source-built AWS plugin is not an ELF binary")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(destination, content, 0o555); err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func writeStableVersions(root string, epoch time.Time) error {
	timestamp := epoch.Format(time.RFC3339)
	versions := databaseVersions{
		FdwExtension: installedVersion{
			Name: "fdwExtension", Version: fdwVersion, ImageDigest: fdwDigest,
			InstalledFrom:   "ghcr.io/turbot/steampipe/fdw:2.2.7",
			LastCheckedDate: timestamp, InstallDate: timestamp,
		},
		EmbeddedDB: installedVersion{
			Name: "embeddedDB", ImageDigest: databaseDigest,
			InstalledFrom:   "ghcr.io/turbot/steampipe/db:14.19.0",
			LastCheckedDate: timestamp, InstallDate: timestamp,
		},
		StructVersion: 20220411,
	}
	encoded, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(filepath.Join(root, "db", "versions.json"), encoded, 0o444)
}

func validateTree(root string) error {
	var total int64
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("template contains unsupported path: %s", path)
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if info.Size() > maxTreeBytes || total > maxTreeBytes {
				return errors.New("template exceeds its 512 MiB build bound")
			}
		}
		return nil
	})
}

func normalizeTimes(root string, timestamp time.Time) error {
	var paths []string
	if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := os.Chtimes(path, timestamp, timestamp); err != nil {
			return err
		}
	}
	return nil
}

func parsePositiveInt64(value string) (int64, error) {
	var result int64
	if value == "" {
		return 0, errors.New("empty")
	}
	for _, character := range value {
		if character < '0' || character > '9' || result > (1<<63-1-int64(character-'0'))/10 {
			return 0, errors.New("invalid")
		}
		result = result*10 + int64(character-'0')
	}
	if result <= 0 {
		return 0, errors.New("not positive")
	}
	return result, nil
}
