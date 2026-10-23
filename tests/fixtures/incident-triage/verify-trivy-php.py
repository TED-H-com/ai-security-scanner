#!/usr/bin/env python3
"""Run real upstream Trivy against inert OCI fixtures, never a remote target.

Usage: python3 verify-trivy-php.py TRIVY_BINARY DB_CACHE OUTPUT_DIRECTORY
The cache must already contain an official Trivy DB with the PHP advisories.
No database download or fixture program execution occurs here.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

binary, cache, output = map(lambda x: Path(x).resolve(), sys.argv[1:])
spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('generate-php-oci.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
expected = {'CVE-2026-109618', 'CVE-2026-109619'}
proof = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
         'database_metadata': json.loads((cache / 'db/metadata.json').read_text()), 'results': []}
for name, version in [('php-vulnerable', '8.3.6-0ubuntu0.24.04.12'), ('php-fixed', '8.3.6-0ubuntu0.24.04.13')]:
    image = output / name
    fixture.generate(image, version)
    report = output / (name + '.json')
    command = [str(binary), 'image', '--input', str(image), '--cache-dir', str(cache),
               '--cache-backend', 'memory', '--skip-db-update', '--skip-java-db-update',
               '--offline-scan', '--pkg-types', 'os', '--skip-version-check',
               '--disable-telemetry', '--skip-vex-repo-update', '--scanners', 'vuln',
               '--format', 'json', '--output', str(report)]
    subprocess.run(command, check=True, timeout=60)
    raw = report.read_bytes()
    data = json.loads(raw)
    assert data['Metadata']['OS']['Family'] == 'ubuntu', 'OS analyzer did not run'
    rows = [v for r in data.get('Results', []) for v in r.get('Vulnerabilities') or []
            if v['VulnerabilityID'] in expected]
    assert {v['VulnerabilityID'] for v in rows} == (expected if name == 'php-vulnerable' else set())
    for row in rows:
        assert row['PkgName'] == 'php8.3-cli'
        assert row['InstalledVersion'] == version
        assert row['FixedVersion'] == '8.3.6-0ubuntu0.24.04.13'
    proof['results'].append({'fixture': name, 'installed_version': version,
                            'matched_advisory_ids': sorted(v['VulnerabilityID'] for v in rows),
                            'raw_report_sha256': hashlib.sha256(raw).hexdigest()})
(output / 'execution-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
print('PASS: both PHP advisories match the vulnerable package and not the vendor-fixed package.')
