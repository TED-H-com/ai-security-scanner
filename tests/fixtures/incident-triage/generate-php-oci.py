#!/usr/bin/env python3
"""Build inert Ubuntu package-metadata OCI fixtures; contains no PHP executable.

Usage: python3 generate-php-oci.py OUTPUT_DIRECTORY
Versions come from https://ubuntu.com/security/notices/USN-8948-1.
This is test input generation, not a vulnerability detector.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile


def generate(destination, version):
    destination.mkdir(parents=True, exist_ok=True)
    blobs = destination / 'blobs' / 'sha256'
    blobs.mkdir(parents=True, exist_ok=True)

    def blob(content, media_type):
        digest = hashlib.sha256(content).hexdigest()
        (blobs / digest).write_bytes(content)
        return {'mediaType': media_type, 'digest': 'sha256:' + digest, 'size': len(content)}

    def json_blob(value, media_type):
        return blob(json.dumps(value, sort_keys=True, separators=(',', ':')).encode(), media_type)

    files = {
        'etc/lsb-release': 'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=24.04\nDISTRIB_CODENAME=noble\n',
        'etc/os-release': 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
        'var/lib/dpkg/status': (
            'Package: php8.3-cli\nStatus: install ok installed\nPriority: optional\n'
            'Section: php\nInstalled-Size: 1\nArchitecture: amd64\nSource: php8.3\n'
            f'Version: {version}\nMaintainer: Fixture <fixture@example.invalid>\n'
            'Description: Inert package metadata fixture; no executable installed\n\n'
        ),
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content in sorted(files.items()):
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    layer = blob(buffer.getvalue(), 'application/vnd.oci.image.layer.v1.tar')
    config = json_blob({
        'architecture': 'amd64', 'os': 'linux',
        'rootfs': {'type': 'layers', 'diff_ids': [layer['digest']]},
        'config': {},
    }, 'application/vnd.oci.image.config.v1+json')
    manifest = json_blob({
        'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': config, 'layers': [layer],
    }, 'application/vnd.oci.image.manifest.v1+json')
    (destination / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (destination / 'index.json').write_text(json.dumps({
        'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
        'manifests': [manifest],
    }, sort_keys=True) + '\n')
    print(destination, manifest['digest'])


if __name__ == '__main__':
    root = Path(sys.argv[1])
    generate(root / 'php-vulnerable', '8.3.6-0ubuntu0.24.04.12')
    generate(root / 'php-fixed', '8.3.6-0ubuntu0.24.04.13')
