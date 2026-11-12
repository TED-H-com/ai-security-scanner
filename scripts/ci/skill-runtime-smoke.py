#!/usr/bin/env python3
"""Owned, synthetic Gitleaks -> saved report -> complete archive/restore smoke.

Runs only after an operator selects the already-built CLI/cache. No image pull,
runtime installation, unrelated target, credential, or cleanup is performed.
All outputs remain in a new private directory printed before execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
runner = parser.add_mutually_exclusive_group(required=True)
runner.add_argument('--cli')
runner.add_argument('--cache-dir')
parser.add_argument('--revision')
parser.add_argument('--profile', default='dev', choices=['dev', 'release'])
parser.add_argument('--allow-dirty', action='store_true')
parser.add_argument('--output-parent', default=tempfile.gettempdir())
args = parser.parse_args()
if not __debug__:
    parser.error('Run without Python optimization so every verification remains enabled.')
if os.name != 'posix':
    parser.error('This opt-in real runtime check requires a local Unix Docker socket.')
if args.cache_dir and (not args.revision or len(args.revision) != 40):
    parser.error('--cache-dir requires the selected full --revision.')
repository = Path(__file__).resolve().parents[2]
env = os.environ.copy()
env.pop('AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE', None)
env.pop('AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY', None)
endpoint = env.get('DOCKER_HOST') or subprocess.run(
    ['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
    check=True, capture_output=True, text=True, timeout=15).stdout.strip()
assert endpoint.startswith('unix://'), 'This fixture smoke requires the already-running local Docker Unix socket.'
env['DOCKER_HOST'] = endpoint
env.pop('DOCKER_CONTEXT', None)
catalog = json.loads((repository / 'engines/catalog.json').read_text())
engine = next(item for item in catalog if item['id'] == 'gitleaks')
pin = engine['image']['repository'] + '@' + engine['image']['digest']
assert not engine.get('network_destinations'), 'The selected owned Gitleaks fixture must not need target networking.'
subprocess.run(['docker', '--host', endpoint, 'image', 'inspect', pin],
               check=True, stdout=subprocess.DEVNULL, timeout=15)

root = Path(tempfile.mkdtemp(prefix='scanner-owned-gitleaks-', dir=args.output_parent)).resolve()
root.chmod(0o700)
print(json.dumps({'private_evidence_directory': str(root), 'selected_image': pin}), flush=True)
data = root / 'data'
selected = root / 'owned-fixture'

def fixture_manifest(directory):
    assert stat.S_ISDIR(directory.lstat().st_mode), 'The fixture root must be a real directory.'
    files = []
    for parent, directories, names in os.walk(directory, followlinks=False):
        for name in directories:
            assert stat.S_ISDIR((Path(parent) / name).lstat().st_mode), 'Fixture links are not allowed.'
        for name in names:
            path = Path(parent) / name
            assert stat.S_ISREG(path.lstat().st_mode), 'Fixture files must be regular and cannot be links.'
            content = path.read_bytes()
            files.append({'path': path.relative_to(directory).as_posix(),
                          'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
    return sorted(files, key=lambda file: file['path'])

fixture_source = repository / 'engines/images/gitleaks/testdata'
fixture_files = fixture_manifest(fixture_source)
shutil.copytree(fixture_source, selected, symlinks=True)
selected.chmod(0o700)
assert fixture_manifest(selected) == fixture_files
if args.cli:
    base = [str(Path(args.cli).resolve(strict=True))]
else:
    assert args.revision and len(args.revision) == 40
    bootstrap = ['node', str(repository / 'scripts/skill/bootstrap.mjs')]
    bootstrap_options = ['--revision', args.revision, '--cache-dir', str(Path(args.cache_dir).resolve()),
                         '--profile', args.profile, '--offline']
    if args.allow_dirty:
        bootstrap_options.append('--allow-dirty')
    base = bootstrap + ['run', *bootstrap_options, '--']

def save(name, value):
    destination = root / name
    destination.write_text(json.dumps(value, indent=2) + '\n')
    destination.chmod(0o600)

def execute(name, command):
    process = subprocess.Popen(command, cwd=repository, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=600)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        print(f'{name}: requesting cancellation and awaiting the owning process; evidence is retained in {root}', flush=True)
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        # Let the fixed CLI settle runtime operations and persist receipts. A
        # test timeout must not force-kill the owner and orphan its containers.
        stdout, stderr = process.communicate()
    for suffix, value in [('stdout', stdout), ('stderr', stderr)]:
        path = root / (name + '.' + suffix)
        path.write_bytes(value)
        path.chmod(0o600)
    assert process.returncode == 0, f'{name} failed with {process.returncode}; retained output in {root}'
    return json.loads(stdout)

def invoke(name, *parameters, workspace=data):
    return execute(name, base + ['--json', '--data-dir', str(workspace), *map(str, parameters)])

identity = invoke('identity', 'build-identity')
assert not data.exists()
if args.cli:
    prepared = invoke('runtime-prepare', 'runtime', 'prepare', '--engine', 'gitleaks', '--offline')
else:
    preparation = execute('bootstrap-scan-prepare', bootstrap + ['prepare', *bootstrap_options,
                          '--capability', 'scan', '--engine', 'gitleaks', '--data-dir', str(data)])
    assert preparation['cache_hit'], 'Selected runtime preparation must reuse the already verified core.'
    prepared = preparation['runtime_preparation']
assert prepared['ready'] and prepared['engines'] == ['gitleaks']
assert len(prepared['images']) == 1 and prepared['images'][0]['image'] == pin
assert prepared['images'][0]['status'] == 'ready'
assert not (data / 'casework.db').exists()
case = invoke('create-case', 'case', 'create', '--title', 'Owned synthetic Gitleaks verification',
              '--organization', 'Synthetic development fixture', '--requested-activity', 'local-artifact-analysis')
case_id = case['id']
attached = invoke('attach-source', 'source', 'attach-workspace', '--case-id', case_id,
                  '--label', 'Owned inert upstream testdata', '--path', selected,
                  '--profile', 'repository-working-tree')
invoke('approve-owned-scope', 'scope', 'approve', '--case-id', case_id,
       '--asset-id', attached['asset_id'], '--permission', 'local-artifact-read',
       '--confirmed-by', 'Owner of this isolated synthetic development fixture')
terminal = invoke('scan-terminal', 'scan', 'run', '--case-id', case_id, '--engine', 'gitleaks', '--wait')
run_id = terminal['run_id']
case = invoke('scanned-case', 'case', 'show', case_id)
run = next(item for item in case['scan_runs'] if item['id'] == run_id)
assert len(run['engine_runs']) == 1 and run['engine_runs'][0]['engine_id'] == 'gitleaks'
assert run['engine_runs'][0]['status'] == 'completed'
assert case['findings'], 'A meaningful synthetic secret finding is required.'
raw = next(item for item in case['raw_artifacts'] if item['relative_path'].endswith('/gitleaks.json'))
raw_path = data / 'artifacts' / raw['relative_path']
raw_bytes = raw_path.read_bytes()
assert hashlib.sha256(raw_bytes).hexdigest() == raw['sha256']
findings = json.loads(raw_bytes)
assert any(item['RuleID'] == 'generic-api-key' for item in findings)
assert all(item['Secret'] == 'REDACTED' for item in findings)
assert b'z9K4mP7qR2sT8vW3xY6a' not in raw_bytes
status = invoke('saved-status', 'scan', 'status', '--case-id', case_id, '--run-id', run_id)
assert status['command_receipts'], 'Foreground command receipt must survive reopen.'

snapshot = root / 'gitleaks.snapshot.json'
invoke('snapshot', 'report', 'snapshot', '--case-id', case_id, '--run-id', run_id,
       '--destination', snapshot, '--acknowledge-private-context')
report_hashes = {}
for format_ in ['html', 'json']:
    original = root / ('report.' + format_)
    replay = root / ('replay.' + format_)
    invoke('retrieve-' + format_, 'report', 'retrieve', '--snapshot', snapshot,
           '--format', format_, '--destination', original)
    invoke('replay-' + format_, 'report', 'replay', '--snapshot', snapshot,
           '--format', format_, '--destination', replay)
    assert original.read_bytes() == replay.read_bytes()
    report_hashes[format_] = hashlib.sha256(original.read_bytes()).hexdigest()
archive = root / 'case.scanner-archive.tar.gz'
invoke('archive-create', 'archive', 'create', '--case-id', case_id, '--destination', archive,
       '--include-source-snapshots', '--report-snapshot', snapshot, '--acknowledge-sensitive-data')
verified = invoke('archive-verify', 'archive', 'verify', '--archive', archive)
assert verified['integrity_valid'] and verified['source_snapshots_included']
# Keep every original byte for review while making its recorded location
# unavailable to restore and report replay.
data.rename(root / 'retained-original-workspace')
selected.rename(root / 'retained-original-source')
snapshot.rename(root / 'retained-original.snapshot.json')
restored = root / 'restored'
invoke('restore-preview', 'archive', 'restore-preview', '--archive', archive, '--destination', restored)
restore_receipt = invoke('restore', 'archive', 'restore', '--archive', archive, '--destination', restored,
                         '--acknowledge-sensitive-data')
assert not restore_receipt['restores_scan_authority']
for relative, digest in restore_receipt['files'].items():
    assert hashlib.sha256((restored / relative).read_bytes()).hexdigest() == digest
portable_case = json.loads((restored / 'case.json').read_text())
assert portable_case['case'] == case
original_case = json.loads((restored / 'original-case.json').read_text())
restored_case = invoke('restored-case', 'case', 'show', case_id, workspace=restored)
assert original_case['findings'] == case['findings']
assert restored_case['findings'] == case['findings']
assert restored_case['scope_grants'] == []
assert restored_case['raw_artifacts'] == case['raw_artifacts']
for artifact in restored_case['raw_artifacts']:
    content = (restored / 'artifacts' / artifact['relative_path']).read_bytes()
    assert hashlib.sha256(content).hexdigest() == artifact['sha256']
restored_status = invoke('restored-status', 'scan', 'status', '--case-id', case_id,
                         '--run-id', run_id, workspace=restored)
assert restored_status['command_receipts'] == status['command_receipts']
assert not data.exists() and not selected.exists()
restored_snapshots = list((restored / 'report-snapshots').rglob('*.json'))
assert restored_snapshots, 'Restoration must retain usable report snapshots.'
replayed_from_archive = False
for snapshot_path in restored_snapshots:
    candidate = json.loads(snapshot_path.read_text())
    if not isinstance(candidate, dict) or 'schema_version' not in candidate:
        continue
    if not str(candidate['schema_version']).startswith('ai-security-scanner.report-snapshot/'):
        continue
    for format_ in ['html', 'json']:
        original = root / ('restored-report.' + format_)
        replay = root / ('restored-report-replay.' + format_)
        invoke('restored-retrieve-' + format_, 'report', 'retrieve', '--snapshot', snapshot_path,
               '--format', format_, '--destination', original, workspace=restored)
        invoke('restored-replay-' + format_, 'report', 'replay', '--snapshot', snapshot_path,
               '--format', format_, '--destination', replay, workspace=restored)
        assert original.read_bytes() == replay.read_bytes()
        assert hashlib.sha256(original.read_bytes()).hexdigest() == report_hashes[format_]
    replayed_from_archive = True
    break
assert replayed_from_archive
summary = {
    'schema_version': 'ai-security-scanner.owned-gitleaks-smoke/v1',
    'real_upstream_execution': True, 'target': 'owned synthetic fixture only',
    'target_network': 'disabled', 'image': pin, 'identity': identity,
    'case_id': case_id, 'run_id': run_id, 'finding_count': len(case['findings']),
    'fixture': {'repository_path': 'engines/images/gitleaks/testdata',
                'files': fixture_files, 'source_snapshot_sha256': attached['snapshot_sha256']},
    'raw_sha256': raw['sha256'], 'raw_secrets_fully_redacted': True,
    'report_sha256': report_hashes, 'restored_findings_and_evidence_equal': True,
    'restored_scope_disabled': True, 'foreground_receipt_preserved': True,
    'all_restored_payload_hashes_verified': True, 'source_snapshots_included': True,
    'original_locations_unavailable': True, 'restored_report_replay_equal': True,
    'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'directory': str(root),
}
save('receipt.json', summary)
print(json.dumps(summary, indent=2), flush=True)
