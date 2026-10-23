"""Regenerate a native JSON fixture with pinned Strix's report producer only.

Run from the repository root after checking out .upstreams/usestrix/strix at
0f81f40765f0329006a9a7d2eb97513f56743a9b. No scanner, agent, provider, telemetry,
project source, or network is initialized. Fixed AST-selected report methods
are evaluated with inert telemetry and persistence hooks.
"""
import ast
import csv
import io
import json
import logging
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

upstream = Path('.upstreams/usestrix/strix/strix')
state_ast = ast.parse((upstream / 'report/state.py').read_text())
writer_ast = ast.parse((upstream / 'report/writer.py').read_text())
state_class = next(node for node in state_ast.body if isinstance(node, ast.ClassDef) and node.name == 'ReportState')
method_names = {'add_vulnerability_report', '_next_report_id', '_deleted_vulnerability_reports'}
methods = [node for node in state_class.body if isinstance(node, ast.FunctionDef) and node.name in method_names]
assert len(methods) == len(method_names)
functions = [node for node in state_ast.body if isinstance(node, ast.FunctionDef) and node.name == '_clean_title']
functions += [node for node in writer_ast.body if isinstance(node, ast.FunctionDef) and node.name in {'write_vulnerabilities', 'atomic_write_text', 'csv_safe'}]

class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 10, 21, 12, 0, 0, tzinfo=UTC)

noop = SimpleNamespace(finding=lambda *args, **kwargs: None)
namespace = dict(Any=Any, Path=Path, datetime=FixedDatetime, UTC=UTC, json=json, csv=csv,
                 io=io, tempfile=tempfile, re=re, logger=logging.getLogger('fixture'),
                 posthog=noop, scarf=noop, _CONTROL_CHARS=re.compile(r'[\x00-\x1f\x7f]+'),
                 _CSV_FORMULA_PREFIXES=('=', '+', '-', '@', '\t', '\r'),
                 _SEVERITY_ORDER={'critical':0, 'high':1, 'medium':2, 'low':3, 'info':4},
                 render_vulnerability_md=lambda report: '# Inert fixture\n')
module = ast.Module(body=functions + methods, type_ignores=[])
exec(compile(ast.fix_missing_locations(module), 'pinned-strix-report-producer', 'exec'), namespace)
ReportProducer = type('ReportProducer', (), {name:namespace[name] for name in method_names})
producer = ReportProducer()
producer.vulnerability_reports = []
producer.run_record = {}
producer.vulnerability_found_callback = None
producer.save_run_data = lambda: None
producer.add_vulnerability_report(
    title='Untrusted command execution', severity='high', target='/workspace/app',
    description='Untrusted input reaches a shell', impact='Command execution',
    remediation_steps='Avoid shell execution and pass argument arrays.',
    confidence='medium', cvss=8.1, cwe='CWE-78',
    code_locations=[{'file':'src/handler.py','start_line':12,'end_line':12}],
    poc_script_code="raise RuntimeError('MUST NEVER EXECUTE')",
)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    namespace['write_vulnerabilities'](root, producer.vulnerability_reports, set())
    Path('tests/fixtures/external-scanners/strix-vulnerabilities.json').write_bytes((root / 'vulnerabilities.json').read_bytes())
