"""Boundary adapters for the drill's real ./chronicle update subprocess."""
import json
import os
from pathlib import Path
import sys

if sys.argv[1:4] != ['-m', 'chronicle_ops', 'update']:
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])

from test_forward_drill import ForwardUpgradeDrill
from chronicle_ops.__main__ import run_cli

request = json.loads(Path(os.environ['CHRONICLE_DRILL_STATE']).read_text())
fixture = ForwardUpgradeDrill()
for name in ('work', 'http', 'backups'):
    setattr(fixture, name, Path(request[name]))
fixture.sources = {version: Path(path) for version, path in request['sources'].items()}
fixture.container = request['container']
fixture.project = request['project']
ForwardUpgradeDrill.project = fixture.project
fixture.kill_rollback_phase = request.get('kill_rollback_phase')
fixture.classpath = request['classpath']
fixture.fail_version = request['fail_version']
fixture.kill_after_migration = request['kill_after_migration']
fixture.environment, fixture.stopped = [], False
with fixture.service_adapters():
    sys.exit(run_cli(sys.argv[3:]))
