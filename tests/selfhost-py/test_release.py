import os
from contextlib import ExitStack
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from chronicle_ops.env_migration import compose_names, merge_env
from chronicle_ops.release import MIGRATIONS_KEY, UPGRADE_FROM_MINIMUM, UPGRADE_FLOOR_KEY, compose_release, free_disk_floor, parse_version, read_manifest, require_current_owner
from chronicle_ops.receipts import OPERATOR_RECEIPTS_DIR
from selfhost_fixture import copy_selfhost_fixture
from test_secret_generation import SelfhostSetupFixture
from chronicle_ops.common import run


def complete_manifest_fixture(bundle, images=None):
    """Complete the small shell fixtures with the publisher's integrity contract."""
    import json
    import shutil
    from chronicle_ops.dump import file_sha256
    from chronicle_ops.envfile import read_env, value
    from chronicle_ops.images import IMAGE_INPUTS_KEY, SOURCE_IMAGES
    from chronicle_ops.migrations import MIGRATIONS_KEY, migration_hashes
    bundle = Path(bundle)
    manifest_path = bundle / 'release-manifest.json'
    version = json.loads(manifest_path.read_text())['release_version']
    host = bundle / 'selfhost'
    for name in ('restore.sh', 'network-subnet.py', 'rotate-secret.sh',
                 'docs/DEPLOYMENT-COMPATIBILITY.md', 'docs/SECRET-ROTATION.md', 'docs/UNINSTALL-DATA-DELETION.md'):
        target = host / name
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(__file__).resolve().parents[2] / 'selfhost' / name, target)
    template = host / '.env.example'
    if not template.exists():
        template.write_text(f'RELEASE_VERSION={version}\n' + ''.join(
            f'{image.variable}=fixture/{image.component}@sha256:' + 'a' * 64 + '\n' for image in SOURCE_IMAGES))
    copy_selfhost_fixture(host, preserve_existing=True)
    (host / 'docker-compose.yml').touch(exist_ok=True)
    from chronicle_ops.envfile import set_env_values
    settings = read_env(template)
    pins = {image.component: value(settings, image.variable) or f'fixture/{image.component}@sha256:' + 'a' * 64
            for image in SOURCE_IMAGES}
    if images:
        pins.update(images)
    template.write_text(set_env_values(template.read_text(),
                                      {image.variable: pins[image.component] for image in SOURCE_IMAGES}, require_existing=False))
    manifest = {'schema_version': 1, 'release_version': version, 'source_revision': 'a' * 40,
                UPGRADE_FLOOR_KEY: UPGRADE_FROM_MINIMUM, 'images': pins,
                MIGRATIONS_KEY: migration_hashes(Path(__file__).resolve().parents[2]),
                IMAGE_INPUTS_KEY: {image.component: 'a' * 40 for image in SOURCE_IMAGES},
                'files': {path.relative_to(bundle).as_posix(): file_sha256(path)
                          for path in bundle.rglob('*') if path.is_file() and path != manifest_path}}
    manifest_path.write_text(json.dumps(manifest))
    for path in [bundle, *bundle.rglob('*')]:
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)


def complete_update_fixture(root, version):
    import hashlib
    import tarfile
    root = Path(root)
    name = 'chronicle-selfhost-' + version
    archive_path = root / 'http' / (name + '.tar.gz')
    with tempfile.TemporaryDirectory(dir=root) as folder:
        with tarfile.open(archive_path) as archive:
            archive.extractall(folder)
        bundle = Path(folder) / name
        complete_manifest_fixture(bundle)
        with tarfile.open(archive_path, 'w:gz') as archive:
            archive.add(bundle, arcname=name)
    archive_path.with_suffix('.gz.sha256').write_text(
        hashlib.sha256(archive_path.read_bytes()).hexdigest() + '  ' + archive_path.name + '\n')
    docker = root / 'bin/docker'
    inventory = '''if [[ "$1 ${2:-}" == 'compose ls' ]]; then printf '[]\\n'; fi\n'''
    if inventory not in docker.read_text():
        with docker.open('a') as output:
            output.write(inventory)


class FreeDiskFloorLauncherTests(SelfhostSetupFixture):
    def floors(self, saved, inherited):
        text = (self.host / '.env').read_text()
        lines = [line for line in text.splitlines() if not line.startswith('MIN_FREE_DISK_GIB=')]
        if saved is not None:
            lines.append(f'MIN_FREE_DISK_GIB={saved}')
        (self.host / '.env').write_text('\n'.join(lines) + '\n')
        environment = {key: item for key, item in self.environment.items() if key != 'MIN_FREE_DISK_GIB'}
        if inherited is not None:
            environment['MIN_FREE_DISK_GIB'] = inherited
        # storage-check (startup) passes no settings; update and upgrade pass the parsed .env.
        script = (f'source {self.host / "chronicle"}\nneed_env\nops_python -c "from chronicle_ops.release import '
                  'free_disk_floor; from chronicle_ops.envfile import read_env; print(free_disk_floor({}), free_disk_floor(read_env(\'.env\')))"\n')
        result = run(['bash', '-c', script], cwd=self.host, env=environment, capture=True, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.split()

    def test_startup_and_update_resolve_the_same_floor_from_settings_then_environment_then_default(self):
        self.run_setup()
        for saved, inherited, expected in (('2', '0', '2'), (None, '0', '0'), (None, None, '5'), ('0', None, '0')):
            with self.subTest(saved=saved, inherited=inherited):
                self.assertEqual([expected, expected], self.floors(saved, inherited))


class ReleaseTests(unittest.TestCase):
    def test_free_disk_floor_prefers_env_file_then_environment_then_default(self):
        with patch.dict(os.environ, {'MIN_FREE_DISK_GIB': '0'}):
            self.assertEqual(free_disk_floor({'MIN_FREE_DISK_GIB': '2'}), '2')
            self.assertEqual(free_disk_floor({}), '0')
        with patch.dict(os.environ, clear=True):
            self.assertEqual(free_disk_floor({}), '5')

    def test_every_free_disk_reader_resolves_the_floor_through_the_one_owner(self):
        # update, upgrade, doctor and storage-check once read .env alone and ignored the CLI's precedence.
        import ast
        readers = []
        for path in sorted((ROOT / 'selfhost/chronicle_ops').glob('*.py')):
            tree = ast.parse(path.read_text())
            owners = {node for function in ast.walk(tree) if isinstance(function, ast.FunctionDef)
                      and function.name == 'free_disk_floor' for node in ast.walk(function)}
            readers += [f'{path.name}:{node.lineno}' for node in ast.walk(tree)
                        if isinstance(node, ast.Constant) and node.value == 'MIN_FREE_DISK_GIB' and node not in owners]
        self.assertEqual([], readers)

    def test_rollback_keeps_the_same_candidate_valid_and_archives_settings_privately(self):
        from chronicle_ops.restore import rollback
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            old, candidate, state = root / "old/selfhost", root / "candidate/selfhost", root / "state"
            old.mkdir(parents=True); candidate.mkdir(parents=True); state.mkdir()
            (old / "chronicle_ops").mkdir()
            (old / "chronicle_ops/__main__.py").touch()
            (candidate.parent / "release-manifest.json").write_text('{"release_version":"2.0.0"}')
            (candidate / "chronicle").touch()
            complete_manifest_fixture(candidate.parent)
            settings = f"COMPOSE_PROJECT_NAME=pilot\nCHRONICLE_STATE_DIR={state}\n"
            for host in (old, candidate):
                (host / ".env").write_text(settings)
                (host / ".env").chmod(0o600)
            (old / ".env.example").write_text(settings)
            operation = stack.enter_context(patch("chronicle_ops.restore.Restore"))
            operation.return_value.execute.return_value = 0
            for name in ("chronicle_ops.restore.acquire_operation_lock", "chronicle_ops.restore.release_operation_lock",
                         "chronicle_ops.restore.compose", "chronicle_ops.release.require_current_owner",
                         "chronicle_ops.env_migration.merge_env", "chronicle_ops.release.set_current_owner",
                         "chronicle_ops.reconcile.install", "chronicle_ops.reconcile.uninstall"):
                stack.enter_context(patch(name))
            stack.enter_context(patch("chronicle_ops.upgrade.start_release"))
            stack.enter_context(patch("chronicle_ops.common.run", return_value=subprocess.CompletedProcess([], 0)))
            stack.enter_context(patch.object(Path, "cwd", return_value=candidate))
            stack.enter_context(patch.dict(os.environ, {}, clear=True))
            self.assertEqual(rollback(old, "/backups/fixture.sql.gz", "a" * 64, True), 0)
            self.assertFalse((candidate / ".env").exists())
            archives = list((state / OPERATOR_RECEIPTS_DIR).glob(".env.rollback-*"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_text(), settings)
            self.assertEqual(archives[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(archives[0].parent.stat().st_mode & 0o777, 0o700)
            # This is the exact candidate validation performed at the next upgrade's entry.
            self.assertEqual(read_manifest(candidate.parent / "release-manifest.json", True)[0]["release_version"], "2.0.0")
            (candidate / "unlisted").write_text("unexpected file")
            with self.assertRaisesRegex(ValueError, "unlisted files"):
                read_manifest(candidate.parent / "release-manifest.json", True)

    def test_release_ownership_survives_disabled_reconciliation_and_uninstall(self):
        from chronicle_ops import reconcile, release
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder); active = state / 'active'; retired = state / 'retired'
            with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'false'}, clear=True), \
                 patch('chronicle_ops.release.compose_projects', return_value=[]), \
                 patch('chronicle_ops.reconcile.shutil.which', return_value=None):
                (state / 'reconcile.sh').write_text('cd ' + str(retired) + '\n')
                reconcile.install(active / 'chronicle', state, 'pilot')
                require_current_owner(active, state, 'pilot')
                reconcile.uninstall(state, 'pilot')
                self.assertFalse((state / 'reconcile.sh').exists())
                with self.assertRaisesRegex(ValueError, 'superseded'):
                    require_current_owner(retired, state, 'pilot')
                require_current_owner(active, state, 'pilot')
                # Rollback transfers ownership even with no schedule to update.
                reconcile.install(retired / 'chronicle', state, 'pilot', update_only=True)
                with self.assertRaisesRegex(ValueError, 'superseded'):
                    require_current_owner(active, state, 'pilot')
                require_current_owner(retired, state, 'pilot')
                self.assertEqual((state / release.OWNER_FILE).stat().st_mode & 0o777, 0o644)

    def test_superseded_release_cannot_mutate_live_project_or_state_owner(self):
        import json
        import shlex
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder); old = state / 'old'; active = state / 'active'
            for path in (old, active): path.mkdir()
            with patch('chronicle_ops.release.run', return_value=subprocess.CompletedProcess([], 0,
                    json.dumps([{'Name': 'pilot', 'ConfigFiles': str(active / 'docker-compose.yml')}]))):
                with self.assertRaisesRegex(ValueError, 'does not own'):
                    require_current_owner(old, state, 'pilot')
                require_current_owner(active, state, 'pilot')
            for output in ('malformed', '{}'):
                with patch('chronicle_ops.release.run', return_value=subprocess.CompletedProcess([], 0, output)), \
                     self.assertRaises(ValueError):
                    require_current_owner(old, state, 'pilot')
            (state / 'reconcile.sh').write_text('cd ' + shlex.quote(str(active)) + '\n')
            with patch('chronicle_ops.release.run', return_value=subprocess.CompletedProcess([], 0, '[]')):
                with self.assertRaisesRegex(ValueError, 'superseded'):
                    require_current_owner(old, state, 'pilot')
                require_current_owner(active, state, 'pilot')

    def test_compose_isolates_inherited_controls_and_all_interpolation_inputs(self):
        inherited = {"COMPOSE_FILE": "poison", "COMPOSE_PROFILES": "restore", "BACKEND_IMAGE": "poison",
                     "OPTIONAL_SETTING": "poison", "DOCKER_HOST": "unix:///docker.sock"}
        with patch.dict(os.environ, inherited, clear=True), patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "is_symlink", return_value=False), \
             patch("chronicle_ops.release.before_compose"), \
             patch.object(Path, "read_text", return_value="# BACKEND_IMAGE=fixture\nvalue: ${OPTIONAL_SETTING:-}\n"), \
             patch("chronicle_ops.release.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            compose_release(Path("/release"), "pilot", ["docker-compose.yml"], "up", "-d")
            self.assertEqual(run.call_args.args[0], ["docker", "compose", "--env-file", "/release/.env", "--project-name", "pilot", "-f", "/release/docker-compose.yml", "up", "-d"])
            environment = run.call_args.kwargs["env"]
            for key in inherited.keys() - {"DOCKER_HOST"}:
                self.assertNotIn(key, environment)
            self.assertEqual(environment["DOCKER_HOST"], inherited["DOCKER_HOST"])
            self.assertEqual(environment["CHRONICLE_HOST_UID"], str(os.getuid()))

    def test_compose_paths_reject_escape_duplicates_and_retired_modes(self):
        for text in ("../outside.yml", "docker-compose.yml:docker-compose.yml", "docker-compose.yml:overlays/mode-behind-proxy-public.yml", "docker-compose.yml::overlays/backups.yml"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                compose_names({"COMPOSE_FILE": text}, Path("/release"))

    def test_merge_keeps_operator_values_and_new_defaults_and_pins(self):
        old = {"PASSWORD": "'fixture'", "BACKEND_IMAGE": "old", "CUSTOM": "'keep me'"}
        template = "RELEASE_VERSION=2.0.0\nBACKEND_IMAGE=new\nPASSWORD=default\nCHRONICLE_STATE_DIR=.\nCOMPOSE_FILE=old\nNEW=default\n"
        with patch("chronicle_ops.env_migration.write_text") as write:
            merge_env(old, template, Path("/new/.env"), "/operator's state", ["docker-compose.yml"])
            content = write.call_args.args[1]
            for line in ("PASSWORD='fixture'", "BACKEND_IMAGE=new", 'CHRONICLE_STATE_DIR="/operator\'s state"', "COMPOSE_FILE=docker-compose.yml", "CUSTOM='keep me'", "NEW=default"):
                self.assertIn(line + "\n", content)

    def test_merge_preserves_current_proxy_and_dashboard_settings(self):
        old = {'DASHBOARD_PASSWORD_HASH': "'$2b$fixture'", 'CADDY_TRUSTED_PROXIES': "'127.0.0.1/32 ::1/128'",
               'DASHBOARD_ALLOWED_IPS': "'127.0.0.1/32 ::1/128'"}
        template = "DASHBOARD_PASSWORD_HASH='$2b$fixture'\nTESTING_LOGIN_ENABLED=false\nREQUIRE_MFA=false\nCADDY_TRUSTED_PROXIES=default\nDASHBOARD_ALLOWED_IPS=default\n"
        rendered = merge_env(old, template, None, '/state', ['overlays/mode-behind-proxy-internal.yml'])
        self.assertEqual(rendered, template.replace('default', "'127.0.0.1/32 ::1/128'"))

    def test_rollback_refuses_a_cli_without_the_current_operator_package(self):
        from chronicle_ops.restore import rollback
        with tempfile.TemporaryDirectory() as folder, patch('chronicle_ops.restore.Restore') as operation:
            with self.assertRaisesRegex(ValueError, 'current operator package'):
                rollback(folder, '/backups/fixture.sql.gz', 'a' * 64, True)
            operation.assert_not_called()

    def test_a_damaged_or_hand_edited_release_bundle_is_refused_before_it_is_used(self):
        import json
        import shutil
        with tempfile.TemporaryDirectory() as folder:
            pristine = Path(folder) / 'pristine'
            (pristine / 'selfhost').mkdir(parents=True)
            (pristine / 'release-manifest.json').write_text(json.dumps({'release_version': UPGRADE_FROM_MINIMUM}))
            (pristine / 'selfhost/chronicle').touch()
            import_path = sys.path[:]
            complete_manifest_fixture(pristine)
            self.assertEqual(import_path, sys.path)
            self.assertEqual(UPGRADE_FROM_MINIMUM, read_manifest(pristine / 'release-manifest.json', True).manifest['release_version'])

            def edit(**changes):
                def apply(bundle):
                    path = bundle / 'release-manifest.json'
                    manifest = json.loads(path.read_text())
                    manifest.update({key: change(manifest[key]) if callable(change) else change for key, change in changes.items()})
                    path.write_text(json.dumps(manifest))
                return apply

            def linked_manifest(bundle):
                (bundle / 'release-manifest.json').rename(bundle / 'manifest.real')
                (bundle / 'release-manifest.json').symlink_to(bundle / 'manifest.real')

            for case, damage, message in (
                    ('manifest symlink', linked_manifest, 'release manifest is missing or unsafe'),
                    ('future schema', edit(schema_version=2), 'unsupported release manifest schema'),
                    ('branch name as revision', edit(source_revision='main'), 'invalid source revision'),
                    ('empty inventory', edit(files={}), 'release manifest has no file inventory'),
                    ('non-text checksum', edit(files=lambda files: dict(files, **{'selfhost/chronicle': 7})), 'malformed file inventory entry'),
                    ('escaping path', edit(files=lambda files: dict(files, **{'selfhost/../../etc/passwd': '0' * 64})), 'unsafe file path'),
                    ('short checksum', edit(files=lambda files: dict(files, **{'selfhost/chronicle': 'abc'})), 'invalid checksum for selfhost/chronicle'),
                    ('listed file removed', lambda bundle: (bundle / 'selfhost/restore.sh').unlink(), 'release file is missing or unsafe'),
                    ('extra symlink', lambda bundle: (bundle / 'selfhost/link').symlink_to('/etc/hostname'), 'unsafe symlink in new release'),
                    ('named pipe', lambda bundle: os.mkfifo(bundle / 'selfhost/pipe'), 'unsupported file type in new release'),
                    ('required file unlisted', lambda bundle: (edit(files=lambda files: {key: digest for key, digest in files.items()
                                                                                         if key != 'selfhost/restore.sh'})(bundle),
                                                               (bundle / 'selfhost/restore.sh').unlink()),
                     'release manifest omits required files in .*: selfhost/restore.sh'),
                    ('version not in its template', edit(release_version='2099.1.1'), 'manifest version does not match selfhost/.env.example'),
                    ('mutable third-party pin', edit(images=lambda images: dict(images, postgres='percona/percona-distribution-postgresql:17')),
                     'manifest image inventory does not match selfhost/.env.example'),
                    ('pin the template does not name', edit(images=lambda images: dict(images, backend='fixture/other@sha256:' + 'c' * 64)),
                     'manifest image inventory does not match selfhost/.env.example'),
                    ('mixed source trees', edit(image_inputs=lambda trees: dict(trees, backend='b' * 40)),
                     'first-party images require one immutable source inputs tree')):
                with self.subTest(case):
                    bundle = Path(folder) / case.replace(' ', '-')
                    shutil.copytree(pristine, bundle, symlinks=True)
                    damage(bundle)
                    with self.assertRaisesRegex(ValueError, message):
                        read_manifest(bundle / 'release-manifest.json', True)

    def test_an_interrupted_updates_candidate_alone_may_act_before_ownership_moves(self):
        import json
        from chronicle_ops import release
        from chronicle_ops.reconcile import RECOVERY_FILE, UPGRADE_LOCK
        with tempfile.TemporaryDirectory() as folder, patch.object(release, 'compose_projects', return_value=[]):
            state, old, candidate, stranger = (Path(folder) / name for name in ('state', 'old', 'candidate', 'stranger'))
            for directory in (state, old, candidate, stranger):
                directory.mkdir()
            release.set_current_owner(old, state)
            with self.assertRaisesRegex(ValueError, 'this release was superseded; use the active selfhost directory: ' + str(old)):
                require_current_owner(candidate, state, 'pilot')
            (state / UPGRADE_LOCK).mkdir()
            (state / UPGRADE_LOCK / RECOVERY_FILE).write_text(json.dumps({'owner': str(candidate), 'phase': 'migration-started'}))
            require_current_owner(candidate, state, 'pilot')  # resumes or rolls back its own transaction
            require_current_owner(old, state, 'pilot')
            with self.assertRaisesRegex(ValueError, 'this release was superseded'):
                require_current_owner(stranger, state, 'pilot')

    def test_a_full_disk_during_the_pre_update_dump_stops_pg_dump(self):
        from chronicle_ops import release
        real_popen, started = subprocess.Popen, []
        real_exit = real_popen.__exit__
        def popen(*args, **kwargs):
            started.append(real_popen(*args, **kwargs))
            return started[-1]
        def stopped_on_exit(process, *error):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                self.fail('dump producer kept running after the output disk filled')
            return real_exit(process, *error)
        with tempfile.TemporaryDirectory() as folder, patch.object(release.subprocess, 'Popen', side_effect=popen), \
             patch.object(real_popen, '__exit__', stopped_on_exit), \
             patch.object(release.shutil, 'copyfileobj', side_effect=OSError(28, 'No space left on device')):
            with self.assertRaisesRegex(OSError, 'No space left on device'):
                release.rollback_dump([sys.executable, '-s', '-c', 'import signal; signal.pause()'],
                                      Path(folder) / 'pre-update.sql.gz', env={'RELEASE_VERSION': UPGRADE_FROM_MINIMUM})
        self.assertLess(started[0].returncode, 0)  # terminated, not left writing into a full disk

    def test_new_inventory_must_be_exact(self):
        import json
        files = {name: "a" * 64 for name in ("selfhost/.env.example", "selfhost/chronicle", "selfhost/docker-compose.yml", "selfhost/restore.sh", "selfhost/network-subnet.py", "selfhost/rotate-secret.sh", "selfhost/docs/DEPLOYMENT-COMPATIBILITY.md", "selfhost/docs/SECRET-ROTATION.md", "selfhost/docs/UNINSTALL-DATA-DELETION.md")}
        manifest = {"schema_version": 1, UPGRADE_FLOOR_KEY: UPGRADE_FROM_MINIMUM, MIGRATIONS_KEY: {"V1__fresh_schema.sql": "a" * 64}, "release_version": "2.0.0", "source_revision": "a" * 40, "files": files}
        paths = [Path("/bundle") / name for name in files] + [Path("/bundle/unlisted")]
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "is_symlink", return_value=False), \
             patch.object(Path, "read_text", return_value=json.dumps(manifest)), \
             patch.object(Path, "rglob", return_value=paths), patch("chronicle_ops.release.file_sha256", return_value="a" * 64):
            with self.assertRaisesRegex(ValueError, "new release file inventory is not exact"):
                read_manifest(Path("/bundle/release-manifest.json"), True)

    def test_cleanup_subtracts_every_retained_runtime_image(self):
        import hashlib
        import json
        from chronicle_ops.images import bundle_config, SOURCE_IMAGES
        from chronicle_ops.release import cleanup_releases, RELEASE_KEEP_COUNT, UPDATE_DIRECTORY_PREFIX
        services = bundle_config(Path(__file__).resolve().parents[2] / 'selfhost')['services']
        pins = {service['image'] for service in services.values() if 'image' in service}
        pins = {next((f'fixture/{image.component}@sha256:' + 'a' * 64 for image in SOURCE_IMAGES
                      if image.placeholder == pin), pin) for pin in pins}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); state = root / 'state'; state.mkdir()
            releases = []
            for number in range(1, RELEASE_KEEP_COUNT + 3):
                version = f'1.0.{number}'
                parent = root / (UPDATE_DIRECTORY_PREFIX + version) if number == 1 else root
                directory = parent / ('chronicle-selfhost-' + version); directory.mkdir(parents=True)
                (directory / 'selfhost').mkdir()
                images = {str(i): pin if i == 0 else pin.split('@')[0] + '@sha256:' +
                          hashlib.sha256((version + pin).encode()).hexdigest() for i, pin in enumerate(sorted(pins))}
                (directory / 'release-manifest.json').write_text(json.dumps(dict(release_version=version, images=images)))
                releases.append((directory, set(images.values())))
            active = releases[-1][0] / 'selfhost'
            with patch.object(Path, 'cwd', return_value=active), \
                 patch('chronicle_ops.release.compose_projects', return_value=[]), patch('chronicle_ops.release.run') as run:
                cleanup_releases(root, state, apply=True)
            retained = set.union(*(images for _, images in releases[-RELEASE_KEEP_COUNT:]))
            candidates = set.union(*(images for _, images in releases[:-RELEASE_KEEP_COUNT]))
            self.assertEqual(candidates - retained, {call.args[0][-1] for call in run.call_args_list})
            self.assertTrue(all(directory.exists() for directory, _ in releases[-RELEASE_KEEP_COUNT:]))
            self.assertTrue(all(not directory.exists() for directory, _ in releases[:-RELEASE_KEEP_COUNT]))
            self.assertFalse(releases[0][0].parent.exists())

    def test_offline_bundle_links_are_closed_for_alternate_relative_paths(self):
        import runpy
        from urllib.parse import quote
        builder = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts/build-selfhost-release.py'))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            document = root / 'README.md'
            for relative in ('notes.md', 'nested/guide.md', 'a guide.md'):
                with self.subTest(relative=relative):
                    target = root / relative
                    document.write_text('[guide](' + quote(relative) + '#section)\n')
                    with self.assertRaises(SystemExit):
                        builder['require_offline_links'](root)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('# Section\n')
                    builder['require_offline_links'](root)
                    target.unlink()

    def test_bundle_inputs_have_the_same_modes_under_any_builder_umask(self):
        import runpy
        root = Path(__file__).resolve().parents[2]
        builder = runpy.run_path(str(root / 'scripts/build-selfhost-release.py'))

        class EveryPath(set):
            def __contains__(self, item):
                return True

        def modes(umask):
            with tempfile.TemporaryDirectory() as folder:
                bundle = Path(folder) / 'bundle'
                previous = os.umask(umask)
                try:
                    builder['copy_bundle_inputs'](bundle, None, EveryPath(), source_root=root)
                finally:
                    os.umask(previous)
                return {path.relative_to(bundle).as_posix(): path.stat().st_mode & 0o7777
                        for path in sorted(bundle.rglob('*'))}

        self.assertEqual(modes(0o022), modes(0o077))

    def test_semver_ordering_and_numeric_prerelease(self):
        versions = ["1.0.0-alpha.2", "1.0.0-alpha.10", "1.0.0", "1.0.1"]
        self.assertEqual(sorted(versions, key=lambda version: parse_version(version, "fixture")), versions)
        with self.assertRaises(ValueError):
            parse_version("1.0.0-01", "fixture")


class ReleaseGitDiagnosticTests(unittest.TestCase):
    def test_missing_git_source_metadata_has_an_operator_action_without_a_traceback(self):
        import runpy
        builder = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts/build-selfhost-release.py'))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(SystemExit) as failure:
                builder['require_committed_release_source'](Path(folder), 'a' * 40)
        self.assertIn('source metadata', str(failure.exception))
        self.assertIn('checkout', str(failure.exception))
