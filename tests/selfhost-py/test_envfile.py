"""Literal environment parsing shared by file reads and setup validation."""

from pathlib import Path
import tempfile
import unittest


class EnvFileTests(unittest.TestCase):
    def test_text_and_file_parsing_have_the_same_literal_contract(self):
        from chronicle_ops.envfile import parse_env_text, read_env, value
        text = '# Settings\n export FIRST=\'literal $value\'\nEMPTY= # comment\nSECOND="two words" # comment\n'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings'
            path.write_text(text)
            parsed = parse_env_text(text)
            self.assertEqual(parsed, read_env(path))
            self.assertEqual([value(parsed, key) for key in parsed], ['literal $value', '', 'two words'])
        for invalid in ('FIRST=one\nexport FIRST=two\n', 'FIRST=$(private-sentinel)\n', 'private-sentinel'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError) as failure:
                parse_env_text(invalid)
            self.assertNotIn('private-sentinel', str(failure.exception))

    def test_compose_project_defaults_when_missing_or_empty(self):
        from chronicle_ops.common import DEFAULT_COMPOSE_PROJECT, compose_project
        from chronicle_ops.envfile import parse_env_text
        self.assertEqual(compose_project(parse_env_text('')), DEFAULT_COMPOSE_PROJECT)
        self.assertEqual(compose_project(parse_env_text('COMPOSE_PROJECT_NAME=\n')), DEFAULT_COMPOSE_PROJECT)
        self.assertEqual(compose_project(parse_env_text('COMPOSE_PROJECT_NAME=lab\n')), 'lab')
