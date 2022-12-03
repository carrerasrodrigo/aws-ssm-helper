import unittest
from unittest.mock import patch
from click.testing import CliRunner

from ssm.scripts.ssm_get_key import main as main_ssm_get_key
from ssm.scripts.ssm_replace_from_input import main as main_input


class TestClient(unittest.TestCase):
    def test_get_key(self):
        with patch('ssm.scripts.ssm_get_key.get_keys_env',
                return_value=dict(x='x')) as fn:
            runner = CliRunner()
            result = runner.invoke(main_ssm_get_key,
                ['-k x', '-s @'])
            self.assertTrue(fn.called)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.output, 'x')

    def test_get_key_fail(self):
        with patch('ssm.scripts.ssm_get_key.get_keys_env',
                return_value=dict(x='x')) as fn:
            runner = CliRunner()
            result = runner.invoke(main_ssm_get_key,
                ['-k y', '-fm'])
            self.assertTrue(fn.called)
            self.assertEqual(result.exit_code, 1)

    def test_get_key_multi(self):
        with patch('ssm.scripts.ssm_get_key.get_keys_env',
                return_value=dict(x='x', y='y')) as fn:
            runner = CliRunner()
            result = runner.invoke(main_ssm_get_key,
                ['-k y', '-k x', '-s@'])
            self.assertTrue(fn.called)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.output, 'y@x')

    def test_get_key_multi_with_missing(self):
        with patch('ssm.scripts.ssm_get_key.get_keys_env',
                return_value=dict(x='x', y='y')) as fn:
            runner = CliRunner()
            result = runner.invoke(main_ssm_get_key,
                ['-k y', '-k m', '-k x', '-s@'])
            self.assertTrue(fn.called)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.output, 'y@@x')
