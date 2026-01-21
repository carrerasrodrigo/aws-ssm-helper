import json
import os
import unittest
from unittest.mock import patch

import boto3
from botocore.stub import ANY, Stubber

from ssm import (
    _decrypt_data,
    _encrypt_data,
    _get_encryption_key,
    get_keys,
    get_keys_env,
)


class TestClient(unittest.TestCase):

    def test_get_keys(self):
        response = {
            "Parameters": [
                {"Name": "/some/path/x", "Value": "xvalue"},
                {"Name": "/some/path/x2", "Value": "x2value"},
                {"Name": "/some/path2/x3", "Value": "x3value"},
            ]
        }

        client = boto3.client("ssm")
        stubber = Stubber(client)
        params = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
        }
        stubber.add_response("get_parameters_by_path", response, params)

        with patch("ssm.boto3") as m:
            with stubber:
                m.client.return_value = client
                data = get_keys("sa-east-1", "/some/path/", cache_file=None)

                self.assertEqual(data["x"], "xvalue")
                self.assertEqual(len(data), 2)

    def test_get_keys_next_token(self):
        response = {
            "Parameters": [
                {"Name": "/some/path/x", "Value": "xvalue"},
                {"Name": "/some/path/x2", "Value": "x2value"},
                {"Name": "/some/path2/x3", "Value": "x3value"},
            ],
            "NextToken": "x",
        }

        response2 = {"Parameters": [{"Name": "/some/path/y", "Value": "y"}]}

        client = boto3.client("ssm")
        stubber = Stubber(client)
        params = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
        }

        params2 = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
            "NextToken": ANY,
        }
        stubber.add_response("get_parameters_by_path", response, params)
        stubber.add_response("get_parameters_by_path", response2, params2)

        with patch("ssm.boto3") as m:
            with stubber:
                m.client.return_value = client
                data = get_keys("sa-east-1", "/some/path/", cache_file=None)

                self.assertEqual(data["x"], "xvalue")
                self.assertEqual(data["y"], "y")
                self.assertEqual(len(data), 3)

    def test_ignore_load(self):
        data = get_keys("sa-east-1", "/some/path/", cache_file=None, ignore_load=True)
        self.assertEqual(len(data), 0)

    def test_cache(self):
        response = {"Parameters": [{"Name": "/some/path/x", "Value": "xvalue"}]}

        client = boto3.client("ssm")
        stubber = Stubber(client)
        params = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
        }
        stubber.add_response("get_parameters_by_path", response, params)

        with patch("ssm.boto3") as m:
            with stubber:
                m.client.return_value = client
                data = get_keys(
                    "sa-east-1",
                    "/some/path/",
                    cache_file=".cache",
                    encryption_key=None,
                )

                self.assertEqual(data["x"], "xvalue")
                self.assertEqual(len(data), 1)
                self.assertTrue(os.path.exists(".cache"))

        # When encryption_key is None, data is stored as JSON string
        with open(".cache") as f:
            cache_data = json.loads(f.read())
            self.assertEqual(cache_data["x"], "xvalue")
        self.assertEqual(oct(os.stat(".cache").st_mode), "0o100600")

        with patch("ssm.boto3.client") as fn:
            data = get_keys(
                "sa-east-1",
                "/some/path/",
                cache_file=".cache",
                encryption_key=None,
            )
            self.assertFalse(fn.called)
            self.assertEqual(data["x"], "xvalue")
        os.remove(".cache")

    def test_environ(self):
        os.environ["AWS_SSM_REGION_NAME"] = "region"
        os.environ["AWS_SSM_APP_PATH"] = "path"
        os.environ["AWS_SSM_CACHE_FILE"] = ".test_cache_env"
        os.environ["AWS_SSM_IGNORE_LOAD"] = "1"
        os.environ["AWS_SSM_WITH_DECRYPTION"] = "1"
        os.environ["AWS_SSM_FAIL_ON_ERROR"] = "1"

        with patch("ssm.get_keys") as fn:
            get_keys_env()
            params = fn.call_args_list[0][1]
            self.assertEqual(params["region_name"], "region")
            self.assertEqual(params["key_path"], "path")
            self.assertEqual(params["cache_file"], ".test_cache_env")
            self.assertTrue(params["ignore_load"])
            self.assertTrue(params["with_decryption"])
            self.assertTrue(params["fail_on_error"])

    def test_environ_with_no_cache(self):
        os.environ["AWS_SSM_REGION_NAME"] = "region"
        os.environ["AWS_SSM_APP_PATH"] = "/some/path/"
        os.environ["AWS_SSM_CACHE_FILE"] = ""
        os.environ["AWS_SSM_IGNORE_LOAD"] = "0"
        os.environ["AWS_SSM_WITH_DECRYPTION"] = "1"

        response = {"Parameters": [{"Name": "/some/path/x", "Value": "xvalue"}]}

        client = boto3.client("ssm")
        stubber = Stubber(client)
        params = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
        }
        stubber.add_response("get_parameters_by_path", response, params)

        with patch("ssm.boto3") as m:
            with stubber:
                m.client.return_value = client
                data = get_keys_env()
                self.assertEqual(data["x"], "xvalue")
                self.assertEqual(len(data), 1)
                # When AWS_SSM_CACHE_FILE is empty, no cache file should be created
                self.assertFalse(os.path.exists(".cache"))
                self.assertFalse(os.path.exists("/tmp/keys.enc"))

    def test_encryption_key_generation(self):
        # Test with no key set
        key = _get_encryption_key(None)
        self.assertIsNone(key)

        # Test with empty key
        key = _get_encryption_key("")
        self.assertIsNone(key)

        # Test with whitespace only key
        key = _get_encryption_key("   ")
        self.assertIsNone(key)

        # Test with valid key
        key = _get_encryption_key("test_key")
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 44)  # Fernet keys are 32 bytes base64 encoded

    def test_encrypt_decrypt_no_key(self):
        # Test encryption/decryption without key
        test_data = {"key1": "value1", "key2": "value2"}

        encrypted = _encrypt_data(test_data, None)
        self.assertEqual(encrypted, json.dumps(test_data))  # Should return JSON string

        decrypted = _decrypt_data(encrypted, None)
        self.assertEqual(decrypted, test_data)  # Should parse back to dict

    def test_encrypt_decrypt_with_key(self):
        test_data = {"key1": "value1", "key2": "value2"}

        encrypted = _encrypt_data(test_data, "my_secret_key")
        self.assertNotEqual(encrypted, test_data)  # Should be encrypted
        self.assertIsInstance(encrypted, str)  # Should be a string

        decrypted = _decrypt_data(encrypted, "my_secret_key")
        self.assertEqual(decrypted, test_data)  # Should decrypt back to original

    def test_encrypt_decrypt_different_keys(self):
        test_data = {"key1": "value1"}

        # Encrypt with one key
        encrypted = _encrypt_data(test_data, "key1")

        # Try to decrypt with different key - should fail
        with self.assertRaises(ValueError) as context:
            _decrypt_data(encrypted, "key2")
        self.assertIn("Invalid encryption key", str(context.exception))

    def test_cache_with_encryption(self):
        response = {"Parameters": [{"Name": "/some/path/x", "Value": "xvalue"}]}

        client = boto3.client("ssm")
        stubber = Stubber(client)
        params = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
        }
        stubber.add_response("get_parameters_by_path", response, params)

        with patch("ssm.boto3") as m:
            with stubber:
                m.client.return_value = client
                data = get_keys(
                    "sa-east-1",
                    "/some/path/",
                    cache_file=".encrypted_cache",
                    encryption_key="test_encryption_key",
                )

                self.assertEqual(data["x"], "xvalue")
                self.assertEqual(len(data), 1)
                self.assertTrue(os.path.exists(".encrypted_cache"))

        # Verify cache file contains encrypted data
        with open(".encrypted_cache") as f:
            encrypted_content = f.read()
            # Should not be plain JSON
            self.assertNotEqual(encrypted_content, json.dumps({"x": "xvalue"}))

        # Test reading from encrypted cache
        with patch("ssm.boto3.client") as fn:
            data = get_keys(
                "sa-east-1",
                "/some/path/",
                cache_file=".encrypted_cache",
                encryption_key="test_encryption_key",
            )
            self.assertFalse(fn.called)  # Should not call AWS API
            self.assertEqual(data["x"], "xvalue")

        os.remove(".encrypted_cache")

    def test_backward_compatibility_unencrypted_cache(self):
        # Create an unencrypted cache file (simulating old version)
        cache_data = {"x": "xvalue"}
        with open(".unencrypted_cache", "w") as f:
            json.dump(cache_data, f)
        os.chmod(".unencrypted_cache", 0o600)

        response = {"Parameters": [{"Name": "/some/path/x", "Value": "xvalue"}]}

        client = boto3.client("ssm")
        stubber = Stubber(client)
        params = {
            "Path": ANY,
            "Recursive": ANY,
            "MaxResults": ANY,
            "WithDecryption": ANY,
        }
        stubber.add_response("get_parameters_by_path", response, params)

        # Try to read with encryption enabled - should handle gracefully
        # Decryption of unencrypted data fails, so it should refetch from AWS
        with patch("ssm.boto3") as m:
            with stubber:
                m.client.return_value = client
                data = get_keys(
                    "sa-east-1",
                    "/some/path/",
                    cache_file=".unencrypted_cache",
                    encryption_key="some_key",
                )
                # Should have refetched from AWS because decryption failed
                self.assertEqual(data["x"], "xvalue")

        os.remove(".unencrypted_cache")

    def test_encryption_error_handling(self):
        # Test with invalid encrypted data
        invalid_data = "not_encrypted_data"
        with self.assertRaises(ValueError) as context:
            _decrypt_data(invalid_data, "test_key")
        self.assertIn("Invalid encryption key", str(context.exception))

        # Test with malformed JSON in encrypted data
        # Encrypt valid data first
        valid_data = {"test": "data"}
        encrypted = _encrypt_data(valid_data, "test_key")

        # Manually corrupt the encrypted data
        corrupted = encrypted[:-5] + "xxxxx"
        with self.assertRaises(ValueError) as context:
            _decrypt_data(corrupted, "test_key")
        self.assertIn("Invalid encryption key", str(context.exception))
