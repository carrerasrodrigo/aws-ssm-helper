import json
import os
import unittest
from unittest.mock import MagicMock, patch

import boto3
from botocore.stub import ANY, Stubber

from ssm import (
    _decrypt_data,
    _decrypt_with_kms,
    _encrypt_data,
    _encrypt_with_kms,
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
        """
        Verify that get_keys_env loads parameters from AWS SSM using environment variables and does not create a cache file when AWS_SSM_CACHE_FILE is empty.

        Sets relevant AWS_SSM_* environment variables, stubs an SSM get_parameters_by_path response, and asserts that the returned key-value mapping contains the expected entry and that no cache files are created when the cache-file environment variable is an empty string.
        """
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

    def test_kms_encrypt_decrypt(self):
        """Test KMS encryption and decryption"""
        test_data = {"key1": "value1", "key2": "value2"}

        kms_client = MagicMock()
        encrypted_blob = b"encrypted_test_blob"

        # Mock encrypt response
        kms_client.encrypt.return_value = {"CiphertextBlob": encrypted_blob}

        # Mock decrypt response
        kms_client.decrypt.return_value = {"Plaintext": json.dumps(test_data).encode()}

        with patch("ssm._get_kms_client", return_value=kms_client):
            # Test encryption
            encrypted = _encrypt_with_kms(test_data, "test_key_id", "us-east-1")
            self.assertIsNotNone(encrypted)
            self.assertIsInstance(encrypted, str)
            kms_client.encrypt.assert_called_once()

            # Test decryption
            kms_client.reset_mock()
            decrypted = _decrypt_with_kms(encrypted, "us-east-1")
            self.assertEqual(decrypted, test_data)
            kms_client.decrypt.assert_called_once()

    def test_encrypt_data_with_kms(self):
        """Test _encrypt_data uses KMS when kms_key_id is provided"""
        test_data = {"key1": "value1"}
        kms_client = MagicMock()
        kms_client.encrypt.return_value = {"CiphertextBlob": b"encrypted_blob"}

        with patch("ssm._get_kms_client", return_value=kms_client):
            encrypted = _encrypt_data(
                test_data,
                encryption_key=None,
                kms_key_id="test_key_id",
                region_name="us-east-1",
            )
            self.assertIsNotNone(encrypted)
            kms_client.encrypt.assert_called_once()

    def test_decrypt_data_with_kms(self):
        """Test _decrypt_data uses KMS when kms_key_id is provided"""
        test_data = {"key1": "value1"}
        kms_client = MagicMock()
        kms_client.decrypt.return_value = {"Plaintext": json.dumps(test_data).encode()}

        with patch("ssm._get_kms_client", return_value=kms_client):
            encrypted = "base64_encoded_kms_blob"
            decrypted = _decrypt_data(
                encrypted,
                encryption_key=None,
                kms_key_id="test_key_id",
                region_name="us-east-1",
            )
            self.assertEqual(decrypted, test_data)
            kms_client.decrypt.assert_called_once()

    def test_kms_region_name_fallback(self):
        """Test that kms_region_name falls back to region_name"""
        test_data = {"key1": "value1"}
        kms_client = MagicMock()
        kms_client.encrypt.return_value = {"CiphertextBlob": b"encrypted_blob"}

        with patch("ssm._get_kms_client", return_value=kms_client) as mock_get_kms:
            # Test with explicit kms_region_name
            _encrypt_data(
                test_data,
                kms_key_id="test_key_id",
                region_name="us-east-1",
                kms_region_name="eu-west-1",
            )
            # Should use eu-west-1
            mock_get_kms.assert_called_with("eu-west-1")

        mock_get_kms.reset_mock()
        with patch("ssm._get_kms_client", return_value=kms_client) as mock_get_kms:
            # Test without explicit kms_region_name (should use region_name)
            _encrypt_data(
                test_data,
                kms_key_id="test_key_id",
                region_name="us-east-1",
                kms_region_name=None,
            )
            # Should use us-east-1
            mock_get_kms.assert_called_with("us-east-1")

    def test_kms_takes_precedence_over_local_encryption(self):
        """Test that KMS encryption takes precedence over local encryption"""
        test_data = {"key1": "value1"}
        kms_client = MagicMock()
        kms_client.encrypt.return_value = {"CiphertextBlob": b"encrypted_blob"}

        with patch("ssm._get_kms_client", return_value=kms_client):
            # When both kms_key_id and encryption_key are provided, KMS should be used
            _encrypt_data(
                test_data,
                encryption_key="local_key",
                kms_key_id="test_key_id",
                region_name="us-east-1",
            )
            # Should call KMS, not local encryption
            kms_client.encrypt.assert_called_once()

    def test_cache_with_kms_encryption(self):
        """Test caching with KMS encryption"""
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

        kms_client = MagicMock()
        kms_client.encrypt.return_value = {"CiphertextBlob": b"kms_encrypted_data"}

        with patch("ssm.boto3") as m:
            with patch("ssm._get_kms_client", return_value=kms_client):
                with stubber:
                    m.client.return_value = client
                    data = get_keys(
                        "us-east-1",
                        "/some/path/",
                        cache_file=".kms_encrypted_cache",
                        kms_key_id="test_key_id",
                    )

                    self.assertEqual(data["x"], "xvalue")
                    self.assertEqual(len(data), 1)
                    self.assertTrue(os.path.exists(".kms_encrypted_cache"))
                    kms_client.encrypt.assert_called_once()

        # Verify cache was created
        self.assertTrue(os.path.exists(".kms_encrypted_cache"))
        os.remove(".kms_encrypted_cache")

    def test_read_cache_with_kms_encryption(self):
        """Test reading from KMS encrypted cache"""
        test_data = {"x": "xvalue"}

        # Create a test cache file first
        kms_client = MagicMock()
        kms_client.encrypt.return_value = {"CiphertextBlob": b"kms_encrypted_data"}
        kms_client.decrypt.return_value = {"Plaintext": json.dumps(test_data).encode()}

        with patch("ssm._get_kms_client", return_value=kms_client):
            # First, create the cache with encrypted data
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
                        "us-east-1",
                        "/some/path/",
                        cache_file=".test_kms_cache",
                        kms_key_id="test_key_id",
                    )
                    self.assertEqual(data["x"], "xvalue")

            # Now read from cache without calling AWS
            kms_client.reset_mock()
            kms_client.decrypt.return_value = {
                "Plaintext": json.dumps(test_data).encode()
            }

            with patch("ssm.boto3.client") as fn:
                data = get_keys(
                    "us-east-1",
                    "/some/path/",
                    cache_file=".test_kms_cache",
                    kms_key_id="test_key_id",
                )
                # Should not call AWS API if cache exists
                self.assertFalse(fn.called)
                self.assertEqual(data["x"], "xvalue")

        # Cleanup
        if os.path.exists(".test_kms_cache"):
            os.remove(".test_kms_cache")

    def test_kms_region_in_env_variables(self):
        """Test AWS_SSM_ENCRYPTION_KMS_REGION environment variable"""
        os.environ["AWS_SSM_REGION_NAME"] = "us-east-1"
        os.environ["AWS_SSM_APP_PATH"] = "/path/"
        os.environ["AWS_SSM_ENCRYPTION_KMS_KEY"] = "test_key_id"
        os.environ["AWS_SSM_ENCRYPTION_KMS_REGION"] = "eu-west-1"

        with patch("ssm.get_keys") as fn:
            get_keys_env()
            params = fn.call_args_list[0][1]
            self.assertEqual(params["region_name"], "us-east-1")
            self.assertEqual(params["kms_key_id"], "test_key_id")
            self.assertEqual(params["kms_region_name"], "eu-west-1")

    def test_kms_encryption_error_handling(self):
        """Test error handling for KMS encryption failures"""
        kms_client = MagicMock()
        kms_client.decrypt.side_effect = Exception("KMS access denied")

        with patch("ssm._get_kms_client", return_value=kms_client):
            with self.assertRaises(ValueError) as context:
                _decrypt_data(
                    "encrypted_data", kms_key_id="test_key_id", region_name="us-east-1"
                )
            self.assertIn("KMS decryption failed", str(context.exception))

    def test_kms_missing_region_raises_error(self):
        """Test that KMS encryption/decryption fails when no region is provided"""
        test_data = {"key1": "value1"}

        # Test encryption without region
        with self.assertRaises(ValueError) as context:
            _encrypt_data(
                test_data,
                kms_key_id="test_key_id",
                region_name=None,
                kms_region_name=None,
            )
        self.assertIn("KMS region is not provided", str(context.exception))

        # Test decryption without region
        with self.assertRaises(ValueError) as context:
            _decrypt_data(
                "encrypted_data",
                kms_key_id="test_key_id",
                region_name=None,
                kms_region_name=None,
            )
        self.assertIn("KMS region is not provided", str(context.exception))
