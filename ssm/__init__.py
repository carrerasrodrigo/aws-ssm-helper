import base64
import json
import os

import boto3
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CACHE_NULL_VALUE_PATH = [None, ""]


def _get_encryption_key(encryption_key=None):
    """Get the encryption key from parameter or environment variable."""
    if not encryption_key or (
        isinstance(encryption_key, str) and not encryption_key.strip()
    ):
        return None

    # Derive a key from the provided key using PBKDF2
    salt = b"ssm_cache_salt_2024"  # Fixed salt for consistency
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
    return derived_key


def _encrypt_data(data, encryption_key=None):
    """Encrypt data if encryption key is available."""
    key = _get_encryption_key(encryption_key)
    if key is None:
        return json.dumps(data)

    f = Fernet(key)
    json_data = json.dumps(data)
    encrypted = f.encrypt(json_data.encode())
    return base64.b64encode(encrypted).decode()


def _decrypt_data(encrypted_data, encryption_key=None):
    """Decrypt data if encryption key is available."""
    key = _get_encryption_key(encryption_key)
    if key is None:
        try:
            return json.loads(encrypted_data)
        except (json.JSONDecodeError, ValueError):
            # If JSON parsing fails, return None to indicate cache is invalid
            raise ValueError("Invalid encryption key, cant read cache file")

    try:
        f = Fernet(key)
        decoded = base64.b64decode(encrypted_data)
        decrypted = f.decrypt(decoded)
        return json.loads(decrypted.decode())
    except (InvalidToken, ValueError, json.JSONDecodeError):
        # If decryption fails, return None to indicate cache is invalid
        raise ValueError("Invalid encryption key, cant read cache file")


def _get_data(client, key_path, next_token, with_decryption=True):
    params = {
        "Path": key_path,
        "Recursive": True,
        "MaxResults": 10,
        "WithDecryption": with_decryption,
    }

    if next_token is not None:
        params["NextToken"] = next_token

    response = client.get_parameters_by_path(**params)
    return response


def _get_cache_data(name, encryption_key=None):
    try:
        with open(name) as f:
            encrypted_content = f.read()
            return _decrypt_data(encrypted_content, encryption_key)
    except IOError:
        return None
    except ValueError:
        # Invalid encryption key or corrupted cache - return None to trigger refetch
        return None


def _build_cache_data(name, data, encryption_key=None):
    with open(name, "w") as f:
        encrypted_data = _encrypt_data(data, encryption_key)
        f.write(encrypted_data)
    os.chmod(name, 0o600)


def get_keys(
    region_name,
    key_path,
    cache_file="/tmp/keys.enc",
    ignore_load=False,
    with_decryption=False,
    fail_on_error=False,
    encryption_key=None,
):
    if ignore_load:
        return {}

    if cache_file not in CACHE_NULL_VALUE_PATH:
        cdata = _get_cache_data(cache_file, encryption_key)
        if cdata is not None:
            return cdata

    client = boto3.client("ssm", region_name=region_name)
    next_token = None
    results = []

    while True:
        try:
            response = _get_data(client, key_path, next_token, with_decryption)
        except Exception as ex:
            if fail_on_error:
                raise ex
            return {}

        results += response["Parameters"]
        next_token = response.get("NextToken")
        if next_token is None:
            break

    keys = {}
    for k in results:
        if not k["Name"].startswith(key_path):
            continue

        name = k["Name"][len(key_path) :]
        keys[name] = k["Value"]

    if cache_file not in CACHE_NULL_VALUE_PATH:
        _build_cache_data(cache_file, keys, encryption_key)
    return keys


def get_keys_env():
    return get_keys(
        region_name=os.environ["AWS_SSM_REGION_NAME"],
        key_path=os.environ["AWS_SSM_APP_PATH"],
        cache_file=os.environ.get("AWS_SSM_CACHE_FILE", "/tmp/keys.enc"),
        ignore_load=os.environ.get("AWS_SSM_IGNORE_LOAD") == "1",
        with_decryption=os.environ.get("AWS_SSM_WITH_DECRYPTION") == "1",
        fail_on_error=os.environ.get("AWS_SSM_FAIL_ON_ERROR") == "1",
        encryption_key=os.environ.get("AWS_SSM_ENCRYPTION_KEY"),
    )
