import base64
import json
import os

import boto3
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CACHE_NULL_VALUE_PATH = [None, ""]


def _get_encryption_key(encryption_key=None):
    """
    Derive a Fernet-compatible encryption key from the provided passphrase.
    
    When a non-empty string `encryption_key` is provided, a 32-byte key is derived using PBKDF2-HMAC-SHA256 with a fixed salt and 100000 iterations, then URL-safe base64-encoded for use with Fernet. If `encryption_key` is None or an empty/whitespace string, returns None.
    
    Parameters:
        encryption_key (str | None): Passphrase to derive the encryption key from.
    
    Returns:
        bytes | None: URL-safe base64-encoded derived key suitable for Fernet when `encryption_key` is provided, `None` otherwise.
    """
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
    """
    Serialize the given data and, if an encryption key is provided, return an encrypted payload suitable for cache storage.
    
    Parameters:
        data: A JSON-serializable Python object to be stored.
        encryption_key (str | None): Optional encryption key; when provided the serialized data is encrypted and returned as a base64-encoded string. When omitted or invalid, the function returns the plain JSON serialization.
    
    Returns:
        str: A base64-encoded encrypted payload when an encryption key is used, otherwise the JSON string representation of `data`.
    """
    key = _get_encryption_key(encryption_key)
    if key is None:
        return json.dumps(data)

    f = Fernet(key)
    json_data = json.dumps(data)
    encrypted = f.encrypt(json_data.encode())
    return base64.b64encode(encrypted).decode()


def _decrypt_data(encrypted_data, encryption_key=None):
    """
    Parse or decrypt cached JSON data.
    
    If an encryption key is provided, the function derives a decryption key, base64-decodes and decrypts the input, then parses the resulting JSON. If no encryption key is provided, the function parses the input directly as JSON.
    
    Parameters:
        encrypted_data (str): Base64-encoded encrypted payload or a JSON string when no encryption key is used.
        encryption_key (str | None): Optional raw encryption key used to derive the decryption key; pass None to treat `encrypted_data` as plain JSON.
    
    Returns:
        Any: The Python object resulting from parsing the JSON content.
    
    Raises:
        ValueError: If decryption or JSON parsing fails, indicating an invalid encryption key or a corrupted cache file.
    """
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
    """
    Request parameters under the specified SSM path using the provided client.
    
    Parameters:
        key_path (str): The SSM parameter path to query.
        next_token (str | None): Pagination token from a previous response; included when provided.
        with_decryption (bool): Whether to request decrypted parameter values.
    
    Returns:
        dict: The response dictionary returned by the client's get_parameters_by_path call.
    """
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
    """
    Load and decrypt cached data from a file.
    
    Parameters:
    	name (str): Path to the cache file to read.
    	encryption_key (str | None): Optional encryption key used to decrypt the file; when None, the file is treated as plaintext JSON.
    
    Returns:
    	cached_data (any | None): The parsed cache contents (typically a dict) on success, or `None` if the file is missing, unreadable, corrupted, or cannot be decrypted/parsed.
    """
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
    """
    Write the provided data to the file at `name`, encrypting the stored content when `encryption_key` is provided, and set the file permissions to owner read/write only (0o600).
    
    Parameters:
        name (str): Filesystem path to write the cache to.
        data (any): JSON-serializable object to store in the cache.
        encryption_key (str | None): Optional encryption key; when provided the stored content will be encrypted, otherwise it will be written as JSON.
    """
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
    """
    Retrieve parameter values from AWS SSM Parameter Store under a given path, optionally caching the results to a local file with optional encryption.
    
    Parameters:
    	region_name (str): AWS region to create the SSM client in.
    	key_path (str): Parameter path prefix to fetch; returned keys have this prefix removed.
    	cache_file (str): Path to a local cache file; if set to None or empty string, caching is disabled.
    	ignore_load (bool): If True, skip loading from cache and always fetch from SSM.
    	with_decryption (bool): If True, request decrypted secure string values from SSM.
    	fail_on_error (bool): If True, propagate exceptions raised while fetching from SSM; otherwise return an empty dict on error.
    	encryption_key (str | None): Optional passphrase used to encrypt/decrypt the cache file; if None or empty, cache is stored as plain JSON.
    
    Returns:
    	dict: Mapping of parameter names (original name with key_path prefix removed) to their string values.
    """
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
    """
    Builds SSM retrieval options from environment variables and returns the resulting keys mapping.
    
    Reads the following environment variables to configure behavior:
    - AWS_SSM_REGION_NAME: AWS region (required).
    - AWS_SSM_APP_PATH: SSM parameter path prefix (required).
    - AWS_SSM_CACHE_FILE: path to cache file (defaults to "/tmp/keys.enc").
    - AWS_SSM_IGNORE_LOAD: "1" to skip loading cache.
    - AWS_SSM_WITH_DECRYPTION: "1" to request SSM decryption.
    - AWS_SSM_FAIL_ON_ERROR: "1" to propagate errors instead of returning an empty dict.
    - AWS_SSM_ENCRYPTION_KEY: optional key used to encrypt/decrypt the local cache.
    
    Returns:
        dict: Mapping of parameter names (with the configured path prefix removed) to their values.
    """
    return get_keys(
        region_name=os.environ["AWS_SSM_REGION_NAME"],
        key_path=os.environ["AWS_SSM_APP_PATH"],
        cache_file=os.environ.get("AWS_SSM_CACHE_FILE", "/tmp/keys.enc"),
        ignore_load=os.environ.get("AWS_SSM_IGNORE_LOAD") == "1",
        with_decryption=os.environ.get("AWS_SSM_WITH_DECRYPTION") == "1",
        fail_on_error=os.environ.get("AWS_SSM_FAIL_ON_ERROR") == "1",
        encryption_key=os.environ.get("AWS_SSM_ENCRYPTION_KEY"),
    )