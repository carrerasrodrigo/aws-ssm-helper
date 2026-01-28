import base64
import json
import os

import boto3

# Optional cryptography dependency for cache encryption
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

CACHE_NULL_VALUE_PATH = [None, ""]

# Parameter discovery methods
KEY_DISCOVERY_BYPATH = "bypath"
KEY_DISCOVERY_BYDESCRIBE = "bydescribe"
VALID_KEY_DISCOVERY_METHODS = {KEY_DISCOVERY_BYPATH, KEY_DISCOVERY_BYDESCRIBE}


def _get_kms_client(region_name):
    """
    Create a KMS client for the specified region.

    Parameters:
        region_name (str): AWS region for the KMS client.

    Returns:
        boto3 KMS client.
    """
    return boto3.client("kms", region_name=region_name)


def _encrypt_with_kms(data, kms_key_id, region_name):
    """
    Encrypt data using AWS KMS.

    Parameters:
        data (dict): Data to encrypt.
        kms_key_id (str): KMS key ID or ARN to use for encryption.
        region_name (str): AWS region where KMS key is located.

    Returns:
        str: Base64-encoded encrypted blob.

    Raises:
        Exception: If KMS encryption fails.
    """
    json_data = json.dumps(data)
    kms_client = _get_kms_client(region_name)
    response = kms_client.encrypt(KeyId=kms_key_id, Plaintext=json_data.encode())
    encrypted_blob = response["CiphertextBlob"]
    return base64.b64encode(encrypted_blob).decode()


def _decrypt_with_kms(encrypted_data, region_name):
    """
    Decrypt data using AWS KMS.

    Parameters:
        encrypted_data (str): Base64-encoded encrypted blob.
        region_name (str): AWS region where KMS key is located.

    Returns:
        dict: Decrypted and parsed JSON data.

    Raises:
        Exception: If KMS decryption fails or data is invalid.
    """
    kms_client = _get_kms_client(region_name)
    encrypted_blob = base64.b64decode(encrypted_data)
    response = kms_client.decrypt(CiphertextBlob=encrypted_blob)
    plaintext = response["Plaintext"].decode()
    return json.loads(plaintext)


def _get_encryption_key(encryption_key=None):
    """
    Derive a Fernet-compatible encryption key from the provided passphrase.

    When a non-empty string `encryption_key` is provided, a 32-byte key is derived using PBKDF2-HMAC-SHA256 with a fixed salt and 100000 iterations, then URL-safe base64-encoded for use with Fernet. If `encryption_key` is None or an empty/whitespace string, returns None.

    Parameters:
        encryption_key (str | None): Passphrase to derive the encryption key from.

    Returns:
        bytes | None: URL-safe base64-encoded derived key suitable for Fernet when `encryption_key` is provided, `None` otherwise.

    Raises:
        ImportError: If encryption_key is not None and cryptography library is not installed.
    """
    if not encryption_key or (
        isinstance(encryption_key, str) and not encryption_key.strip()
    ):
        return None

    if not HAS_CRYPTOGRAPHY:
        raise ImportError(
            "The 'cryptography' library is required to use cache encryption. "
            "Install it with: pip install 'ssm[encryption]' or pip install cryptography"
        )

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


def _encrypt_data(
    data, encryption_key=None, kms_key_id=None, region_name=None, kms_region_name=None
):
    """
    Serialize the given data and, if an encryption key is provided, return an encrypted payload suitable for cache storage.

    KMS encryption takes precedence over local encryption if both are specified.

    Parameters:
        data: A JSON-serializable Python object to be stored.
        encryption_key (str | None): Optional encryption key; when provided the serialized data is encrypted using Fernet and returned as a base64-encoded string.
        kms_key_id (str | None): Optional KMS key ID or ARN; when provided, uses AWS KMS for encryption (takes precedence over encryption_key).
        region_name (str | None): AWS region for SSM client (used as fallback for KMS region if kms_region_name not provided).
        kms_region_name (str | None): AWS region for KMS operations; if not provided, uses region_name.

    Returns:
        str: A base64-encoded encrypted payload when encryption is used, otherwise the JSON string representation of `data`.
    """
    # KMS takes precedence
    if kms_key_id:
        kms_region = kms_region_name or region_name
        if kms_region:
            return _encrypt_with_kms(data, kms_key_id, kms_region)
        else:
            raise ValueError("KMS region is not provided")

    key = _get_encryption_key(encryption_key)
    if key is None:
        return json.dumps(data)

    f = Fernet(key)
    json_data = json.dumps(data)
    encrypted = f.encrypt(json_data.encode())
    return base64.b64encode(encrypted).decode()


def _decrypt_data(
    encrypted_data,
    encryption_key=None,
    kms_key_id=None,
    region_name=None,
    kms_region_name=None,
):
    """
    Parse or decrypt cached JSON data.

    If KMS key ID is provided, attempts KMS decryption first. Falls back to local encryption if KMS fails or is not configured.

    Parameters:
        encrypted_data (str): Base64-encoded encrypted payload or a JSON string when no encryption is used.
        encryption_key (str | None): Optional raw encryption key used to derive the decryption key; pass None to treat `encrypted_data` as plain JSON.
        kms_key_id (str | None): Optional KMS key ID or ARN; when provided, uses AWS KMS for decryption.
        region_name (str | None): AWS region for SSM client (used as fallback for KMS region if kms_region_name not provided).
        kms_region_name (str | None): AWS region for KMS operations; if not provided, uses region_name.

    Returns:
        Any: The Python object resulting from parsing the JSON content.

    Raises:
        ValueError: If decryption or JSON parsing fails, indicating an invalid encryption key or a corrupted cache file.
    """
    # Try KMS decryption first if key ID is provided
    if kms_key_id:
        kms_region = kms_region_name or region_name
        if kms_region:
            try:
                return _decrypt_with_kms(encrypted_data, kms_region)
            except Exception as e:
                raise ValueError(f"KMS decryption failed: {str(e)}")
        else:
            raise ValueError("KMS region is not provided")

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


def _get_parameter_names_by_describe(client, key_path):
    """
    Get parameter names using describe-parameters API.

    This method is useful when get_parameters_by_path doesn't support IAM tag-based filtering.
    Uses describe_parameters with a Name filter to find parameters by path prefix.

    Parameters:
        client: SSM client instance.
        key_path (str): The SSM parameter path prefix to query.

    Returns:
        list: List of parameter names matching the path prefix.
    """
    parameter_names = []
    next_token = None

    while True:
        params = {
            "ParameterFilters": [
                {
                    "Key": "Name",
                    "Option": "BeginsWith",
                    "Values": [key_path],
                }
            ],
            "MaxResults": 10,
        }

        if next_token is not None:
            params["NextToken"] = next_token

        response = client.describe_parameters(**params)
        parameter_names.extend(
            [param["Name"] for param in response.get("Parameters", [])]
        )

        next_token = response.get("NextToken")
        if next_token is None:
            break

    return parameter_names


def _get_parameters_by_names(client, parameter_names, with_decryption=True):
    """
    Get parameter values for a list of parameter names.

    Uses get_parameters API to fetch actual values. Handles pagination and returns
    results in the same format as get_parameters_by_path for consistency.

    Parameters:
        client: SSM client instance.
        parameter_names (list): List of parameter names to retrieve.
        with_decryption (bool): Whether to decrypt SecureString parameters.

    Returns:
        dict: Response with "Parameters" key containing parameter details.
    """
    all_parameters = []
    # get_parameters supports up to 10 parameters per call
    batch_size = 10

    for i in range(0, len(parameter_names), batch_size):
        batch = parameter_names[i : i + batch_size]
        response = client.get_parameters(Names=batch, WithDecryption=with_decryption)
        all_parameters.extend(response.get("Parameters", []))

    return {"Parameters": all_parameters}


def _get_data(
    client,
    key_path,
    next_token,
    with_decryption=True,
    discovery_method=KEY_DISCOVERY_BYPATH,
):
    """
    Request parameters under the specified SSM path using the provided client.

    Supports two discovery methods:
    - "bypath": Uses get_parameters_by_path (faster but requires path permissions)
    - "bydescribe": Uses describe_parameters + get_parameters (supports tag-based IAM filtering)

    Parameters:
        client: SSM client instance.
        key_path (str): The SSM parameter path to query.
        next_token (str | None): Pagination token from a previous response; included when provided.
        with_decryption (bool): Whether to request decrypted parameter values.
        discovery_method (str): Method to discover parameters ("bypath" or "bydescribe").

    Returns:
        dict: The response dictionary with "Parameters" key.
    """
    if discovery_method == KEY_DISCOVERY_BYDESCRIBE:
        # Use describe_parameters + get_parameters
        parameter_names = _get_parameter_names_by_describe(client, key_path)
        return _get_parameters_by_names(client, parameter_names, with_decryption)
    else:
        # Use get_parameters_by_path
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


def _get_cache_data(
    name, encryption_key=None, kms_key_id=None, region_name=None, kms_region_name=None
):
    """
    Load and decrypt cached data from a file.

    Parameters:
        name (str): Path to the cache file to read.
        encryption_key (str | None): Optional encryption key used to decrypt the file; when None, the file is treated as plaintext JSON.
        kms_key_id (str | None): Optional KMS key ID or ARN; when provided, uses AWS KMS for decryption.
        region_name (str | None): AWS region for SSM client (used as fallback for KMS region if kms_region_name not provided).
        kms_region_name (str | None): AWS region for KMS operations; if not provided, uses region_name.

    Returns:
        cached_data (any | None): The parsed cache contents (typically a dict) on success, or `None` if the file is missing, unreadable, corrupted, or cannot be decrypted/parsed.
    """
    try:
        with open(name) as f:
            encrypted_content = f.read()
            return _decrypt_data(
                encrypted_content,
                encryption_key,
                kms_key_id,
                region_name,
                kms_region_name,
            )
    except IOError:
        return None
    except ValueError:
        # Invalid encryption key or corrupted cache - return None to trigger refetch
        return None


def _build_cache_data(
    name,
    data,
    encryption_key=None,
    kms_key_id=None,
    region_name=None,
    kms_region_name=None,
):
    """
    Write the provided data to the file at `name`, encrypting the stored content when `encryption_key` or `kms_key_id` is provided, and set the file permissions to owner read/write only (0o600).

    Parameters:
        name (str): Filesystem path to write the cache to.
        data (any): JSON-serializable object to store in the cache.
        encryption_key (str | None): Optional encryption key; when provided the stored content will be encrypted using Fernet.
        kms_key_id (str | None): Optional KMS key ID or ARN; when provided, uses AWS KMS for encryption (takes precedence).
        region_name (str | None): AWS region for SSM client (used as fallback for KMS region if kms_region_name not provided).
        kms_region_name (str | None): AWS region for KMS operations; if not provided, uses region_name.
    """
    with open(name, "w") as f:
        encrypted_data = _encrypt_data(
            data, encryption_key, kms_key_id, region_name, kms_region_name
        )
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
    kms_key_id=None,
    kms_region_name=None,
    key_discovery=None,
    key_path_list=None,
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
        kms_key_id (str | None): Optional KMS key ID or ARN for cache encryption; takes precedence over encryption_key.
        kms_region_name (str | None): AWS region for KMS operations; if not provided, uses region_name.
        key_discovery (str): Method to discover parameters ("bypath" for get_parameters_by_path, "bydescribe" for describe_parameters + get_parameters).
        key_path_list (list | None): Optional list of key paths to merge with key_path. Each path is concatenated with key_path and parameters are fetched using get_parameters API.

    Returns:
        dict: Mapping of parameter names (original name with key_path prefix removed) to their string values.

    Raises:
        ValueError: If key_discovery is not a valid method.
    """
    if key_discovery is None:
        key_discovery = KEY_DISCOVERY_BYPATH

    if key_discovery not in VALID_KEY_DISCOVERY_METHODS:
        raise ValueError(
            f"Invalid key discovery method: '{key_discovery}'. "
            f"Valid methods are: {', '.join(sorted(VALID_KEY_DISCOVERY_METHODS))}"
        )

    # Validate key_path_list - keys should not start with /
    if key_path_list:
        for key in key_path_list:
            if key.startswith("/"):
                raise ValueError(
                    f"Keys in key_path_list should not start with '/'. "
                    f"Got: '{key}'. Use relative paths like 'db/host' instead of '/db/host'."
                )

    if ignore_load:
        return {}

    if cache_file not in CACHE_NULL_VALUE_PATH:
        cdata = _get_cache_data(
            cache_file, encryption_key, kms_key_id, region_name, kms_region_name
        )
        if cdata is not None:
            return cdata

    client = boto3.client("ssm", region_name=region_name)
    results = []

    # If key_path_list is provided, use get_parameters with merged paths
    if key_path_list:
        try:
            # Merge key_path with each item in key_path_list
            full_paths = [key_path + item for item in key_path_list]
            response = _get_parameters_by_names(client, full_paths, with_decryption)
            results = response.get("Parameters", [])
        except Exception as ex:
            if fail_on_error:
                raise ex
            return {}
    else:
        # Use standard key_discovery method
        next_token = None
        while True:
            try:
                response = _get_data(
                    client, key_path, next_token, with_decryption, key_discovery
                )
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
        _build_cache_data(
            cache_file, keys, encryption_key, kms_key_id, region_name, kms_region_name
        )
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
    - AWS_SSM_ENCRYPTION_KMS_KEY: optional KMS key ID or ARN for cache encryption (supersedes AWS_SSM_ENCRYPTION_KEY).
    - AWS_SSM_ENCRYPTION_KMS_REGION: optional AWS region for KMS operations; if not provided, uses AWS_SSM_REGION_NAME.
    - AWS_SSM_KEY_DISCOVERY: parameter discovery method ("bypath" for get_parameters_by_path or "bydescribe" for describe_parameters).
    - AWS_SSM_KEY_PATH_LIST: optional comma-separated list of key paths to merge with AWS_SSM_APP_PATH.

    Returns:
        dict: Mapping of parameter names (with the configured path prefix removed) to their values.
    """
    key_path_list_env = os.environ.get("AWS_SSM_KEY_PATH_LIST")
    key_path_list = key_path_list_env.split(",") if key_path_list_env else None

    return get_keys(
        region_name=os.environ["AWS_SSM_REGION_NAME"],
        key_path=os.environ["AWS_SSM_APP_PATH"],
        cache_file=os.environ.get("AWS_SSM_CACHE_FILE", "/tmp/keys.enc"),
        ignore_load=os.environ.get("AWS_SSM_IGNORE_LOAD") == "1",
        with_decryption=os.environ.get("AWS_SSM_WITH_DECRYPTION") == "1",
        fail_on_error=os.environ.get("AWS_SSM_FAIL_ON_ERROR") == "1",
        encryption_key=os.environ.get("AWS_SSM_ENCRYPTION_KEY"),
        kms_key_id=os.environ.get("AWS_SSM_ENCRYPTION_KMS_KEY"),
        kms_region_name=os.environ.get("AWS_SSM_ENCRYPTION_KMS_REGION"),
        key_discovery=os.environ.get("AWS_SSM_KEY_DISCOVERY", KEY_DISCOVERY_BYPATH),
        key_path_list=key_path_list,
    )
