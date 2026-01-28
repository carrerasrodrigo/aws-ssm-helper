# Aws SSM Helper
This library allows to easily obtain keys from aws ssm.

Let's say we have some parameters in SSM
```
/some/path/key = 'x'
/some/path/pass = 'y'
```

In order to obtain the information you will have to call

```python
from ssm import get_keys, get_keys_env

get_keys('sa-east-1', '/some/path/', cache_file='.cache')

# the result would be
{'key': 'x', 'pass': 'y'}

get_keys_env()
{'key': 'x', 'pass': 'y'}
```

## Methods
### `get_keys`
This method will return parameters from ssm.
- `region_name` aws region name, for example `sa-east-1`
-  `key_path` the main path of the ssm parameter, for example `/some/path/`
- `cache_file` the name of the cache file where the parameters will be stored temporarily. If you want to disable the cache, pass `None` as a parameter.
- `ignore_load` indicated to ignore the loading of the parameters and return an empty dict.
- `with_decryption` indicated if the parameters that we want to retrieve are encrypted.
- `fail_on_error` in case there is an error getting the credentials it will be raised.
- `encryption_key` optional key to encrypt cached data on disk. If not provided, uses `AWS_SSM_ENCRYPTION_KEY` environment variable.
- `kms_key_id` optional AWS KMS key ID or ARN for cache encryption. When provided, uses AWS KMS instead of local encryption (supersedes `encryption_key`).
- `kms_region_name` optional AWS region for KMS operations. If not provided, uses `region_name`.
- `key_discovery` optional parameter discovery method ("bypath" for get_parameters_by_path, or "bydescribe" for describe_parameters + get_parameters). Defaults to "bypath".
- `key_path_list` optional list of key paths to merge with `key_path`. When provided, uses `get_parameters` API to fetch specific parameters from multiple paths.

### `get_keys_env`
This method will return the same information that `get_keys` but instead of asking for arguments it will obtain the information from the environment variables. In order to use it you have to define the following variables.
```
AWS_SSM_REGION_NAME
AWS_SSM_APP_PATH
AWS_SSM_CACHE_FILE

# Optionals
AWS_SSM_IGNORE_LOAD # default 0
AWS_SSM_WITH_DECRYPTION # default 0
AWS_SSM_FAIL_ON_ERROR # default 0
AWS_SSM_ENCRYPTION_KEY # optional key for encrypting cached data
AWS_SSM_ENCRYPTION_KMS_KEY # optional KMS key ID or ARN (supersedes AWS_SSM_ENCRYPTION_KEY)
AWS_SSM_ENCRYPTION_KMS_REGION # optional AWS region for KMS operations (defaults to AWS_SSM_REGION_NAME)
AWS_SSM_KEY_DISCOVERY # optional parameter discovery method ("bypath" default, or "bydescribe")
AWS_SSM_KEY_PATH_LIST # optional comma-separated list of key paths to merge with AWS_SSM_APP_PATH
```
for example
```
AWS_SSM_REGION_NAME=sa-east-1
AWS_SSM_APP_PATH=/some/path/
AWS_SSM_CACHE_FILE=.cache
AWS_SSM_IGNORE_LOAD=0
AWS_SSM_WITH_DECRYPTION=1
AWS_SSM_FAIL_ON_ERROR=0
AWS_SSM_ENCRYPTION_KMS_KEY=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
AWS_SSM_ENCRYPTION_KMS_REGION=us-east-1
AWS_SSM_KEY_DISCOVERY=bydescribe
AWS_SSM_KEY_PATH_LIST=db/host,db/port,db/user
```

## Parameter Discovery Methods

The library supports two parameter discovery methods to accommodate different IAM permission models:

### 1. ByPath (Default) - `bypath`

Uses `get_parameters_by_path` API - faster and more efficient when you have path-based IAM permissions.

```bash
# Default behavior - no configuration needed
export AWS_SSM_KEY_DISCOVERY=bypath
# Or just omit the variable (bypath is default)
```

**Pros:**
- Faster - fewer API calls
- More efficient
- Recommended for standard setups

**Cons:**
- Requires `ssm:GetParametersByPath` IAM permission
- May not work with tag-based IAM filtering

### 2. ByDescribe - `bydescribe`

Uses `describe_parameters` + `get_parameters` APIs - supports tag-based IAM filtering and resource-level permissions.

```bash
export AWS_SSM_KEY_DISCOVERY=bydescribe
```

**Pros:**
- Supports tag-based IAM filtering
- More granular permission control
- Works with complex IAM policies

**Cons:**
- Slightly slower - requires two API calls per batch of parameters
- More API calls overall

**When to use:**
- Your IAM policy uses tags for parameter filtering
- You don't have `GetParametersByPath` permission
- You need fine-grained access control

**Example IAM Policy for bydescribe:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeParameters",
        "ssm:GetParameters"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Environment": "production"
        }
      }
    }
  ]
}
```

## Fetching Multiple Key Paths

The `key_path_list` parameter allows you to fetch parameters from multiple paths efficiently using a single API call. This is useful when you need parameters from different directories or when you want to avoid path-based discovery.

### Usage

**Python API:**
```python
from ssm import get_keys

# Fetch specific parameters from multiple paths
params = get_keys(
    region_name='us-east-1',
    key_path='/app/',
    key_path_list=['db/host', 'db/port', 'db/user', 'cache/redis_url']
)

# Resulting parameters fetched:
# /app/db/host, /app/db/port, /app/db/user, /app/cache/redis_url

# Returned dictionary:
# {'db/host': 'localhost', 'db/port': '5432', 'db/user': 'admin', 'cache/redis_url': 'redis://...'}
```

**Environment variables:**
```bash
export AWS_SSM_REGION_NAME=us-east-1
export AWS_SSM_APP_PATH=/app/
export AWS_SSM_KEY_PATH_LIST=db/host,db/port,db/user,cache/redis_url
```

Then in Python:
```python
from ssm import get_keys_env

params = get_keys_env()
```

### Behavior

- When `key_path_list` is provided, it merges each item with `key_path`
- Uses `get_parameters` API for direct parameter retrieval
- `key_discovery` method is ignored when `key_path_list` is used
- Parameters are returned with the `key_path` prefix removed
- Works with all encryption methods (KMS, local encryption, or none)
- **Keys in `key_path_list` must be relative paths** (not starting with `/`)
  - ✅ Valid: `['db/host', 'db/port', 'cache/redis']`
  - ❌ Invalid: `['/db/host', '/db/port']` - raises `ValueError`

### When to Use

- Fetching a known set of specific parameters
- Parameters are scattered across different sub-paths
- You need more control over which parameters to fetch
- Combining with other discovery methods via multiple calls

### Comparison

| Method | Use Case |
|--------|----------|
| `key_discovery="bypath"` (default) | Fetch all parameters under a path |
| `key_discovery="bydescribe"` | Fetch all parameters with tag-based filtering |
| `key_path_list` | Fetch specific known parameters from multiple paths |

## Installation

```bash
# Basic installation (without encryption support)
pip install git+https://github.com/carrerasrodrigo/aws-ssm-helper.git#egg=ssm

# With encryption support for cache files (optional)
pip install git+https://github.com/carrerasrodrigo/aws-ssm-helper.git#egg=ssm[encryption]
```

### Cache Encryption (Optional)

The library supports two encryption methods for caching:

#### 1. AWS KMS Encryption (Recommended for production)

Use AWS Key Management Service for enterprise-grade encryption. This is ideal for Lambda and production environments.

**Environment variables:**
```bash
export AWS_SSM_REGION_NAME=us-east-1
export AWS_SSM_ENCRYPTION_KMS_KEY="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
# Optional: specify a different region for KMS than SSM (if not provided, uses AWS_SSM_REGION_NAME)
export AWS_SSM_ENCRYPTION_KMS_REGION="us-west-2"
```

You can also use a key alias instead of the ARN:
```bash
export AWS_SSM_ENCRYPTION_KMS_KEY="alias/my-ssm-key"
```

**Python API:**
```python
from ssm import get_keys

# Use KMS with default region (same as SSM region)
params = get_keys(
    region_name='us-east-1',
    key_path='/myapp/',
    cache_file='.cache',
    kms_key_id='arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
)

# Use KMS with a different region
params = get_keys(
    region_name='us-east-1',
    key_path='/myapp/',
    cache_file='.cache',
    kms_key_id='arn:aws:kms:eu-west-1:123456789012:key/87654321-4321-4321-4321-210987654321',
    kms_region_name='eu-west-1'  # Explicitly set KMS region
)
```

**Key ID/ARN formats supported:**
- Key ID: `12345678-1234-1234-1234-123456789012`
- Key ARN: `arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012`
- Key Alias: `alias/my-ssm-key`
- Alias ARN: `arn:aws:kms:us-east-1:123456789012:alias/my-ssm-key`

**Region behavior:**
- If `kms_region_name` is provided, it will be used for KMS operations
- If `kms_region_name` is not provided or None, the `region_name` will be used (same region as SSM)
- This is useful when your KMS key is in a different region than your SSM parameters

**Requirements:**
- IAM permissions: `kms:Encrypt`, `kms:Decrypt`
- Works natively with Lambda (no external dependencies)
- **Recommended** for production and Lambda deployments

#### 2. Local Encryption with Cryptography (Optional)

For local development, you can use a simple passphrase-based encryption. Install the optional `cryptography` dependency:

```bash
pip install 'ssm[encryption]'
# or manually
pip install cryptography
```

Usage:
```bash
export AWS_SSM_ENCRYPTION_KEY="your-secret-passphrase"
```

In Python:
```python
from ssm import get_keys

params = get_keys(
    region_name='us-east-1',
    key_path='/myapp/',
    cache_file='.cache',
    encryption_key='your-secret-passphrase'
)
```

**Note:**
- Requires the `cryptography` library
- May have compatibility issues with Lambda (use KMS instead)
- Less secure than KMS for production use

#### Priority

If both `kms_key_id` and `encryption_key` are provided, **KMS takes precedence**.

#### No Encryption (Default)

If neither `kms_key_id` nor `encryption_key` are provided, the cache is stored as plain JSON:

```bash
# Just omit the encryption parameters
get_keys('us-east-1', '/myapp/', cache_file='.cache')
```

## SSM helper scripts
This is a list of scripts that helps to parse text and replace values with keys in ssm.

### ssm_get_key
Obtains a key from ssm and prints the value in the stdout.

Use:
```bash
ssm_get_key -k key_name > my_key_file
ssm_get_key -k key_name -k key_name2 -s " " > my_key_file
```

### ssm_replace_from_input
It takes a text to replace (TR) and the name of a key (KEY). This script will replace TR with the value of KEY.

Use:
```bash
cat text_file | ssm_replace_from_input -k key_name -r TEXT
```

## Testing

```python
pytest tests
```
