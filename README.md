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

### `get_keys_env`
This method will return the same information that `get_keys` but instead of asking for arguments it will obtain the information from the environment variables. In order to use it you have to define the following variables.
```
AWS_SSM_REGION_NAME
AWS_SSM_APP_PATH
AWS_SSM_CACHE_FILE

# Optionals
AWS_SSM_IGNORE_LOAD # default 0
AWS_SSM_WITH_DECRYPTION # default 0
```
for example
```
AWS_SSM_REGION_NAME=sa-east-1
AWS_SSM_APP_PATH=/some/path/
AWS_SSM_CACHE_FILE=.cache
AWS_SSM_IGNORE_LOAD=0
AWS_SSM_WITH_DECRYPTION=1
```

## Installation

```python
pip install git+https://github.com/carrerasrodrigo/aws-ssm-helper.git#egg=ssm
```
