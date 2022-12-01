import json
import os

import boto3


CACHE_NULL_VALUE_PATH = [None, '']


def _get_data(client, key_path, next_token, with_decryption=True):
    params = {
        'Path': key_path,
        'Recursive': True,
        'MaxResults': 10,
        'WithDecryption': with_decryption,
    }

    if next_token is not None:
        params['NextToken'] = next_token

    response = client.get_parameters_by_path(**params)
    return response


def _get_cache_data(name):
    try:
        with open(name) as f:
            return json.loads(f.read())
    except IOError:
        return None


def _build_cache_data(name, data):
    with open(name, 'w') as f:
        f.write(json.dumps(data))
    os.chmod(name, 0o600)


def get_keys(region_name, key_path, cache_file='/tmp/keys.json',
        ignore_load=False, with_decryption=False):
    if ignore_load:
        return {}

    if cache_file not in CACHE_NULL_VALUE_PATH:
        cdata = _get_cache_data(cache_file)
        if cdata is not None:
            return cdata

    client = boto3.client('ssm', region_name=region_name)
    next_token = None
    results = []

    while True:
        try:
            response = _get_data(client, key_path, next_token, with_decryption)
        except Exception:
            return {}

        results += response['Parameters']
        next_token = response.get('NextToken')
        if next_token is None:
            break

    keys = {}
    for k in results:
        if not k['Name'].startswith(key_path):
            continue

        name = k['Name'][len(key_path):]
        keys[name] = k['Value']

    if cache_file not in CACHE_NULL_VALUE_PATH:
        _build_cache_data(cache_file, keys)
    return keys


def get_keys_env():
    return get_keys(
        region_name=os.environ['AWS_SSM_REGION_NAME'],
        key_path=os.environ['AWS_SSM_APP_PATH'],
        cache_file=os.environ.get('AWS_SSM_CACHE_FILE', '/tmp/keys.json'),
        ignore_load=os.environ.get('AWS_SSM_IGNORE_LOAD') == '1',
        with_decryption=os.environ.get('AWS_SSM_WITH_DECRYPTION') == '1')
