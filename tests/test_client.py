import json
import os
import unittest

import boto3
from botocore.stub import Stubber, ANY
from ssm import get_keys, get_keys_env
from unittest.mock import patch


class TestClient(unittest.TestCase):

    def test_get_keys(self):
        response = {
            'Parameters': [
                {'Name': '/some/path/x', 'Value': 'xvalue'},
                {'Name': '/some/path/x2', 'Value': 'x2value'},
                {'Name': '/some/path2/x3', 'Value': 'x3value'},
            ]
        }

        client = boto3.client('ssm')
        stubber = Stubber(client)
        params = {
            'Path': ANY,
            'Recursive': ANY,
            'MaxResults': ANY,
            'WithDecryption': ANY
        }
        stubber.add_response('get_parameters_by_path', response, params)

        with patch('ssm.boto3') as m:
            with stubber:
                m.client.return_value = client
                data = get_keys('sa-east-1', '/some/path/', cache_file=None)

                self.assertEqual(data['x'], 'xvalue')
                self.assertEqual(len(data), 2)

    def test_get_keys_next_token(self):
        response = {
            'Parameters': [
                {'Name': '/some/path/x', 'Value': 'xvalue'},
                {'Name': '/some/path/x2', 'Value': 'x2value'},
                {'Name': '/some/path2/x3', 'Value': 'x3value'},
            ],
            'NextToken': 'x'
        }

        response2 = {
            'Parameters': [
                {'Name': '/some/path/y', 'Value': 'y'}
            ]
        }

        client = boto3.client('ssm')
        stubber = Stubber(client)
        params = {
            'Path': ANY,
            'Recursive': ANY,
            'MaxResults': ANY,
            'WithDecryption': ANY
        }

        params2 = {
            'Path': ANY,
            'Recursive': ANY,
            'MaxResults': ANY,
            'WithDecryption': ANY,
            'NextToken': ANY
        }
        stubber.add_response('get_parameters_by_path', response, params)
        stubber.add_response('get_parameters_by_path', response2, params2)

        with patch('ssm.boto3') as m:
            with stubber:
                m.client.return_value = client
                data = get_keys('sa-east-1', '/some/path/', cache_file=None)

                self.assertEqual(data['x'], 'xvalue')
                self.assertEqual(data['y'], 'y')
                self.assertEqual(len(data), 3)

    def test_ignore_load(self):
        data = get_keys('sa-east-1', '/some/path/', cache_file=None,
            ignore_load=True)
        self.assertEqual(len(data), 0)

    def test_cache(self):
        response = {
            'Parameters': [
                {'Name': '/some/path/x', 'Value': 'xvalue'}
            ]
        }

        client = boto3.client('ssm')
        stubber = Stubber(client)
        params = {
            'Path': ANY,
            'Recursive': ANY,
            'MaxResults': ANY,
            'WithDecryption': ANY
        }
        stubber.add_response('get_parameters_by_path', response, params)

        with patch('ssm.boto3') as m:
            with stubber:
                m.client.return_value = client
                data = get_keys('sa-east-1', '/some/path/',
                    cache_file='.cache')

                self.assertEqual(data['x'], 'xvalue')
                self.assertEqual(len(data), 1)
                self.assertTrue(os.path.exists('.cache'))

        with open('.cache') as f:
            self.assertEqual(json.loads(f.read())['x'], 'xvalue')
        self.assertEqual(oct(os.stat('.cache').st_mode), '0o100600')

        with patch('ssm.boto3.client') as fn:
            data = get_keys('sa-east-1', '/some/path/', cache_file='.cache')
            self.assertFalse(fn.called)
            self.assertEqual(data['x'], 'xvalue')
        os.remove(".cache")

    def test_environ(self):
        os.environ['AWS_SSM_REGION_NAME'] = 'region'
        os.environ['AWS_SSM_APP_PATH'] = 'path'
        os.environ['AWS_SSM_CACHE_FILE'] = 'cache'
        os.environ['AWS_SSM_IGNORE_LOAD'] = '1'
        os.environ['AWS_SSM_WITH_DECRYPTION'] = '1'

        with patch('ssm.get_keys') as fn:
            get_keys_env()
            params = fn.call_args_list[0][1]
            self.assertEqual(params['region_name'], 'region')
            self.assertEqual(params['key_path'], 'path')
            self.assertEqual(params['cache_file'], 'cache')
            self.assertTrue(params['ignore_load'])
            self.assertTrue(params['with_decryption'])

    def test_environ_with_no_cache(self):
        os.environ['AWS_SSM_REGION_NAME'] = 'region'
        os.environ['AWS_SSM_APP_PATH'] = '/some/path/'
        os.environ['AWS_SSM_CACHE_FILE'] = ''
        os.environ['AWS_SSM_IGNORE_LOAD'] = '0'
        os.environ['AWS_SSM_WITH_DECRYPTION'] = '1'

        response = {
            'Parameters': [
                {'Name': '/some/path/x', 'Value': 'xvalue'}
            ]
        }

        client = boto3.client('ssm')
        stubber = Stubber(client)
        params = {
            'Path': ANY,
            'Recursive': ANY,
            'MaxResults': ANY,
            'WithDecryption': ANY
        }
        stubber.add_response('get_parameters_by_path', response, params)

        with patch('ssm.boto3') as m:
            with stubber:
                m.client.return_value = client
                data = get_keys_env()
                self.assertEqual(data['x'], 'xvalue')
                self.assertEqual(len(data), 1)
                self.assertFalse(os.path.exists('.cache'))
