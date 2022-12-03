import sys

import click

from ssm import get_keys_env


@click.command()
@click.option('--key', '-k', required=True,
    help='The name of the key we want to obtain')
@click.option('--text-replace', '-r', required=True,
    help='The text we want to replace')
@click.option('--fail-if-missing', '-fm', is_flag=True, default=False,
    help='Fail if there is a missing key')
@click.option('--file-in', '-f',
    type=click.File('r'), required=True, default=sys.stdin,
    help='The file that we will open in order to read the content')
def main(key, text_replace, fail_if_missing, file_in):
    '''Replaces a text from the stdin based on the value of a ssm key'''
    try:
        key_value = get_keys_env()[key]
    except KeyError:
        if fail_if_missing:
            raise Exception(f'key not found {key}')
        key_value = ''

    content = file_in.read().replace(text_replace, key_value)
    click.echo(content, nl=False)


if __name__ == '__main__':
    main()
