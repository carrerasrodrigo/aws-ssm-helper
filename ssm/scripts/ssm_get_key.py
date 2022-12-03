import click

from ssm import get_keys_env


@click.command()
@click.option('--key', '-k', multiple=True,
    help='The name of the key we want to obtain', required=True)
@click.option('--key-separator', '-s', default='\n',
    help='Text separator for  multiples keys')
@click.option('--fail-if-missing', '-fm', is_flag=True, default=False,
    help='Fail if thre is a missing key')
def main(key, key_separator, fail_if_missing):
    '''Download a ssm key and print it in the standard output'''
    values = []
    for key_name in key:
        try:
            values.append(get_keys_env()[key_name.strip()])
        except KeyError:
            if fail_if_missing:
                raise Exception(f'key not found {key_name}')
            values.append('')

    click.echo(f'{key_separator}'.join(values), nl=False)

if __name__ == '__main__':
    main()
