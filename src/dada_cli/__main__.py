import sys

from dada_cli.cli import get_default_cli


def cli_main(cli, args):
    return cli.invoke(args)


dada_cli = get_default_cli()

exit_code = cli_main(dada_cli, sys.argv[1:])

dada_cli.save_env_file()
sys.exit(exit_code)
