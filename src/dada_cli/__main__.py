import os
import sys

from knack.cli import CLI
from dotenv import load_dotenv

from dada_cli.Command import DadaCommandsLoader, DadaCLIHelp


DADA_DATA_PATH = os.getenv("DADA_DATA_PATH")
ALL_ENV_VARS = [
    "CLIENT_ID",
    "TENANT_ID",
    "AUTH_CODE_AT",
    "AUTH_CODE_IT",
    "AUTH_CODE_RT",
    "CAE_CLAIMS_CHALLENGE",
    "CLIENT_CREDENTIAL_AT",
    "PRIVATE_KEY",
    "PUBLIC_KEY",
    "CLIENT_SECRET",
    "ENTITY_ID",
    "SAML_RESPONSE",
]


def save_env_file(filename, variables_to_save):
    with open(filename, "w") as file:
        for key in variables_to_save:
            value = os.getenv(key, "")
            file.write(f"{key}={value}\n")


load_dotenv(DADA_DATA_PATH)

dada_cli = CLI(cli_name="dada", commands_loader_cls=DadaCommandsLoader, help_cls=DadaCLIHelp)

exit_code = dada_cli.invoke(sys.argv[1:])

save_env_file(DADA_DATA_PATH, ALL_ENV_VARS)
sys.exit(exit_code)
