from knack.cli import CLI
from knack.util import ensure_dir
from dotenv import load_dotenv
import os

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


class DadaCli(CLI):
    def __init__(self, **kwargs):
        super(DadaCli, self).__init__(**kwargs)

        dada_folder = self.config.config_dir
        ensure_dir(dada_folder)

        if not os.path.exists(os.path.join(dada_folder, ".env")):
            self.save_env_file()

        load_dotenv(os.path.join(dada_folder, ".env"))

    def save_env_file(self):
        dada_env_file = os.path.join(self.config.config_dir, ".env")
        with open(dada_env_file, "w") as file:
            for key in ALL_ENV_VARS:
                value = os.getenv(key, "")
                file.write(f"{key}={value}\n")


def get_config_dir():
    return os.getenv("DADA_DATA_PATH", None) or os.path.expanduser(os.path.join("~", ".dada"))


def get_default_cli():
    from dada_cli.command import DadaCommandsLoader, DadaCLIHelp

    DADA_DATA_PATH = get_config_dir()
    return DadaCli(
        cli_name="dada", config_dir=DADA_DATA_PATH, commands_loader_cls=DadaCommandsLoader, help_cls=DadaCLIHelp
    )


def get_env_ver():
    dict_env_ver = {}
    dict_env_ver["CLIENT_ID"] = os.getenv("CLIENT_ID")
    dict_env_ver["TENANT_ID"] = os.getenv("TENANT_ID")
    dict_env_ver["AUTH_CODE_AT"] = os.getenv("AUTH_CODE_AT")
    dict_env_ver["AUTH_CODE_IT"] = os.getenv("AUTH_CODE_IT")
    dict_env_ver["AUTH_CODE_RT"] = os.getenv("AUTH_CODE_RT")
    dict_env_ver["PRIVATE_KEY"] = os.getenv("PRIVATE_KEY").replace("\\n", "\n")
    dict_env_ver["PUBLIC_KEY"] = os.getenv("PUBLIC_KEY").replace("\\n", "\n")
    dict_env_ver["CLIENT_CREDENTIAL_AT"] = os.getenv("CLIENT_CREDENTIAL_AT")
    dict_env_ver["CLIENT_SECRET"] = os.getenv("CLIENT_SECRET")
    dict_env_ver["CAE_CLAIMS_CHALLENGE"] = os.getenv("CAE_CLAIMS_CHALLENGE")
    dict_env_ver["ENTITY_ID"] = os.getenv("ENTITY_ID")
    dict_env_ver["SAML_RESPONSE"] = os.getenv("SAML_RESPONSE")
    return dict_env_ver
