import os

from knack.commands import CLICommandsLoader, CommandGroup, CLICommand
from knack.arguments import ArgumentsContext
from knack.help import CLIHelp
from dotenv import load_dotenv

from dada_core.auth_code import AuthCodeApp
from dada_core.client_credential import ClientCredentialApp
from dada_core.credential import Credential
from dada_core.saml import SAMLApp

CREDENTIAL_ENV_VARS = [
    "AUTH_CODE_AT",
    "AUTH_CODE_IT",
    "AUTH_CODE_RT",
    "CLIENT_CREDENTIAL_AT",
    "PRIVATE_KEY",
    "PUBLIC_KEY",
    "CLIENT_SECRET",
    "CAE_CLAIMS_CHALLENGE",
    "SAML_RESPONSE",
]

DADA_DATA_PATH = os.getenv("DADA_DATA_PATH")
load_dotenv(DADA_DATA_PATH)

CLIENT_ID = os.getenv("CLIENT_ID")
TENANT_ID = os.getenv("TENANT_ID")
AUTH_CODE_AT = os.getenv("AUTH_CODE_AT")
AUTH_CODE_IT = os.getenv("AUTH_CODE_IT")
AUTH_CODE_RT = os.getenv("AUTH_CODE_RT")
PRIVATE_KEY = os.getenv("PRIVATE_KEY").replace("\\n", "\n")
PUBLIC_KEY = os.getenv("PUBLIC_KEY").replace("\\n", "\n")
CLIENT_CREDENTIAL_AT = os.getenv("CLIENT_CREDENTIAL_AT")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
CAE_CLAIMS_CHALLENGE = os.getenv("CAE_CLAIMS_CHALLENGE")
ENTITY_ID = os.getenv("ENTITY_ID")
SAML_RESPONSE = os.getenv("SAML_RESPONSE")

WELCOME_MESSAGE = r"""
Welcome to the DADA CLI!
"""


class DadaCommandsLoader(CLICommandsLoader):
    def load_command_table(self, args):
        with CommandGroup(self, "", "dada_cli.Command#{}") as g:
            g.command("credential", "set_credential")
            g.command("logout", "logout")

        with CommandGroup(self, "auth_code", "dada_cli.Command#{}") as g:
            g.command("token_request", "auth_code_token_request")
            g.command("show", "get_auth_code_token")
            g.command("graph_request", "graph_request")

        with CommandGroup(self, "client_cred", "dada_cli.Command#{}") as g:
            g.command("token_request", "client_cred_token_request")
            g.command("show", "get_client_cred_token")

        with CommandGroup(self, "cert", "dada_cli.Command#{}") as g:
            g.command("thumbprint", "get_thumbprint")

        with CommandGroup(self, "saml", "dada_cli.Command#{}") as g:
            g.command("saml_request", "saml_request")
            g.command("show", "get_saml_response")

        return super(DadaCommandsLoader, self).load_command_table(args)

    def load_arguments(self, command):
        with ArgumentsContext(self, "auth_code show") as ac:
            ac.argument("decode", action="store_true", help="Enable decoding")
            ac.argument("token_type", type=str, default="access", help="access, id, refresh")

        with ArgumentsContext(self, "auth_code token_request") as ac:
            ac.argument("cae", action="store_true", help="Enable decoding")
            ac.argument("scopes", type=str)

        with ArgumentsContext(self, "auth_code graph_request") as ac:
            ac.argument("url", type=str)
            ac.argument("method", type=str)
            ac.argument("body", type=str)
            ac.argument("ver", type=str)

        with ArgumentsContext(self, "client_cred token_request") as ac:
            ac.argument("credential", type=str, required=True)
            ac.argument("secret", type=str)
            ac.argument("pfx", type=str)
            ac.argument("passphrase", type=str)

        with ArgumentsContext(self, "client_cred show") as ac:
            ac.argument("decode", action="store_true", help="Enable decoding")

        with ArgumentsContext(self, "saml saml_request") as ac:
            ac.argument("sign", action="store_true", help="Enable Signature")
            ac.argument("force_authn", action="store_true")
            ac.argument("name_id_format", type=str)
            ac.argument("authn_context", type=str)

        with ArgumentsContext(self, "credential") as ac:
            ac.argument("path", type=str)
            ac.argument("passphrase", type=str)
            ac.argument("secret", type=str)

        return super().load_arguments(command)


class DadaCLIHelp(CLIHelp):
    def __init__(self, cli_ctx=None):
        super(DadaCLIHelp, self).__init__(
            cli_ctx=cli_ctx,
            privacy_statement="My privacy statement.",
            welcome_message=WELCOME_MESSAGE,
        )


def auth_code_token_request(cae=False, scopes=None):
    auth_code_app = AuthCodeApp(CLIENT_ID, TENANT_ID, AUTH_CODE_AT, AUTH_CODE_IT, AUTH_CODE_RT, scope=scopes)
    if cae:
        auth_code_app.token_request(cae=True, cae_claims_challenge=CAE_CLAIMS_CHALLENGE)
    else:
        auth_code_app.token_request()

    return auth_code_app.get_access_token()


def get_auth_code_token(decode=False, token_type="access"):
    auth_code_app = AuthCodeApp(CLIENT_ID, TENANT_ID, AUTH_CODE_AT, AUTH_CODE_IT, AUTH_CODE_RT)
    token_methods = {
        (False, "access"): auth_code_app.get_access_token,
        (False, "id"): auth_code_app.get_id_token,
        (True, "access"): auth_code_app.get_decode_access_token,
        (True, "id"): auth_code_app.get_decode_id_token,
    }

    method = token_methods.get((decode, token_type))
    if method:
        return method()
    else:
        raise ValueError(f"Token type '{token_type}' is not supported.")


def graph_request(url="me", method="GET", body=None, ver="v1.0"):
    auth_code_app = AuthCodeApp(CLIENT_ID, TENANT_ID, AUTH_CODE_AT, AUTH_CODE_IT, AUTH_CODE_RT)
    return auth_code_app.graph_request(url_path=url, method=method, body=body, ver=ver)


def client_cred_token_request(credential, secret=None, pfx=None, passphrase=None):
    cred = Credential(secret=secret, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY)
    cred_app = ClientCredentialApp(CLIENT_ID, TENANT_ID, cred, CLIENT_CREDENTIAL_AT)

    if "secret" in credential:
        if secret:
            cred.secret = secret
            cred_app.credential = cred
            return cred_app.token_request("secret")
        else:
            return cred_app.token_request("secret")
    elif "cert" in credential:
        if pfx:
            cred.load_cert_file(pfx, passphrase)
            cred_app.credential = cred
            return cred_app.token_request("cert")
        else:
            return cred_app.token_request("cert")


def get_client_cred_token(decode=None):
    cred = Credential(secret=CLIENT_SECRET, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY)
    cred_app = ClientCredentialApp(CLIENT_ID, TENANT_ID, cred, CLIENT_CREDENTIAL_AT)

    if decode:
        return cred_app.get_decode_access_token()
    return cred_app.get_access_token()


def set_credential(path=None, passphrase=None, secret=None):
    cred = Credential(secret=secret, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY)
    if secret:
        cred.secret = secret
    elif path:
        cred.load_cert_file(path, passphrase)
    return


def saml_request(sign=False, force_authn=False, name_id_format=None, authn_context=None):
    cred = Credential(secret=CLIENT_SECRET, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY)
    saml_app = SAMLApp(
        entity_id=ENTITY_ID,
        tenant_id=TENANT_ID,
        saml_response=SAML_RESPONSE,
        credential=cred,
    )
    return saml_app.saml_request(sign, force_authn, name_id_format, authn_context)


def get_saml_response():
    cred = Credential(secret=CLIENT_SECRET, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY)
    saml_app = SAMLApp(
        entity_id=ENTITY_ID,
        tenant_id=TENANT_ID,
        saml_response=SAML_RESPONSE,
        credential=cred,
    )
    return saml_app.saml_response


def get_thumbprint():
    cred = Credential(secret=CLIENT_SECRET, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY)
    return cred.get_thumbprint()


def logout():
    for key in CREDENTIAL_ENV_VARS:
        os.environ[key] = ""
    return "logout"
