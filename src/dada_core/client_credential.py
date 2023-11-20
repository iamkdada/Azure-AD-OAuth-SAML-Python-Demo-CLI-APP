import os
import time
import uuid
import base64

import jwt
import requests

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from knack.util import CLIError
from knack.log import get_logger


EXPIRE_IN = 600
ALGORITHM = "RS256"
logger = get_logger(__name__)


class ClientCredentialApp:
    def __init__(self, client_id, tenant_id, credential, access_token):
        if not client_id:
            raise CLIError("Client ID is not set.")
        if not tenant_id:
            raise CLIError("Tenant ID is not set.")

        self.client_id = client_id
        self.credential = credential
        self.tenant_id = tenant_id
        self.authority = "https://login.microsoftonline.com"
        self.ca_url = f"{self.authority}/{self.tenant_id}"
        self._access_token = access_token

    @property
    def access_token(self):
        if self._access_token:
            return self._access_token
        else:
            return None

    @access_token.setter
    def access_token(self, value):
        os.environ["CLIENT_CREDENTIAL_AT"] = value
        self._access_token = value

    def create_jwt_assertion(self):
        """
        JWT assertion format
        https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
        """

        try:
            cert_obj = x509.load_pem_x509_certificate(self.credential.public_key.encode())
            x5t = base64.urlsafe_b64encode(cert_obj.fingerprint(hashes.SHA1())).decode()
        except:
            raise CLIError(
                "Public Key is not valid. Please execute 'dada credential --path <cert file path>' to set certificate"
            )

        now = time.time()
        headers = {"alg": ALGORITHM, "typ": "JWT", "x5t": x5t}
        payload = {
            "aud": f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            "iss": self.client_id,
            "sub": self.client_id,
            "iat": now,
            "exp": now + EXPIRE_IN,
            "nbf": now,
            "jti": str(uuid.uuid4()),
        }
        try:
            jwt_assertion = jwt.encode(
                payload,
                self.credential.private_key.encode(),
                algorithm=ALGORITHM,
                headers=headers,
            )
        except:
            raise CLIError(
                "Private Key is not valid. Please execute 'dada credential --path <cert file path>' to set certificate"
            )
        logger.debug(f"client_assertion: {jwt_assertion}")
        return jwt_assertion

    def _log_token_request_params(self, params):
        logger.debug("---------------Token request param ---------------")
        for key, value in params.items():
            if key == "client_assertion":
                logger.debug("client_assertion : *****")
            else:
                logger.debug(f"{key} : {value}")
        logger.debug("--------------------------------------------------")

    def token_request(self, credential):
        """
        :params credential: "secret" or "cert". The credentials used to request a token.
        """

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        params = {}
        params["client_id"] = self.client_id
        params["scope"] = "https://graph.microsoft.com/.default"
        params["grant_type"] = "client_credentials"

        if "secret" in credential:
            params["client_secret"] = self.credential.secret
        else:
            params["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            params["client_assertion"] = self.create_jwt_assertion()

        self._log_token_request_params(params)
        response = requests.post(f"{self.ca_url}/oauth2/v2.0/token", headers=headers, data=params)

        result = {}
        if response.ok:
            self.access_token = response.json().get("access_token")
            result["access token"] = self.access_token
            return result
        else:
            result["status code"] = response.status_code
            result["body"] = response.json()
            return result

    def get_access_token(self):
        if self.access_token:
            return self.access_token
        else:
            raise CLIError(
                "Not found access token. Please execute 'dada client_cred token_request' to obtain an access token."
            )

    def get_decode_access_token(self):
        if self.access_token:
            return jwt.decode(self.access_token, options={"verify_signature": False})
        else:
            raise CLIError(
                "Not found access token. Please execute 'dada client_cred token_request' to obtain an access token."
            )
