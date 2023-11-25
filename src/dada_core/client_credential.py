import os
import json

import jwt
import requests

from knack.util import CLIError
from knack.log import get_logger

from dada_core.credential import Credential
from .util import decode_base64


EXPIRE_IN = 600
ALGORITHM = "RS256"
logger = get_logger(__name__)


class ClientCredentialApp:
    def __init__(self, client_id: str, tenant_id: str, credential: Credential, access_token: str):
        if not client_id:
            raise CLIError("Client ID is not set. Please execute 'dada configure --client-id <client-id>'")
        if not tenant_id:
            raise CLIError("Tenant ID is not set.Please execute 'dada configure --tenant-id <tenant-id>'")

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
            params["client_assertion"] = self.credential.generate_jwt_assertion(self.tenant_id, self.client_id)

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

    def _cae_error_handler(self, www_auth_header):
        if www_auth_header.find('claims="') == -1:
            return
        start = www_auth_header.find('claims="') + len('claims="')
        end = www_auth_header.find('"', start)
        claims_encoded = www_auth_header[start:end]
        claims = decode_base64(claims_encoded)
        logger.debug("CAE claims challenge: %r", claims)
        return claims

    def _image_response_handler(self, response):
        while True:
            try:
                save_path = input("Enter the path to save the image: ")
                if os.path.isdir(save_path):
                    raise IsADirectoryError("Entered path is a directory. Please enter a file path.")
                with open(save_path, "wb") as f:
                    f.write(response.content)
                print(f"Image saved to {save_path}")
                break
            except (IsADirectoryError, FileNotFoundError, PermissionError) as e:
                print(f"Error: {e}. Please try again.")

    def graph_request(self, url_path="users", ver="v1.0", method="GET", body=None, params=None):
        base_url = "https://graph.microsoft.com"
        url = f"{base_url}/{ver}/{url_path}"
        headers = {"Authorization": f"Bearer {self.access_token}"}

        if method in ["POST", "PUT", "PATCH"] and body:
            headers["Content-type"] = "application/json"
            body = json.dumps(body)

        method_function = {
            "GET": requests.get,
            "POST": requests.post,
            "PUT": requests.put,
            "PATCH": requests.patch,
            "DELETE": requests.delete,
        }

        if method not in method_function:
            raise ValueError(f"HTTP method '{method}' is not supported.")

        token_payload = jwt.decode(self.access_token, options={"verify_signature": False})
        result = {"request": {"url": url, "roles": token_payload["roles"]}, "response": {}}

        response = method_function[method](url, headers=headers, data=body, params=params)
        result["response"]["status code"] = response.status_code

        if response.ok:
            if response.headers.get("Content-Type", "").startswith("image/"):
                self._image_response_handler(response)
            else:
                result["response"]["body"] = response.json()
        else:
            if response.status_code == 401 and "WWW-Authenticate" in response.headers:
                claims = self._cae_error_handler(response.headers["WWW-Authenticate"])
                if claims:
                    os.environ["CAE_CLAIMS_CHALLENGE"] = claims
            result["response"]["body"] = response.json()

        return result
