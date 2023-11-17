import random
import hashlib
import string
import os
import base64
import socket
import urllib.parse
import threading
import time
import json

import requests
import jwt
from knack.log import get_logger

from .util import is_wsl, is_windows, open_page_in_browser, ClientRedirectServer, ClientRedirectHandler, decode_base64

EXPIRE_IN = 600
ALGORITHM = "RS256"

logger = get_logger(__name__)


class AuthCodeApp:
    def __init__(self, client_id, tenant_id, access_token=None, id_token=None, refresh_token=None, scope=None):
        """
        :param client_id: Application ID (Client ID)
        :param tenant_id: Tenant GUID, like 00000000-0000-0000-0000-000000000000.
        :param access_token: Non decode access token. Environment Variable "AUTH_CODE_AT"
        :param id_token: Non decode id token. Environment Variable "AUTH_CODE_IT"
        :param refresh_token : Non decode refresh token. Environment Variable "AUTH_CODE_RT"
        :param scope : api permission. Example "User.Read openid email profile"
        """
        self.client_id = client_id
        self.tenant_id = tenant_id
        self._access_token = access_token
        self._id_token = id_token
        self._refresh_token = refresh_token
        self.authority = "https://login.microsoftonline.com"
        self.ca_url = f"{self.authority}/{self.tenant_id}"
        self.scope = scope if scope else "openid email profile"
        self.code_verifier = None
        self.code_challenge = None
        self.request_state = None
        self.reply_url = None
        self.code = None
        self.cae_claim = None
        self.capabilities = ["CP1"]

    @property
    def access_token(self):
        if self._access_token:
            return self._access_token
        else:
            return None

    @access_token.setter
    def access_token(self, value):
        os.environ["AUTH_CODE_AT"] = value
        self._access_token = value

    @property
    def id_token(self):
        if self._id_token:
            return self._id_token
        else:
            return None

    @id_token.setter
    def id_token(self, value):
        os.environ["AUTH_CODE_IT"] = value
        self._id_token = value

    @property
    def refresh_token(self):
        if self._refresh_token:
            return self._refresh_token
        else:
            return None

    @refresh_token.setter
    def refresh_token(self, value):
        os.environ["AUTH_CODE_RT"] = value
        self._refresh_token = value

    def _generate_pkce_code_verifier(self, length=43):
        """
        Required by https://tools.ietf.org/html/rfc7636#section-3
        code_verifier : https://tools.ietf.org/html/rfc7636#section-4.1
        code_challenge : https://tools.ietf.org/html/rfc7636#section-4.2
        """
        assert 43 <= length <= 128
        self.code_verifier = "".join(random.sample(string.ascii_letters + string.digits + "-._~", length))
        self.code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(self.code_verifier.encode("ascii")).digest()).rstrip(b"=")
        ).decode()

        return self.code_verifier, self.code_challenge

    def _generate_authorization_code_request_url(self):
        self._generate_pkce_code_verifier()
        base_url = f"{self.ca_url}/oauth2/authorize"
        params = {}
        params["client_id"] = self.client_id
        params["redirect_uri"] = self.reply_url
        params["state"] = self.request_state
        params["code_challenge"] = self.code_challenge
        params["code_challenge_method"] = "S256"
        params["response_type"] = "code"
        params["prompt"] = "select_account"
        params["scope"] = self.scope
        if self.cae_claim:
            params["claims"] = self.cae_claim
            logger.debug(f"cae claims:{self.cae_claim}")

        authorization_code_request_url = f"{base_url}?{urllib.parse.urlencode(params)}"
        return authorization_code_request_url

    def _get_authorization_code_worker(self, results):
        """https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow"""

        if is_windows():
            ClientRedirectServer.allow_reuse_address = False
        elif is_wsl():
            ClientRedirectServer.allow_reuse_address = False

        for port in range(8400, 9000):
            try:
                web_server = ClientRedirectServer(("localhost", port), ClientRedirectHandler)
                self.reply_url = "http://localhost:{}".format(port)
                break
            except socket.error as ex:
                print(
                    "Port '%s' is taken with error '%s'. Trying with the next one",
                    port,
                    ex,
                )

        if self.reply_url is None:
            return 0

        try:
            self.request_state = "".join(
                random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(20)
            )
        except NotImplementedError:
            self.request_state = "code"

        authorization_code_request_url = self._generate_authorization_code_request_url()
        logger.debug(f"authorization code url: {authorization_code_request_url}")

        succ = open_page_in_browser(authorization_code_request_url)
        if succ is False:
            web_server.server_close()
            results["no_browser"] = True
            return

        while True:
            web_server.handle_request()
            if "error" in web_server.query_params or "code" in web_server.query_params:
                break

        if "error" in web_server.query_params:
            print(
                'Authentication Error: "%s". Description: "%s" ',
                web_server.query_params["error"],
                web_server.query_params.get("error_description"),
            )
            return

        if "code" in web_server.query_params:
            code = web_server.query_params["code"]
        else:
            print(
                'Authentication Error: Authorization code was not captured in query strings "%s"',
                web_server.query_params,
            )
            return

        if "state" in web_server.query_params:
            response_state = web_server.query_params["state"][0]
            if response_state != self.request_state:
                raise RuntimeError("mismatched OAuth state")
        else:
            raise RuntimeError("missing OAuth state")

        self.code = code[0]
        logger.debug(f"authorization code : {self.code}")
        return code[0]

    def _get_authorization_code(self):
        results = {}
        t = threading.Thread(
            target=self._get_authorization_code_worker,
            args=(results,),
        )
        t.daemon = True
        t.start()
        while True:
            # so that ctrl+c can stop the command
            time.sleep(2)
            if not t.is_alive():
                break  # done
        if results.get("no_browser"):
            raise RuntimeError()
        return results

    def _merge_claims_challenge_and_capabilities(self, claims_challenge):
        # Represent capabilities as {"access_token": {"xms_cc": {"values": capabilities}}}
        # and then merge/add it into incoming claims
        claims_dict = json.loads(claims_challenge) if claims_challenge else {}
        for key in ["access_token"]:
            claims_dict.setdefault(key, {}).update(xms_cc={"values": self.capabilities})
        return json.dumps(claims_dict)

    def _set_cae_claims(self, claims_challenge):
        if claims_challenge:
            claims = self._merge_claims_challenge_and_capabilities(claims_challenge)
            self.cae_claim = urllib.parse.quote(claims)
            os.environ["CAE_CLAIMS_CHALLENGE"] = ""

        else:
            default_claims = '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
            self.cae_claim = default_claims
        return self.cae_claim

    def token_request(self, cae=False, cae_claims_challenge=None):
        """https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow"""

        if cae:
            self._set_cae_claims(cae_claims_challenge)

        self._get_authorization_code()

        token_request_url = f"{self.ca_url}/oauth2/v2.0/token"

        logger.debug("---------------Token request param ---------------")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        params = {}
        params["client_id"] = self.client_id
        params["scope"] = self.scope
        params["redirect_uri"] = self.reply_url
        params["code"] = self.code
        params["code_verifier"] = self.code_verifier
        params["grant_type"] = "authorization_code"
        if cae:
            params["claims"] = self.cae_claim
            logger.debug(f"claims : {self.cae_claim}")
        logger.debug(f"client_id : {self.client_id}")
        logger.debug(f"scope : {self.scope}")
        logger.debug(f"code : *****")
        logger.debug(f"code_verifier: {self.code_verifier}")
        logger.debug(f"grant_type : authorization_code")
        logger.debug("--------------------------------------------------")

        response = requests.post(token_request_url, headers=headers, data=params)

        if response.ok:
            self.access_token = response.json().get("access_token", "")
            self.id_token = response.json().get("id_token", "")
            self.refresh_token = response.json().get("refresh_token", "")
            return self.access_token

        else:
            print("Error:", response.status_code)
            print("Details:", response.text)
            return

    def get_access_token(self):
        return self.access_token

    def get_decode_access_token(self):
        decoded_token = jwt.decode(self.access_token, options={"verify_signature": False})
        return decoded_token

    def get_id_token(self):
        return self.id_token

    def get_decode_id_token(self):
        decoded_token = jwt.decode(self.id_token, options={"verify_signature": False})
        return decoded_token

    def get_refresh_token(self):
        return self.refresh_token

    def graph_request(self, url_path="me", ver="v1.0", method="GET", body=None):
        base_url = "https://graph.microsoft.com"
        url = f"{base_url}/{ver}/{url_path}"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if method != "GET":
            headers["Content-type"] = "application/json"
        if body:
            body = json.loads(body)
        method_function = {
            "GET": requests.get,
            "POST": requests.post,
            "PUT": requests.put,
            "PATCH": requests.patch,
        }
        result = {}
        if method in method_function:
            response = method_function[method](url, headers=headers, data=body)
            if response.ok:
                result["body"] = response.json()
                return result

            else:
                if response.status_code == 401 and "WWW-Authenticate" in response.headers:
                    """Get client capabilities"""
                    www_authenticate_header = response.headers["WWW-Authenticate"]
                    start = www_authenticate_header.find('claims="') + len('claims="')
                    end = www_authenticate_header.find('"', start)
                    claims_encoded = www_authenticate_header[start:end]
                    claims = decode_base64(claims_encoded)

                    logger.debug("CAE claims challenge: %r", claims)

                    os.environ["CAE_CLAIMS_CHALLENGE"] = claims

                result["status code"] = response.status_code
                result["body"] = response.json()
                return result

        else:
            raise ValueError(f"HTTP method '{method}' is not supported.")
