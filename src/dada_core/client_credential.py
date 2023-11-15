import os
import time
import uuid
import base64

import jwt
import requests
from urllib.parse import quote_plus

from cryptography import x509
from cryptography.hazmat.primitives import hashes


EXPIRE_IN = 600
ALGORITHM = "RS256"


class ClientCredentialApp:
    def __init__(self, client_id, tenant_id, credential, access_token):
        self.client_id = client_id
        self.credential = credential
        self.jwt_assertion = None
        self.tenant_id = tenant_id
        self.authority = "https://login.microsoftonline.com"
        self.ca_url = f"{self.authority}/{self.tenant_id}"
        self.access_token = access_token

    def create_jwt_assertion(self):
        """
        JWT assertion format
        https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
        """

        cert_obj = x509.load_pem_x509_certificate(self.credential.public_key.encode())
        self.credential.thumbprint = cert_obj.fingerprint(hashes.SHA1())
        x5t = base64.urlsafe_b64encode(self.credential.thumbprint).decode()
        # x5t = base64.urlsafe_b64encode(self.credential.get_thumbprint().encode()).decode()

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

        jwt_assertion = jwt.encode(
            payload,
            self.credential.private_key.encode(),
            algorithm=ALGORITHM,
            headers=headers,
        )
        return jwt_assertion

    def token_request(self, credential):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if "secret" in credential:
            data = {
                "client_id": self.client_id,
                "scope": "https://graph.microsoft.com/.default",
                "client_secret": self.credential.secret,
                "grant_type": "client_credentials",
            }
        else:
            data = {
                "client_id": self.client_id,
                "scope": "https://graph.microsoft.com/.default",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": self.create_jwt_assertion(),
                "grant_type": "client_credentials",
            }

        response = requests.post(f"{self.ca_url}/oauth2/v2.0/token", headers=headers, data=data)

        if response.ok:
            os.environ["CLIENT_CREDENTIAL_AT"] = response.json().get("access_token")
            return os.environ["CLIENT_CREDENTIAL_AT"]
        else:
            print("Error:", response.status_code)
            print("Details:", response.text)

    def get_access_token(self):
        return self.access_token

    def get_decode_access_token(self):
        decoded_token = jwt.decode(self.access_token, options={"verify_signature": False})
        return decoded_token
