import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key

from knack.util import CLIError
from knack.log import get_logger

logger = get_logger(__name__)


class Credential:
    def __init__(
        self, secret: str, public_key: str, private_key: str, cert_file_path: str = None, pass_phrase: str = None
    ):
        self._public_key = public_key
        self._private_key = private_key
        self._secret = secret
        if cert_file_path:
            self.load_cert_file(cert_file_path, pass_phrase)

    @property
    def public_key(self):
        if self._public_key:
            return self._public_key
        else:
            return None

    @public_key.setter
    def public_key(self, value):
        os.environ["PUBLIC_KEY"] = value.replace("\n", "\\n")
        self._public_key = value

    @property
    def private_key(self):
        if self._private_key:
            return self._private_key
        else:
            return None

    @private_key.setter
    def private_key(self, value):
        os.environ["PRIVATE_KEY"] = value.replace("\n", "\\n")
        self._private_key = value

    @property
    def secret(self):
        if self._secret:
            return self._secret
        else:
            return None

    @secret.setter
    def secret(self, value):
        os.environ["CLIENT_SECRET"] = value
        self._secret = value

    def load_cert_file(self, cert_file_path, pass_phrase=None):
        file_extension = os.path.splitext(cert_file_path)[1].lower()

        with open(cert_file_path, "rb") as f:
            cert_data = f.read()

        if file_extension in [".pfx", ".p12"]:
            self._load_pfx_cert(cert_data, pass_phrase)
        elif file_extension in [".pem", ".cer"]:
            self._load_pem_cert(cert_data, pass_phrase)
        else:
            CLIError("Provided file is not in the correct format.")

    def _load_pfx_cert(self, cert_data, pass_phrase):
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            cert_data, pass_phrase.encode(), backend=default_backend()
        )

        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        self.public_key = certificate.public_bytes(serialization.Encoding.PEM).decode()

    def _load_pem_cert(self, cert_data, pass_phrase):
        if b"BEGIN CERTIFICATE" in cert_data:
            self.public_key = cert_data.decode()

        elif b"BEGIN PRIVATE KEY" in cert_data or b"BEGIN RSA PRIVATE KEY" in cert_data:
            self.private_key = cert_data.decode()

        elif b"BEGIN ENCRYPTED PRIVATE KEY" in cert_data:
            private_key = load_pem_private_key(cert_data, password=pass_phrase.encode(), backend=default_backend())
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.private_key = private_key_pem.decode("utf-8")

        else:
            public_key = x509.load_der_x509_certificate(cert_data, default_backend())
            self.public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM).decode()

    def _calc_thumbprint(self):
        cert_obj = x509.load_pem_x509_certificate(self.public_key.encode())
        return cert_obj.fingerprint(hashes.SHA1())

    def get_thumbprint(self):
        return self._calc_thumbprint().hex().upper()

    def generate_jwt_assertion(self, tenant_id, client_id):
        import base64
        import time
        import uuid
        import jwt

        EXPIRE_IN = 600
        ALGORITHM = "RS256"

        """
        JWT assertion format
        https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
        """

        try:
            x5t = base64.urlsafe_b64encode(self._calc_thumbprint()).decode()
        except:
            raise CLIError(
                "Certificate is not valid. Please execute 'dada credential --path <cert file path>' to set certificate"
            )

        now = time.time()
        headers = {"alg": ALGORITHM, "typ": "JWT", "x5t": x5t}
        payload = {
            "aud": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            "iss": client_id,
            "sub": client_id,
            "iat": now,
            "exp": now + EXPIRE_IN,
            "nbf": now,
            "jti": str(uuid.uuid4()),
        }
        try:
            jwt_assertion = jwt.encode(
                payload,
                self.private_key.encode(),
                algorithm=ALGORITHM,
                headers=headers,
            )
        except:
            raise CLIError(
                "Private Key is not valid. Please execute 'dada credential --path <cert file path>' to set certificate"
            )
        logger.debug(f"client_assertion: {jwt_assertion}")
        return jwt_assertion
