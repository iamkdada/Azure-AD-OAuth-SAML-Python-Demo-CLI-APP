import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key


class Credential:
    def __init__(self, secret, public_key, private_key, cert_file_path=None, pass_phrase=None):
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

    def get_thumbprint(self):
        cert_obj = x509.load_pem_x509_certificate(self.public_key.encode())
        self._thumbprint = cert_obj.fingerprint(hashes.SHA1())
        return self._thumbprint.hex().upper()

    def load_cert_file(self, cert_file_path, pass_phrase=None):
        file_extension = os.path.splitext(cert_file_path)[1].lower()

        if file_extension in [".pfx", ".p12"]:
            with open(cert_file_path, "rb") as f:
                pfx = f.read()
                (
                    private_key,
                    certificate,
                    additional_certificates,
                ) = pkcs12.load_key_and_certificates(pfx, pass_phrase.encode(), backend=default_backend())

                private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode()
                public_key = certificate.public_bytes(serialization.Encoding.PEM).decode()
                self.public_key = public_key
                self.private_key = private_key

        elif file_extension in [".pem", ".cer"]:
            with open(cert_file_path, "rb") as f:
                cert_file = f.read()
                if b"BEGIN CERTIFICATE" in cert_file:
                    self.public_key = cert_file.decode()

                elif b"BEGIN PRIVATE KEY" in cert_file or b"BEGIN RSA PRIVATE KEY" in cert_file:
                    self.private_key = cert_file.decode()

                elif b"BEGIN ENCRYPTED PRIVATE KEY" in cert_file:
                    private_key = load_pem_private_key(
                        cert_file,
                        password=pass_phrase.encode(),
                        backend=default_backend(),
                    )
                    private_key_pem = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    self.private_key = private_key_pem.decode("utf-8")

                else:
                    public_key = x509.load_der_x509_certificate(cert_file, default_backend())
                    self.public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM).decode()

        else:
            print("Provided file is not in the correct format.")
