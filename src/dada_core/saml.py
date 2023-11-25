import base64
import os
import socket
import uuid
import zlib
from datetime import datetime
from urllib.parse import quote

import xml.etree.ElementTree as ET
from knack.util import CLIError
from knack.log import get_logger

from dada_core.credential import Credential
from .util import (
    is_wsl,
    is_windows,
    open_page_in_browser,
    SAMLRedirectServer,
    SAMLRedirectHandler,
    decode_base64,
    pretty_print_xml,
)

name_id_policy_mapping = {
    "persistent": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "emailAddress": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "unspecified": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "transient": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
}

logger = get_logger(__name__)


class SAMLApp:
    def __init__(
        self, entity_id, tenant_id, forth_authn: bool = False, saml_response=None, credential: Credential = None
    ):
        if not entity_id:
            raise CLIError("Entity ID is not set.")
        if not tenant_id:
            raise CLIError("Tenant ID is not set.")

        self.entity_id = entity_id
        self.tenant_id = tenant_id
        self.forth_authn = forth_authn
        self.idp_url = f"https://login.microsoftonline.com/{self.tenant_id}/saml2"
        self.reply_url = "http://localhost"
        self.saml_response = saml_response
        self.saml_assertion = None
        self.sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        self.credential = credential

    def _sign_saml_request(self, encode_saml_request):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if self.credential.private_key:
            private_key = load_pem_private_key(
                self.credential.private_key.encode(), password=None, backend=default_backend()
            )
        else:
            raise CLIError(
                "Private key is not found. Please execute 'dada credential --path <private key or pfx file path> --passphrase <passphrase>' to set private key."
            )
        signature = private_key.sign(encode_saml_request.encode(), padding.PKCS1v15(), hashes.SHA256())
        signature_encoded = base64.b64encode(signature)

        return signature_encoded

    def _add_name_id_policy(self, authn_request, format_type="persistent", allow_create=True):
        if format_type in name_id_policy_mapping:
            ET.SubElement(
                authn_request,
                "samlp:NameIDPolicy",
                {"Format": name_id_policy_mapping[format_type], "AllowCreate": str(allow_create).lower()},
            )
            return authn_request
        else:
            raise CLIError(
                "Name ID Format is not correct. Supporting Name ID Format is  'persistent', 'emailAddress', 'unspecified', 'transient'."
            )

    def _add_issuer(self, authn_request):
        issuer_element = ET.SubElement(
            authn_request, "saml:Issuer", {"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
        )
        issuer_element.text = self.entity_id
        return authn_request

    def _add_requested_authn_context(self, authn_request, authn_context_class_ref):
        requested_authn_context = ET.SubElement(authn_request, "samlp:RequestedAuthnContext", {"Comparison": "exact"})
        authn_context_class_ref_element = ET.SubElement(
            requested_authn_context,
            "saml:AuthnContextClassRef",
            {"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion"},
        )
        authn_context_class_ref_element.text = authn_context_class_ref
        return authn_request

    def _add_signature_param(self, saml_request_param):
        sig_alg_quoted = quote(self.sig_alg)
        saml_request_param += f"&SigAlg={sig_alg_quoted}"
        signature = self._sign_saml_request(saml_request_param)
        signature_quoted = quote(signature)
        saml_request_param += f"&Signature={signature_quoted}"
        return saml_request_param

    def _pack_saml_request(self, request_xml):
        request_deflated = zlib.compress(request_xml.encode("utf-8"))[2:-4]
        saml_request_encoded = base64.b64encode(request_deflated).decode("utf-8")
        return quote(saml_request_encoded)

    def _generate_saml_request_url(self, is_sign=False, is_force_authn=False, name_id_format=None, authn_context=None):
        authn_request = ET.Element(
            "samlp:AuthnRequest",
            {
                "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "ID": "_" + str(uuid.uuid4()),
                "Version": "2.0",
                "IssueInstant": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "AssertionConsumerServiceURL": self.reply_url,
                "Destination": self.idp_url,
            },
        )
        authn_request = self._add_issuer(authn_request)

        if is_force_authn:
            authn_request.set("ForceAuthn", "true")
        if name_id_format:
            authn_request = self._add_name_id_policy(authn_request, name_id_format)
        if authn_context:
            # example "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
            authn_request = self._add_requested_authn_context(authn_request, authn_context)

        request_xml = ET.tostring(authn_request, encoding="unicode")
        logger.debug(f"Saml Request XML: {request_xml}")

        packed_xml = self._pack_saml_request(request_xml)
        saml_request_param = f"SAMLRequest={packed_xml}"

        if is_sign:
            saml_request_param = self._add_signature_param(saml_request_param)

        return f"{self.idp_url}?{saml_request_param}"

    def _saml_request_worker(self, results, is_sign, is_force_authn, name_id_format, authn_context):
        if is_windows():
            SAMLRedirectServer.allow_reuse_address = False
        elif is_wsl():
            SAMLRedirectServer.allow_reuse_address = False

        for port in range(8400, 9000):
            try:
                web_server = SAMLRedirectServer(("localhost", port), SAMLRedirectHandler)
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

        saml_request_url = self._generate_saml_request_url(is_sign, is_force_authn, name_id_format, authn_context)
        logger.debug(f"Saml Request URL: {saml_request_url}")

        # launch browser:
        succ = open_page_in_browser(saml_request_url)
        if succ is False:
            web_server.server_close()
            results["no_browser"] = True
            return

        while True:
            web_server.handle_request()
            if "error" in web_server.post_data or "SAMLResponse" in web_server.post_data:
                encode_saml_response = web_server.post_data["SAMLResponse"][0]
                break

        if "error" in web_server.post_data:
            print(
                'Authentication Error: "%s". Description: "%s" ',
                web_server.post_data["error"],
                web_server.post_data.get("error_description"),
            )
            return

        return encode_saml_response

    def saml_request(self, is_sign=False, is_force_authn=False, name_id_format=None, authn_context=None):
        self.saml_response = decode_base64(
            self._saml_request_worker({}, is_sign, is_force_authn, name_id_format, authn_context)
        )
        os.environ["SAML_RESPONSE"] = self.saml_response
        print(pretty_print_xml(self.saml_response))
        return
