import os

import subprocess
import webbrowser
import platform
import base64

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def _get_platform_info():
    uname = platform.uname()
    return uname.system.lower(), uname.release.lower()


def is_wsl():
    platform_name, release = _get_platform_info()
    return platform_name == "linux" and "microsoft" in release


def is_windows():
    platform_name, _ = _get_platform_info()
    return platform_name == "windows"


def open_page_in_browser(url):
    platform_name, _ = _get_platform_info()

    if is_wsl():  # windows 10 linux subsystem
        try:
            # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
            # Ampersand (&) should be quoted
            return subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    'Start-Process "{}"'.format(url),
                ]
            ).wait()
        except OSError:  # WSL might be too old  # FileNotFoundError introduced in Python 3
            pass
    elif platform_name == "darwin":
        # handle 2 things:
        # a. On OSX sierra, 'python -m webbrowser -t <url>' emits out "execution error: <url> doesn't
        #    understand the "open location" message"
        return subprocess.Popen(["open", url])
    try:
        return webbrowser.open(url, new=2)  # 2 means: open in a new tab, if possible
    except TypeError:  # See https://bugs.python.org/msg322439
        return webbrowser.open(url, new=2)


class ClientRedirectServer(HTTPServer):  # pylint: disable=too-few-public-methods
    query_params = {}


class ClientRedirectHandler(BaseHTTPRequestHandler):
    # pylint: disable=line-too-long
    def log_message(self, format, *args):
        # 何も出力しないことで、標準のログメッセージを抑制
        pass

    def do_GET(self):
        query = self.path.split("?", 1)[-1]
        query = parse_qs(query, keep_blank_values=True)
        self.server.query_params = query

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        landing_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "landing_page",
            "ok.html" if "code" in query else "fail.html",
        )
        with open(landing_file, "rb") as html_file:
            self.wfile.write(html_file.read())


def decode_base64(encoded_str):
    decoded_bytes = base64.b64decode(encoded_str)
    decoded_str = decoded_bytes.decode("utf-8")
    return decoded_str


class SAMLRedirectHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)

        self.server.results["SAMLResponse"] = query_params.get("SAMLResponse", [None])[0]

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Received SAML Response")

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)

        post_data_decoded = parse_qs(post_data.decode("utf-8"))

        self.server.post_data = post_data_decoded
        self.send_response(200)
        self.end_headers()

        landing_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "landing_page",
            "ok.html" if "SAMLResponse" in post_data_decoded else "fail.html",
        )
        with open(landing_file, "rb") as html_file:
            self.wfile.write(html_file.read())

        return


class SAMLRedirectServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.results = {}


def pretty_print_xml(xml_string):
    import xml.dom.minidom

    parsed_string = xml.dom.minidom.parseString(xml_string)
    pretty_xml_as_string = parsed_string.toprettyxml()

    pretty_lines = pretty_xml_as_string.split("\n")
    non_empty_lines = [line for line in pretty_lines if line.strip() != ""]

    pretty_string = "\n".join(non_empty_lines)
    return pretty_string
