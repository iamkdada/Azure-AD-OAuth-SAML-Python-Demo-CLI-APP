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


def get_wsl_distro_from_powershell():
    try:
        # PowerShellを使用してWSLのディストリビューション一覧を取得
        #   NAME                   STATE           VERSION
        # * Ubuntu-20.04           Running         2
        #   Ubuntu                 Stopped         2
        #   docker-desktop-data    Stopped         2
        command = "powershell.exe -Command wsl -l -v"
        result = subprocess.run(
            command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        lines = result.stdout.split("\n")
        for line in lines:
            if "*" in line:  # 現在のディストリビューションには '*' が付いています
                return line.split()[1]

    except subprocess.CalledProcessError:
        return "Unknown"


def remove_null_chars(s):
    return s.replace("\x00", "")


def run_powershell_command(command):
    try:
        return subprocess.Popen(["powershell.exe", "-NoProfile", "-Command", command]).wait()
    except OSError:
        pass  # 適切なエラーハンドリングをここに追加


def open_page_in_wsl(url):
    if url.startswith("https"):
        command = f"Start-Process {url}"
    else:
        distro = get_wsl_distro_from_powershell()
        distro = remove_null_chars(distro)
        file_path = f"//wsl$/{distro}{url}".replace("/", "\\")
        command = f'Start-Process "{file_path}"'

    return run_powershell_command(command)


def open_page_in_browser(url):
    platform_name, _ = _get_platform_info()

    if is_wsl():
        return open_page_in_wsl(url)
    elif platform_name == "darwin":
        return run_powershell_command(f'open "{url}"')

    try:
        webbrowser.open(url, new=2)  # 2 means: open in a new tab, if possible
    except TypeError:  # See https://bugs.python.org/msg322439
        webbrowser.open(url, new=2)

    return None


def create_temp_html_file(form_html):
    import tempfile

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    with open(temp_file.name, "w") as file:
        file.write(form_html)
    return temp_file.name


class ClientRedirectServer(HTTPServer):  # pylint: disable=too-few-public-methods
    query_params = {}


class ClientRedirectHandler(BaseHTTPRequestHandler):
    # pylint: disable=line-too-long
    def log_message(self, format, *args):
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
