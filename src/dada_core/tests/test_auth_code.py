import unittest
from unittest.mock import patch, Mock
from dada_core.auth_code import AuthCodeApp


class TestAuthCodeApp(unittest.TestCase):
    def setUp(self):
        self.auth_code_app = AuthCodeApp(
            client_id="test_client_id",
            tenant_id="test_tenant_id",
            access_token="test_access_token",
            id_token="test_id_token",
            refresh_token="test_refresh_token",
        )

    def test_access_token_getter(self):
        self.assertEqual(self.auth_code_app.access_token, "test_access_token")

    def test_access_token_setter(self):
        self.auth_code_app.access_token = "new_access_token"
        self.assertEqual(self.auth_code_app.access_token, "new_access_token")

    @patch("your_module.requests.post")
    def test_token_request(self, mock_post):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "id_token": "new_id_token",
            "refresh_token": "new_refresh_token",
        }
        mock_post.return_value = mock_response

        self.auth_code_app.token_request()
        self.assertEqual(self.auth_code_app.access_token, "new_access_token")
        self.assertEqual(self.auth_code_app.id_token, "new_id_token")
        self.assertEqual(self.auth_code_app.refresh_token, "new_refresh_token")

    # 他のメソッドのテストケースも同様に追加


if __name__ == "__main__":
    unittest.main()
