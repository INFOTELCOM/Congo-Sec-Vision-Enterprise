import json
import os
import unittest
from unittest.mock import patch

from app.soc_storage import supabase_public_configured, supabase_public_request


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return b'[{"id":"asset-1"}]'


class SupabaseSOCStorageTests(unittest.TestCase):
    def test_not_configured_without_service_role_key(self):
        with patch.dict(os.environ, {"SUPABASE_URL": "https://example.supabase.co"}, clear=False):
            os.environ.pop("SUPABASE_SERVICE_ROLE_KEY", None)
            self.assertFalse(supabase_public_configured())
            with self.assertRaisesRegex(RuntimeError, "SUPABASE_SERVICE_ROLE_KEY"):
                supabase_public_request("assets", "GET")

    def test_post_uses_server_key_and_public_profile(self):
        env = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "server-only-test-key",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("app.soc_storage.urllib.request.urlopen", return_value=_Response()) as open_url:
                result = supabase_public_request("assets?on_conflict=id", "POST", {"id": "asset-1"})
        self.assertEqual(result, [{"id": "asset-1"}])
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.supabase.co/rest/v1/assets?on_conflict=id")
        self.assertEqual(request.get_header("Apikey"), "server-only-test-key")
        self.assertEqual(request.get_header("Authorization"), "Bearer server-only-test-key")
        self.assertEqual(request.get_header("Content-profile"), "public")
        self.assertEqual(json.loads(request.data.decode()), {"id": "asset-1"})

    def test_rejects_unsupported_method(self):
        with self.assertRaisesRegex(ValueError, "Unsupported Supabase method"):
            supabase_public_request("assets", "DELETE", [])


if __name__ == "__main__":
    unittest.main()
