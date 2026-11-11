import unittest
from app.authz import is_admin_user


class SupabaseAuthorizationTests(unittest.TestCase):
    def test_admin_role_is_accepted_from_app_metadata(self):
        self.assertTrue(is_admin_user({"app_metadata": {"role": "admin"}}))

    def test_owner_role_is_accepted(self):
        self.assertTrue(is_admin_user({"app_metadata": {"roles": ["owner"]}}))

    def test_user_metadata_is_not_trusted(self):
        self.assertFalse(is_admin_user({"user_metadata": {"role": "admin"}}))

    def test_regular_user_is_not_admin(self):
        self.assertFalse(is_admin_user({"app_metadata": {"role": "authenticated"}}))

    def test_malformed_metadata_fails_closed(self):
        self.assertFalse(is_admin_user({"app_metadata": None}))
        self.assertFalse(is_admin_user({"app_metadata": {"roles": "admin"}}))


if __name__ == "__main__":
    unittest.main()
