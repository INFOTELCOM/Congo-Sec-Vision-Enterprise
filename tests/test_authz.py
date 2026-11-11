import unittest
from app.authz import get_user_roles, has_any_role, is_admin_user


class SupabaseAuthorizationTests(unittest.TestCase):
    def test_admin_role_is_accepted_from_app_metadata(self):
        self.assertTrue(is_admin_user({"app_metadata": {"role": "admin"}}))

    def test_owner_is_normalized_to_admin(self):
        self.assertTrue(is_admin_user({"app_metadata": {"roles": ["owner"]}}))

    def test_all_supported_roles_are_extracted(self):
        user = {"app_metadata": {"roles": ["analyst", "viewer", "incident-responder"]}}
        self.assertEqual(
            get_user_roles(user),
            frozenset({"analyst", "viewer", "incident_responder"}),
        )

    def test_viewer_does_not_receive_analyst_permissions(self):
        user = {"app_metadata": {"role": "viewer"}}
        self.assertTrue(has_any_role(user, {"viewer"}))
        self.assertFalse(has_any_role(user, {"admin", "analyst"}))

    def test_user_metadata_is_not_trusted(self):
        self.assertFalse(is_admin_user({"user_metadata": {"role": "admin"}}))
        self.assertEqual(get_user_roles({"user_metadata": {"role": "analyst"}}), frozenset())

    def test_unknown_and_malformed_roles_fail_closed(self):
        self.assertEqual(get_user_roles({"app_metadata": {"role": "superuser"}}), frozenset())
        self.assertEqual(get_user_roles({"app_metadata": None}), frozenset())
        self.assertEqual(get_user_roles({"app_metadata": {"roles": "admin"}}), frozenset())


if __name__ == "__main__":
    unittest.main()
