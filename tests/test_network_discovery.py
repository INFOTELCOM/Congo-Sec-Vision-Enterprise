import unittest

from app.network_discovery import validate_network


class NetworkDiscoveryValidationTests(unittest.TestCase):
    def test_accepts_private_lab_subnet(self):
        network = validate_network("192.168.50.0/24")
        self.assertEqual(str(network), "192.168.50.0/24")

    def test_rejects_public_subnet(self):
        with self.assertRaises(ValueError):
            validate_network("8.8.8.0/24")

    def test_rejects_oversized_subnet(self):
        with self.assertRaises(ValueError):
            validate_network("10.0.0.0/16")


if __name__ == "__main__":
    unittest.main()
