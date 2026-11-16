import socket
import unittest
from unittest.mock import patch

from app.port_scanner import _probe, scan_network_ports


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        pass

    def sendall(self, _data):
        pass

    def recv(self, _size):
        return b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1"


class PortScannerTests(unittest.TestCase):
    def test_probe_extracts_ssh_product_and_version(self):
        with patch("socket.create_connection", return_value=FakeSocket()):
            result = _probe("192.168.1.10", 22, 0.1)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["product"], "OpenSSH")
        self.assertEqual(result["version"], "9.3p1")

    def test_scan_rejects_public_network(self):
        with self.assertRaises(ValueError):
            scan_network_ports("8.8.8.0/24")

    def test_scan_rejects_private_network_larger_than_256_addresses(self):
        with self.assertRaises(ValueError):
            scan_network_ports("10.0.0.0/16")


if __name__ == "__main__":
    unittest.main()
