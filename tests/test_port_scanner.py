import socket

import pytest

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


def test_probe_extracts_ssh_product_and_version(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    result = _probe("192.168.1.10", 22, 0.1)
    assert result["state"] == "open"
    assert result["product"] == "OpenSSH"
    assert result["version"] == "9.3p1"


def test_scan_rejects_public_network():
    with pytest.raises(ValueError):
        scan_network_ports("8.8.8.0/24")


def test_scan_rejects_private_network_larger_than_256_addresses():
    with pytest.raises(ValueError):
        scan_network_ports("10.0.0.0/16")
