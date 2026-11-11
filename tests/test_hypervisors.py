"""Unit tests for read-only hypervisor inventory adapters.

Run with: python -m unittest tests.test_hypervisors -v
All provider traffic and host commands are mocked; no real infrastructure is contacted.
"""
import json
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch

from app.hypervisors import (
    HyperVConnector, HypervisorError, ProxmoxConnector,
    VMwareConnector, VirtualBoxConnector, _parse_vbox_list,
)


class VMwareConnectorTests(unittest.TestCase):
    @patch.dict(os.environ, {
        "CSV_VMWARE_URL": "https://vcenter.example",
        "CSV_VMWARE_USERNAME": "readonly",
        "CSV_VMWARE_PASSWORD": "not-a-real-password",
        "CSV_VMWARE_VERIFY_TLS": "true",
    }, clear=False)
    @patch("app.hypervisors._request")
    def test_inventory_opens_session_reads_vms_and_closes_session(self, request):
        request.side_effect = [
            (200, b'"session-token"'),
            (200, b'[{"vm":"vm-101","name":"lab-vm","power_state":"POWERED_ON"}]'),
            (204, b""),
        ]
        rows = VMwareConnector().inventory()
        self.assertEqual(rows[0]["id"], "vm-101")
        self.assertTrue(rows[0]["read_only"])
        self.assertEqual(request.call_args_list[0].kwargs["method"], "POST")
        self.assertEqual(request.call_args_list[1].args[0], "https://vcenter.example/api/vcenter/vm")
        self.assertEqual(request.call_args_list[2].kwargs["method"], "DELETE")
        self.assertEqual(request.call_args_list[2].args[0], "https://vcenter.example/api/session")


class ProxmoxConnectorTests(unittest.TestCase):
    @patch.dict(os.environ, {
        "CSV_PROXMOX_URL": "https://pve.example:8006",
        "CSV_PROXMOX_TOKEN_ID": "soc-readonly@pve!inventory",
        "CSV_PROXMOX_TOKEN_SECRET": "not-a-real-secret",
        "CSV_PROXMOX_VERIFY_TLS": "true",
    }, clear=False)
    @patch("app.hypervisors._request", return_value=(200, b'{"data":[{"vmid":100,"name":"soc-lab","status":"running"}]}'))
    def test_inventory_uses_read_endpoint_and_token_auth(self, request):
        rows = ProxmoxConnector().inventory()
        self.assertEqual(rows[0]["id"], "100")
        self.assertTrue(rows[0]["read_only"])
        self.assertIn("/api2/json/cluster/resources?type=vm", request.call_args.args[0])
        self.assertTrue(request.call_args.kwargs["headers"]["Authorization"].startswith("PVEAPIToken="))


class VirtualBoxConnectorTests(unittest.TestCase):
    def test_parser_extracts_inventory(self):
        rows = _parse_vbox_list(
            "Name: soc-lab\nUUID: 1234\nState: running (since 2026-01-01)\n"
            "Memory size: 4096MB\nNumber of CPUs: 2\n"
        )
        self.assertEqual(rows[0]["id"], "1234")
        self.assertEqual(rows[0]["state"], "running")
        self.assertTrue(rows[0]["read_only"])

    @patch.dict(os.environ, {"CSV_VBOXMANAGE_PATH": "VBoxManage"}, clear=False)
    @patch("app.hypervisors.shutil.which", return_value="/usr/bin/VBoxManage")
    @patch("app.hypervisors.subprocess.run")
    def test_only_invokes_list_vms_command(self, run, _which):
        run.return_value = Mock(returncode=0, stdout="Name: lab\nUUID: vm-1\nState: powered off\n")
        rows = VirtualBoxConnector().inventory()
        self.assertEqual(rows[0]["id"], "vm-1")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/VBoxManage", "list", "vms", "--long"])
        self.assertEqual(run.call_args.kwargs["timeout"], 20)


class HyperVConnectorTests(unittest.TestCase):
    @patch.dict(os.environ, {
        "CSV_HYPERV_HOST": "http://hyperv.example:5985/wsman",
        "CSV_HYPERV_USERNAME": "readonly",
        "CSV_HYPERV_PASSWORD": "not-a-real-password",
    }, clear=False)
    def test_refuses_plaintext_winrm(self):
        with self.assertRaisesRegex(HypervisorError, "HTTPS"):
            HyperVConnector().inventory()

    @patch.dict(os.environ, {
        "CSV_HYPERV_HOST": "hyperv.example",
        "CSV_HYPERV_USERNAME": "readonly",
        "CSV_HYPERV_PASSWORD": "not-a-real-password",
        "CSV_HYPERV_TRANSPORT": "ntlm",
    }, clear=False)
    def test_runs_only_get_vm_over_https(self):
        result = Mock(status_code=0, std_out=json.dumps({
            "Name": "soc-vm", "Id": "vm-guid", "State": "Running"
        }).encode())
        session = Mock()
        session.run_ps.return_value = result
        fake_winrm = types.SimpleNamespace(Session=Mock(return_value=session))
        with patch.dict(sys.modules, {"winrm": fake_winrm}):
            rows = HyperVConnector().inventory()
        self.assertEqual(rows[0]["id"], "vm-guid")
        self.assertTrue(rows[0]["read_only"])
        self.assertTrue(fake_winrm.Session.call_args.args[0].startswith("https://"))
        command = session.run_ps.call_args.args[0]
        self.assertIn("Get-VM", command)
        self.assertNotRegex(command, r"(?i)\b(Start|Stop|Remove|Set)-VM\b")


if __name__ == "__main__":
    unittest.main()
