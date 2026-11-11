import unittest
from unittest.mock import patch
from app.hypervisors import HypervisorError, ProxmoxConnector, VMwareConnector, VirtualBoxConnector, _parse_vbox_list, inventory

class HypervisorConnectorTests(unittest.TestCase):
    def test_vbox_parser_normalizes_inventory(self):
        raw = """Name: Lab VM
UUID: 1234-5678
Guest OS: Ubuntu (64-bit)
State: running (since 2026-11-10T10:00:00)
Memory size: 4096MB
Number of CPUs: 2

"""
        rows = _parse_vbox_list(raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["provider"], "virtualbox")
        self.assertEqual(rows[0]["id"], "1234-5678")
        self.assertEqual(rows[0]["state"], "running")
        self.assertEqual(rows[0]["metadata"]["memory_mb"], 4096)
        self.assertTrue(rows[0]["read_only"])

    def test_unknown_provider_is_rejected(self):
        with self.assertRaises(HypervisorError): inventory("unknown")

    @patch.dict("os.environ", {"CSV_PROXMOX_URL":"https://pve.invalid",
        "CSV_PROXMOX_TOKEN_ID":"readonly@pve!csv", "CSV_PROXMOX_TOKEN_SECRET":"test-secret"})
    @patch("app.hypervisors._json_request")
    def test_proxmox_inventory_maps_vm_resources(self, request):
        request.return_value = {"data":[{"vmid":100,"name":"soc-lab","status":"running",
            "node":"pve01","type":"qemu","cpu":2,"mem":1024,"maxmem":4096,"disk":2048,"maxdisk":8192}]}
        rows = ProxmoxConnector().inventory()
        self.assertEqual(rows[0]["id"], "100")
        self.assertEqual(rows[0]["metadata"]["node"], "pve01")
        self.assertEqual(rows[0]["state"], "running")
        self.assertTrue(rows[0]["read_only"])
        request.assert_called_once()

    @patch.dict("os.environ", {}, clear=True)
    def test_vmware_missing_config_fails_closed(self):
        with self.assertRaises(HypervisorError): VMwareConnector().inventory()

    @patch.dict("os.environ", {"CSV_HYPERV_HOST":"http://hyperv.example.invalid", "CSV_HYPERV_USERNAME":"user", "CSV_HYPERV_PASSWORD":"test"})
    def test_hyperv_refuses_plaintext_winrm(self):
        from app.hypervisors import HyperVConnector
        with self.assertRaises(HypervisorError):
            HyperVConnector().inventory()

    @patch("app.hypervisors.shutil.which", return_value=None)
    def test_virtualbox_missing_host_binary_fails_closed(self, _which):
        with self.assertRaises(HypervisorError): VirtualBoxConnector().inventory()

if __name__ == "__main__": unittest.main()

# Additional adapter safety tests. Provider APIs and host commands are mocked;
# these tests never contact real infrastructure.
import json
import os
import sys
import types
from unittest.mock import Mock
from app.hypervisors import HyperVConnector


class HypervisorReadOnlySafetyTests(unittest.TestCase):
    @patch.dict(os.environ, {
        "CSV_VMWARE_URL": "https://vcenter.example",
        "CSV_VMWARE_USERNAME": "readonly",
        "CSV_VMWARE_PASSWORD": "not-a-real-password",
        "CSV_VMWARE_VERIFY_TLS": "true",
    }, clear=False)
    @patch("app.hypervisors._request")
    def test_vmware_session_and_inventory_methods(self, request):
        request.side_effect = [
            (200, b'"session-token"'),
            (200, b'[{"vm":"vm-101","name":"lab-vm","power_state":"POWERED_ON"}]'),
            (204, b""),
        ]
        rows = VMwareConnector().inventory()
        self.assertEqual(rows[0]["id"], "vm-101")
        self.assertEqual(request.call_args_list[0].kwargs["method"], "POST")
        self.assertEqual(request.call_args_list[1].args[0], "https://vcenter.example/api/vcenter/vm")
        self.assertEqual(request.call_args_list[2].kwargs["method"], "DELETE")

    @patch.dict(os.environ, {"CSV_PROXMOX_URL":"https://pve.example:8006",
        "CSV_PROXMOX_TOKEN_ID":"readonly@pve!inventory",
        "CSV_PROXMOX_TOKEN_SECRET":"not-a-real-secret", "CSV_PROXMOX_VERIFY_TLS":"true"}, clear=False)
    @patch("app.hypervisors._request", return_value=(200, b'{"data":[{"vmid":100,"name":"soc-lab","status":"running"}]}'))
    def test_proxmox_uses_inventory_read_endpoint(self, request):
        rows = ProxmoxConnector().inventory()
        self.assertEqual(rows[0]["id"], "100")
        self.assertIn("/api2/json/cluster/resources?type=vm", request.call_args.args[0])
        self.assertTrue(request.call_args.kwargs["headers"]["Authorization"].startswith("PVEAPIToken="))

    @patch.dict(os.environ, {"CSV_VBOXMANAGE_PATH":"VBoxManage"}, clear=False)
    @patch("app.hypervisors.shutil.which", return_value="/usr/bin/VBoxManage")
    @patch("app.hypervisors.subprocess.run")
    def test_virtualbox_executes_only_inventory_command(self, run, _which):
        run.return_value = Mock(returncode=0, stdout="Name: lab\\nUUID: vm-1\\nState: powered off\\n")
        rows = VirtualBoxConnector().inventory()
        self.assertEqual(rows[0]["id"], "vm-1")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/VBoxManage", "list", "vms", "--long"])
        self.assertEqual(run.call_args.kwargs["timeout"], 20)

    @patch.dict(os.environ, {"CSV_HYPERV_HOST":"hyperv.example",
        "CSV_HYPERV_USERNAME":"readonly", "CSV_HYPERV_PASSWORD":"not-a-real-password",
        "CSV_HYPERV_TRANSPORT":"ntlm"}, clear=False)
    def test_hyperv_runs_only_get_vm_over_https(self):
        result = Mock(status_code=0, std_out=json.dumps(
            {"Name":"soc-vm","Id":"vm-guid","State":"Running"}).encode())
        session = Mock()
        session.run_ps.return_value = result
        fake_winrm = types.SimpleNamespace(Session=Mock(return_value=session))
        with patch.dict(sys.modules, {"winrm":fake_winrm}):
            rows = HyperVConnector().inventory()
        self.assertEqual(rows[0]["id"], "vm-guid")
        self.assertTrue(fake_winrm.Session.call_args.args[0].startswith("https://"))
        command = session.run_ps.call_args.args[0]
        self.assertIn("Get-VM", command)
        self.assertNotRegex(command, r"(?i)\b(Start|Stop|Remove|Set)-VM\b")
