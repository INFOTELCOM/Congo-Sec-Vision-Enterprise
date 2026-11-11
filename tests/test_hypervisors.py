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
