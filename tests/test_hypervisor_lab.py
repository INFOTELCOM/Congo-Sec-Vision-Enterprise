import os
import unittest
from unittest.mock import patch
from app.hypervisor_lab import lab_inventory

class HypervisorLabTests(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    def test_lab_is_disabled_by_default(self):
        result = lab_inventory()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["machines"], [])
        self.assertTrue(result["simulated"])

    @patch.dict(os.environ, {"CSV_HYPERVISOR_LAB_MODE":"true"}, clear=True)
    def test_lab_returns_only_marked_synthetic_read_only_rows(self):
        result = lab_inventory()
        self.assertTrue(result["enabled"])
        self.assertEqual(result["count"], 8)
        self.assertEqual({x["provider"] for x in result["machines"]},
                         {"vmware", "proxmox", "virtualbox", "hyperv"})
        for machine in result["machines"]:
            self.assertTrue(machine["simulated"])
            self.assertTrue(machine["read_only"])
            self.assertEqual(machine["source"], "simulation")
            self.assertTrue(machine["vm_id"].startswith("lab-"))

if __name__ == "__main__":
    unittest.main()
