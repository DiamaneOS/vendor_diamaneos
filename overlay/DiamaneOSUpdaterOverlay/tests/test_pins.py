"""Source check of the Updater overlay's pins. Run: python3 -m unittest discover -s
overlay/DiamaneOSUpdaterOverlay/tests"""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

CONFIG = Path(__file__).resolve().parents[1] / 'res/xml/network_security_config.xml'


class PinTests(unittest.TestCase):
    def test_both_hosts_share_existing_tls_pins(self):
        config = ET.parse(CONFIG).getroot().find('domain-config')
        self.assertEqual({x.text for x in config.findall('domain')}, {'releases.diamaneos.de', 'releases-na.diamaneos.de'})
        self.assertTrue(config.findall('pin-set/pin'))


if __name__ == '__main__':
    unittest.main()
