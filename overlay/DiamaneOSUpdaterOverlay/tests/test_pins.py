"""Source check of the Updater overlay's pins. Run: python3 -m unittest discover -s
overlay/DiamaneOSUpdaterOverlay/tests"""
import base64
import datetime
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

CONFIG = Path(__file__).resolve().parents[1] / 'res/xml/network_security_config.xml'
MIN_DAYS_LEFT = 90


class PinTests(unittest.TestCase):
    def setUp(self):
        self.config = ET.parse(CONFIG).getroot().find('domain-config')

    def test_both_hosts_share_existing_tls_pins(self):
        self.assertEqual({x.text for x in self.config.findall('domain')}, {'releases.diamaneos.de', 'releases-na.diamaneos.de'})
        pins = self.config.findall('pin-set/pin')
        self.assertTrue(pins)
        for pin in pins:
            self.assertEqual('SHA-256', pin.get('digest'))
            self.assertEqual(32, len(base64.b64decode(pin.text, validate=True)))

    def test_pins_stay_enforced(self):
        expires = datetime.date.fromisoformat(self.config.find('pin-set').get('expiration'))
        left = (expires - datetime.date.today()).days
        self.assertGreaterEqual(left, MIN_DAYS_LEFT, f'pins stop applying on {expires}: move the expiration')


if __name__ == '__main__':
    unittest.main()
