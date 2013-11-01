import os
import unittest

from pyptlib.client import ClientTransportPlugin
from pyptlib.config import EnvError, Config
from pyptlib.test.test_core import PluginCoreTestMixin

class testClient(PluginCoreTestMixin, unittest.TestCase):
    pluginType = ClientTransportPlugin

    def test_fromEnv_legit(self):
        """Legit environment"""
        TEST_ENVIRON = { "TOR_PT_STATE_LOCATION" : "/pt_stat",
                         "TOR_PT_MANAGED_TRANSPORT_VER" : "1",
                         "TOR_PT_CLIENT_TRANSPORTS" : "dummy" }

        os.environ = TEST_ENVIRON
        self.plugin._loadConfigFromEnv()
        self.assertOutputLinesEmpty()

    def test_fromEnv_bad(self):
        """Missing TOR_PT_MANAGED_TRANSPORT_VER."""
        TEST_ENVIRON = { "TOR_PT_STATE_LOCATION" : "/pt_stat",
                         "TOR_PT_CLIENT_TRANSPORTS" : "dummy" }

        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad2(self):
        """Missing TOR_PT_CLIENT_TRANSPORTS."""
        TEST_ENVIRON = { "TOR_PT_STATE_LOCATION" : "/pt_stat",
                         "TOR_PT_MANAGED_TRANSPORT_VER" : "1" }

        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")


if __name__ == '__main__':
    unittest.main()

