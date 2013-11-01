import os
import unittest

from pyptlib.config import EnvError, Config
from pyptlib.server_config import get_transport_options_impl
from pyptlib.server import ServerTransportPlugin
from pyptlib.test.test_core import PluginCoreTestMixin
from pyptlib.core import SUPPORTED_TRANSPORT_VERSIONS

# a good valid environment to base modifications from
# so it's clearer to see exactly why an environment fails
BASE_ENVIRON = {
    "TOR_PT_STATE_LOCATION" : "/pt_stat",
    "TOR_PT_MANAGED_TRANSPORT_VER" : "1",
    "TOR_PT_EXTENDED_SERVER_PORT" : "",
    "TOR_PT_ORPORT" : "127.0.0.1:43210",
    "TOR_PT_SERVER_BINDADDR" : "dummy-127.0.0.1:5556,boom-127.0.0.1:6666",
    "TOR_PT_SERVER_TRANSPORTS" : "dummy,boom"
}

class testServer(PluginCoreTestMixin, unittest.TestCase):
    pluginType = ServerTransportPlugin

    def test_fromEnv_legit(self):
        """Legit environment."""
        os.environ = BASE_ENVIRON
        self.plugin._loadConfigFromEnv()
        self.assertOutputLinesEmpty()

    def test_fromEnv_bad(self):
        """Missing TOR_PT_MANAGED_TRANSPORT_VER."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON.pop("TOR_PT_MANAGED_TRANSPORT_VER")
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad2(self):
        """Missing TOR_PT_ORPORT."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON.pop("TOR_PT_ORPORT")
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad3(self):
        """Missing TOR_PT_EXTENDED_SERVER_PORT."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON.pop("TOR_PT_EXTENDED_SERVER_PORT")
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad4(self):
        """TOR_PT_EXTENDED_SERVER_PORT not an addport."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_EXTENDED_SERVER_PORT"] = "cakez"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad5(self):
        """TOR_PT_ORPORT not an addport."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_ORPORT"] = "lulz"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad6(self):
        """TOR_PT_SERVER_BINDADDR not an addport."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_SERVER_BINDADDR"] = "dummy-lyrical_content,boom-127.0.0.1:6666"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad7(self):
        """Assymetric TOR_PT_SERVER_TRANSPORTS and TOR_PT_SERVER_BINDADDR."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_SERVER_BINDADDR"] = "dummy-127.0.0.1:5556,laughs-127.0.0.1:6666"
        TEST_ENVIRON["TOR_PT_SERVER_TRANSPORTS"] = "dummy,boom"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad8(self):
        """Assymetric TOR_PT_SERVER_TRANSPORTS and TOR_PT_SERVER_BINDADDR."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_SERVER_BINDADDR"] = "dummy-127.0.0.1:5556,laughs-127.0.0.1:6666"
        TEST_ENVIRON["TOR_PT_SERVER_TRANSPORTS"] = "dummy"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_bad9(self):
        """Assymetric TOR_PT_SERVER_TRANSPORTS and TOR_PT_SERVER_BINDADDR."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_SERVER_BINDADDR"] = "dummy-127.0.0.1:5556"
        TEST_ENVIRON["TOR_PT_SERVER_TRANSPORTS"] = "dummy,laughs"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_fromEnv_disabled_extorport(self):
        """Disabled TOR_PT_EXTENDED_SERVER_PORT."""
        os.environ = BASE_ENVIRON
        config = self.plugin._loadConfigFromEnv()
        self.assertIsNone(config.getExtendedORPort())

    def test_fromEnv_ext_or_but_no_auth_cookie(self):
        """TOR_PT_EXTENDED_SERVER_PORT without TOR_PT_AUTH_COOKIE_FILE."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_EXTENDED_SERVER_PORT"] = "127.0.0.1:5555"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin._loadConfigFromEnv)

    def test_fromEnv_auth_cookie_but_no_ext_or(self):
        """TOR_PT_AUTH_COOKIE_FILE without TOR_PT_EXTENDED_SERVER_PORT."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON.pop("TOR_PT_EXTENDED_SERVER_PORT")
        TEST_ENVIRON["TOR_PT_AUTH_COOKIE_FILE"] = "/lulzie"
        os.environ = TEST_ENVIRON
        self.assertRaises(EnvError, self.plugin.init, ["what"])

    def test_init_correct_ext_orport(self):
        """Correct Extended ORPort configuration."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_EXTENDED_SERVER_PORT"] = "127.0.0.1:5555"
        TEST_ENVIRON["TOR_PT_AUTH_COOKIE_FILE"] = "/lulzie"
        os.environ = TEST_ENVIRON
        self.plugin.init([])
        self.assertEquals(self.plugin.config.getAuthCookieFile(), '/lulzie')
        self.assertEquals(self.plugin.config.getExtendedORPort(), ('127.0.0.1', 5555))
        self.assertOutputLinesStartWith("VERSION ")

    def test_init_correct_transport_bindaddr(self):
        """Correct Extended ORPort configuration."""
        os.environ = BASE_ENVIRON
        self.plugin.init(["dummy", "boom"])
        bindaddr = self.plugin.getBindAddresses()
        self.assertEquals(bindaddr["dummy"], ('127.0.0.1', 5556))
        self.assertEquals(bindaddr["boom"], ('127.0.0.1', 6666))
        self.assertOutputLinesStartWith("VERSION ")

class testServerOutput(PluginCoreTestMixin, unittest.TestCase):
    """
    Test the output of pyptlib. That is, test the SMETHOD lines, etc.
    """
    pluginType = ServerTransportPlugin

    def test_smethod_line(self):
        """Test output SMETHOD lines."""
        os.environ = BASE_ENVIRON
        self.plugin.init(["dummy", "boom"])
        for transport, transport_bindaddr in self.plugin.getBindAddresses().items():
            self.plugin.reportMethodSuccess(transport, transport_bindaddr, None)
        self.plugin.reportMethodsEnd()

        self.assertIn("SMETHOD dummy 127.0.0.1:5556\n", self.getOutputLines())
        self.assertIn("SMETHOD boom 127.0.0.1:6666\n", self.getOutputLines())
        self.assertIn("SMETHODS DONE\n", self.getOutputLines())

    def test_smethod_line_args(self):
        """Test an SMETHOD line with extra arguments."""
        TEST_ENVIRON = dict(BASE_ENVIRON)
        TEST_ENVIRON["TOR_PT_SERVER_TRANSPORT_OPTIONS"] = "boom:roots=culture;random:no=care;boom:first=fire"
        os.environ = TEST_ENVIRON
        self.plugin.init(["dummy", "boom"])
        for transport, transport_bindaddr in self.plugin.getBindAddresses().items():
            self.plugin.reportMethodSuccess(transport, transport_bindaddr, None)
        self.plugin.reportMethodsEnd()

        self.assertIn("SMETHOD boom 127.0.0.1:6666 ARGS:roots=culture,first=fire\n", self.getOutputLines())

    def test_smethod_line_explicit_args(self):
        """Test an SMETHOD line with extra arguments."""
        os.environ = BASE_ENVIRON
        self.plugin.init(["dummy", "boom"])
        for transport, transport_bindaddr in self.plugin.getBindAddresses().items():
            self.plugin.reportMethodSuccess(transport, transport_bindaddr, "roots=culture,first=fire")
        self.plugin.reportMethodsEnd()

        self.assertIn("SMETHOD boom 127.0.0.1:6666 ARGS:roots=culture,first=fire\n", self.getOutputLines())

class testUtils(unittest.TestCase):
    def test_get_transport_options_wrong(self):
        """Invalid options string"""
        to_parse = "trebuchet_secret=nou"
        self.assertRaises(ValueError, get_transport_options_impl, to_parse)

    def test_get_transport_options_wrong_2(self):
        """No k=v value"""
        to_parse = "trebuchet:secret~nou"
        self.assertRaises(ValueError, get_transport_options_impl, to_parse)

    def test_get_transport_options_correct(self):
        to_parse = "trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes;ballista:fun=no;archer:bow=yes"
        expected = {"trebuchet" : {"secret" : "nou", "cache" : "/tmp/cache"} , "ballista" : {"secret" : "yes", "fun" : "no"}, "archer" : {"bow" : "yes" } }

        result = get_transport_options_impl(to_parse)
        self.assertEquals(result, expected)

if __name__ == '__main__':
    unittest.main()

