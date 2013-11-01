import os
import unittest

from cStringIO import StringIO

from pyptlib.config import EnvError, Config

class PluginCoreTestMixin(object):
    """
    This class is not a TestCase but is meant to be mixed-into tests
    for subclasses of TransportPlugin.
    """
    pluginType = None
    origEnv = os.environ

    def setUp(self):
        if not self.pluginType:
            raise ValueError("pluginType not defined")
        self.plugin = self.pluginType(stdout=StringIO())
        os.environ = self.origEnv

    def getOutputLines(self):
        fp = self.plugin.stdout
        fp.seek(0)
        return fp.readlines()

    def installTestConfig(self, stateLocation="/pt_stat", **kwargs):
        """
        Install a base test config into the plugin.

        If this is not called, will try to get config from environment.
        """
        self.plugin.config = self.pluginType.configType(
            stateLocation, **kwargs)

    def assertEmpty(self, c, msg=None):
        """Assert that a container has length 0."""
        self.assertEqual(len(c), 0, "not empty: %s" % (msg or c))

    def assertOutputLinesEmpty(self):
        """Assert that the output is empty."""
        self.assertEmpty(self.getOutputLines())

    def assertOutputLinesStartWith(self, *prefixes):
        """Assert that the output lines each start with the respective prefix."""
        lines = self.getOutputLines()
        for p in prefixes:
            self.assertTrue(lines.pop(0).startswith(p))
        self.assertEmpty(lines)

    def test_declareSupports_bad_protocol_version(self):
        """Unsupported managed-proxy configuration protocol version."""
        self.installTestConfig(managedTransportVer=["666"])
        self.assertRaises(EnvError, self.plugin._declareSupports, [])
        self.assertOutputLinesStartWith("VERSION-ERROR ")

    def test_declareSupports_unknown_transports(self):
        """Unknown transports"""
        self.installTestConfig(transports="are,you,a,badfish,too?".split(","))
        self.plugin._declareSupports(["not_any_of_above"])
        self.assertEmpty(self.plugin.getTransports())
        self.assertOutputLinesStartWith("VERSION ")

    def test_declareSupports_partial(self):
        """Partial transports"""
        self.installTestConfig(transports="are,you,a,badfish,too?".split(","))
        self.plugin._declareSupports(["badfish", "not_any_of_above"])
        self.assertEquals(self.plugin.getTransports(), ["badfish"])
        self.assertOutputLinesStartWith("VERSION ")

    def test_getTransports_noinit(self):
        """getTransports raises correctly."""
        self.assertRaises(ValueError, self.plugin.getTransports)

    def test_init_passthru_loadConfigFromEnv_error(self):
        """init passes-through errors from loadConfigFromEnv."""
        self.plugin.configType = DummyConfig
        self.assertRaises(EnvError, self.plugin.init, [])
        self.assertOutputLinesStartWith("ENV-ERROR ")

    def test_init_correct_servedTransports(self):
        """init results in correct getTransports."""
        self.installTestConfig(transports=["yeayeayea"])
        self.plugin.init(["yeayeayea"])
        self.assertEquals(["yeayeayea"], self.plugin.getTransports())
        self.assertOutputLinesStartWith("VERSION ")

class DummyConfig(Config):

    @classmethod
    def fromEnv(cls, *args, **kwargs):
        """Dummy parser that always fails."""
        raise EnvError("test")

if __name__ == '__main__':
    unittest.main()
