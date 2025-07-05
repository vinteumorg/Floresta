"""
florestad/tls-test.py

This functional test tests the proper creatiion of a TLS port on florestad.
"""

from test_framework import FlorestaTestFramework
from test_framework.electrum.client import ElectrumClient


class TestSslInitialization(FlorestaTestFramework):
    """
    Test the initialization of florestad with --tls-key-path and --tls-cert-path and
    a request from Electrum client to TLS port and its success.
    """

    nodes = [-1]
    electrum = None

    def set_test_params(self):
        """
        Setup a single node and a electrum client at port 20002
        """
        TestSslInitialization.nodes[0] = self.add_node(variant="florestad", tls=True)

    def run_test(self):
        """
        Run the TLS node, create a electrum client that will try to connect to port 20002.
        Send a ping to make sure everything is working.
        """
        self.run_node(TestSslInitialization.nodes[0])
        node = self.get_node(TestSslInitialization.nodes[0])

        # now create a connection with an electrum client at default port
        TestSslInitialization.electrum = ElectrumClient(
            node.get_host(),
            node.get_port("electrum-server-tls"),
            tls=True,
        )

        # request something to TLS port
        res = TestSslInitialization.electrum.ping()
        result = res["result"]
        id = res["id"]
        jsonrpc = res["jsonrpc"]

        # if pinged, we should get a "null" in response
        self.assertIsNone(result)
        self.assertEqual(id, 0)
        self.assertEqual(jsonrpc, "2.0")

        # stop the node
        self.stop_node(TestSslInitialization.nodes[0])


if __name__ == "__main__":
    TestSslInitialization().main()
