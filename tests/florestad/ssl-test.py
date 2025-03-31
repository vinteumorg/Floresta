"""
florestad/ssl-test.py

This functional test tests the proper creatiion of a TLS port on florestad.
"""

from test_framework.electrum_client import ElectrumClient
from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


class TestSslInitialization(FlorestaTestFramework):
    """
    Test the initialization of florestad with --ssl-key-path and --ssl-cert-path and
    a request from Electrum client to TLS port and its success.
    """

    nodes = [-1]
    electrum = None

    def set_test_params(self):
        """
        Setup a single node and a electrum client at port 50002
        """
        TestSslInitialization.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER, ssl=True
        )

    def run_test(self):
        """
        Run the ssl node, create a electrum client that will try to connect to port 50002.
        Send a ping to make sure everything is working.
        """
        self.run_node(TestSslInitialization.nodes[0])
        self.wait_for_rpc_connection(TestSslInitialization.nodes[0])

        # now create a connection with an electrum client at default port
        TestSslInitialization.electrum = ElectrumClient("0.0.0.0", 50002)

        # request something to TLS port
        result = TestSslInitialization.electrum.ping()

        # if pinged, we should get a response `""`
        self.assertEqual(result, "")

        # Shutdown node
        self.stop_node(TestSslInitialization.nodes[0])


if __name__ == "__main__":
    TestSslInitialization().main()
