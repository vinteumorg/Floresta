"""
florestad/tls-fail-test.py

This functional test checks the failure on connect to florestad's TLS port.
"""

import errno

from test_framework import FlorestaTestFramework
from test_framework.electrum.client import ElectrumClient
from test_framework.rpc.floresta import REGTEST_RPC_SERVER, REGTEST_RPC_TLS_SERVER


class TestSslFailInitialization(FlorestaTestFramework):
    """
    Test that a request to the TLS Electrum port will fail if we don't enable it
    with `--enable-electrum-tls` and (`--generate-cert` or (`--tls-key-path` and `tls-cert-path`)).
    """

    nodes = [-1]
    electrum = None

    def set_test_params(self):
        """
        Instantiate the node without Electrum TLS.
        """
        TestSslFailInitialization.nodes[0] = self.add_node(
            rpcserver=REGTEST_RPC_SERVER, tls=False
        )

    def run_test(self):
        """
        Run the node, create an Electrum client that will try to connect to
        the TLS port (20002), and assert that the connection was refused since TLS was not enabled.
        """
        self.run_node(TestSslFailInitialization.nodes[0])

        # Create a connection with an Electrum client at the default Electrum TLS port.
        # It must fail since there is nothing bound to it.
        with self.assertRaises(ConnectionRefusedError) as exc:
            self.log("Trying to connect the Electrum no-TLS client")
            TestSslFailInitialization.electrum = ElectrumClient(
                REGTEST_RPC_TLS_SERVER["host"],
                REGTEST_RPC_TLS_SERVER["ports"]["electrum-server-tls"],
            )

        self.log("Failed to connect to Electrum TLS client")
        self.assertIsSome(exc.exception)
        self.assertEqual(exc.exception.errno, errno.ECONNREFUSED)

        # Stop `florestad`
        self.stop_node(TestSslFailInitialization.nodes[0])


if __name__ == "__main__":
    TestSslFailInitialization().main()
