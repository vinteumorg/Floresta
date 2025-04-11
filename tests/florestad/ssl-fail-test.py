"""
florestad/ssl-fail-test.py

This functional test checks the failure on connect to florestad's TLS port.
"""

import errno

from test_framework.electrum_client import ElectrumClient
from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


class TestSslFailInitialization(FlorestaTestFramework):
    """
    Test the initialization of florestad without --ssl-key-path and --ssl-cert-path
    (and without proper keys), a request from Electrum client to TLS port and its failure.
    """

    nodes = [-1]
    electrum = None

    def set_test_params(self):
        """
        Setup a single node without SSL
        """
        TestSslFailInitialization.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER, ssl=False
        )

    def run_test(self):
        """
        Run the no-ssl node, create an electrum client that will try to connect to port 50002,
        and assert a connection refused failure.
        """
        self.run_node(TestSslFailInitialization.nodes[0])
        self.wait_for_rpc_connection(TestSslFailInitialization.nodes[0])

        # now try create a connection with an electrum client at default port
        # it must fail, since the TLS port isnt opened
        with self.assertRaises(ConnectionRefusedError) as exc:
            TestSslFailInitialization.electrum = ElectrumClient("0.0.0.0", 50002)

        self.assertEqual(exc.exception.errno, errno.ECONNREFUSED)

        # Shutdown node
        self.stop_node(TestSslFailInitialization.nodes[0])


if __name__ == "__main__":
    TestSslFailInitialization().main()
