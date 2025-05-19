"""
integration-test.py

This is an example of how a tests with integrated electrum should look like,
see `tests/test_framework/test_framework.py` for more info.
"""

from test_framework import FlorestaTestFramework
from test_framework.rpc.bitcoin import REGTEST_RPC_SERVER as bitcoind_rpc
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as florestad_rpc
from test_framework.rpc.utreexo import REGTEST_RPC_SERVER as utreexod_rpc


class IntegrationTest(FlorestaTestFramework):
    """
    Tests should be a child class from FlorestaTestFramework

    In each test class definition, `set_test_params` and `run_test`, say what
    the test do and the expected result in the docstrings
    """

    index = [-1, -1, -1]
    expected_chain = "regtest"

    def set_test_params(self):
        """
        Here we define setup for test adding a node definition
        """
        IntegrationTest.index[0] = self.add_node(
            variant="florestad", rpcserver=florestad_rpc
        )

        # since utreexod and bitcoind
        # uses the same RPC server, we need to
        # select a different port for utreexod
        utreexod_rpc["ports"]["server"] = 18446
        utreexod_rpc["ports"]["rpc"] = 18447
        IntegrationTest.index[1] = self.add_node(
            variant="utreexod",
            rpcserver=utreexod_rpc,
            extra_args=["--listen=127.0.0.1:18446", "--rpclisten=127.0.0.1:18447"],
        )

        IntegrationTest.index[2] = self.add_node(
            variant="bitcoind",
            rpcserver=bitcoind_rpc,
        )

    # All tests should override the run_test method
    def run_test(self):
        """
        Here we define the test itself:

        - creates two dummy rpc listening on its default port,
          one for florestad and another for utreexod
        - perform some requests to FlorestaRPC node
        - perform some requests to UtreexoRPC node
        - assert the responses from both nodes
        - compare if both have similar values
        - if any assertion fails, all nodes will be stopped
        - if no error occurs, all nodes will be stopped at the end
        """
        # Start a new node (this crate's binary)
        # This method start a defined daemon,
        # in this case, `florestad`, and wait for
        # all ports opened by it, including the
        # RPC port to be available
        self.run_node(IntegrationTest.index[0])

        # Start a new node (this go's binary)
        # This method start a defined daemon,
        # in this case, `utreexod`, and wait for
        # all ports opened by it, including the
        # RPC port to be available
        self.run_node(IntegrationTest.index[1])

        # Start a new node (the bitcoin-core binary)
        # This method start a defined daemon,
        # in this case, `bitcoind`, and wait for
        # all ports opened by it, including the
        # RPC port to be available
        self.run_node(IntegrationTest.index[2])

        # get both nodes
        floresta_node = self.get_node(IntegrationTest.index[0])
        utreexo_node = self.get_node(IntegrationTest.index[1])
        bitcoin_node = self.get_node(IntegrationTest.index[2])

        # Perform for some defined requests to FlorestaRPC
        # that should be the same for UtreexoRPC and BitcoinRPC
        floresta_response = floresta_node.rpc.get_blockchain_info()
        utreexo_response = utreexo_node.rpc.get_blockchain_info()
        bitcoin_response = bitcoin_node.rpc.get_blockchain_info()

        # the chain should be the same (regtest)
        self.assertEqual(floresta_response["chain"], IntegrationTest.expected_chain)
        self.assertEqual(utreexo_response["chain"], IntegrationTest.expected_chain)
        self.assertEqual(bitcoin_response["chain"], IntegrationTest.expected_chain)

        # stop all nodes
        self.stop()


if __name__ == "__main__":
    IntegrationTest().main()
