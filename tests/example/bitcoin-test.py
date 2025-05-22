"""
bitcoin-test.py

This is an example of how a tests with bitcoin should look like,
see `tests/test_framework/test_framework.py` for more info.
"""

from test_framework import FlorestaTestFramework
from test_framework.rpc.bitcoin import REGTEST_RPC_SERVER


class BitcoindTest(FlorestaTestFramework):
    """
    Tests should be a child class from FlorestaTestFramework

    In each test class definition, `set_test_params` and `run_test`, say what
    the test do and the expected result in the docstrings
    """

    index = [-1]
    expected_chain = "regtest"
    expected_height = 0
    expected_headers = 0
    expected_blockhash = (
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )
    expected_difficulty = 1

    def set_test_params(self):
        """
        Here we define setup for test adding a node definition
        """
        BitcoindTest.index[0] = self.add_node(
            variant="bitcoind", rpcserver=REGTEST_RPC_SERVER
        )

    # All tests should override the run_test method
    def run_test(self):
        """
        Here we define the test itself:

        - creates a dummy rpc listening on default port
        - perform some requests to BitcoinRPC node
        - if any assertion fails, all nodes will be stopped
        - if no error occurs, all nodes will be stopped at the end
        """
        # Start a new node (the bitcoind's binary).
        # This method start a defined daemon,
        # in this case, `bitcoind`, and wait for
        # all ports opened by it, including the
        # RPC port to be available
        self.run_node(BitcoindTest.index[0])

        # Once the node is running, we can create
        # a request to the RPC server. In this case, we
        # call it node, but in truth, will be a RPC request
        # to perform some kind of action
        node = self.get_node(BitcoindTest.index[0])
        bitcoin_response = node.rpc.get_blockchain_info()

        self.assertEqual(bitcoin_response["chain"], BitcoindTest.expected_chain)
        self.assertEqual(
            bitcoin_response["bestblockhash"], BitcoindTest.expected_blockhash
        )
        self.assertTrue(bitcoin_response["difficulty"] > 0)

        self.stop_node(BitcoindTest.index[0])


if __name__ == "__main__":
    BitcoindTest().main()
