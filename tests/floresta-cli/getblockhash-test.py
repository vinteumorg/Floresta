"""
floresta_cli_getblockhash.py

This functional test cli utility to interact with a Floresta node with `getblockhash`
"""

from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


class GetBlockhashTest(FlorestaTestFramework):
    """
    Test `getblock` with a fresh node and expected initial 0 height block
    """

    nodes = [-1]
    best_block = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

    def set_test_params(self):
        """
        Setup a single node
        """
        GetBlockhashTest.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRP and get the hash of height 0
        """
        # Start node
        self.run_node(GetBlockhashTest.nodes[0])
        self.wait_for_rpc_connection(GetBlockhashTest.nodes[0])

        # Test assertions
        node = self.get_node(GetBlockhashTest.nodes[0])
        response = node.get_blockhash(0)
        self.assertEqual(response, GetBlockhashTest.best_block)

        # Shutdown node
        self.stop_node(GetBlockhashTest.nodes[0])


if __name__ == "__main__":
    GetBlockhashTest().main()
