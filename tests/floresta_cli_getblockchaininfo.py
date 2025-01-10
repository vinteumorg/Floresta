"""
floresta_cli_getblockchainfo.py

This functional test cli utility to interact with a Floresta node with `getblockchaininfo`
"""

from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER


class GetBlockchaininfoTest(FlorestaTestFramework):
    """
    Test `getblockchaininfo` with a fresh node and its first block
    """

    nodes = [-1]
    best_block = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    difficulty = 1
    height = 0
    ibd = True
    latest_block_time = 1296688602
    latest_work = "2"
    leaf_count = 0
    progress = None
    root_count = 0
    root_hashes = []
    validated = 0

    def set_test_params(self):
        """
        Setup a single node
        """
        GetBlockchaininfoTest.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRPC server and get some data about blockchain with only regtest genesis block
        """
        # Start node
        self.run_node(GetBlockchaininfoTest.nodes[0])
        self.wait_for_rpc_connection(GetBlockchaininfoTest.nodes[0])

        # Test assertions
        node = self.get_node(GetBlockchaininfoTest.nodes[0])
        response = node.get_blockchain_info()
        assert response["best_block"] == GetBlockchaininfoTest.best_block
        assert response["difficulty"] == GetBlockchaininfoTest.difficulty
        assert response["height"] == GetBlockchaininfoTest.height
        assert response["ibd"] == GetBlockchaininfoTest.ibd
        assert response["latest_block_time"] == GetBlockchaininfoTest.latest_block_time
        assert response["latest_work"] == GetBlockchaininfoTest.latest_work
        assert response["leaf_count"] == GetBlockchaininfoTest.leaf_count
        assert response["progress"] == GetBlockchaininfoTest.progress
        assert response["root_count"] == GetBlockchaininfoTest.root_count
        assert response["root_hashes"] == GetBlockchaininfoTest.root_hashes
        assert response["validated"] == GetBlockchaininfoTest.validated

        # Shutdown node
        self.stop_node(GetBlockchaininfoTest.nodes[0])


if __name__ == "__main__":
    GetBlockchaininfoTest().main()
