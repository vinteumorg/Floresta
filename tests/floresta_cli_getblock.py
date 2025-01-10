"""
floresta_cli_getblock.py

This functional test cli utility to interact with a Floresta node with `getblock`
"""

from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER


class GetBlockTest(FlorestaTestFramework):
    """
    Test `getblock` with a fresh node and the first block with verbose levels 0 and 1
    """

    nodes = [-1]
    block = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

    # pylint: disable=line-too-long
    serialized_data = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

    bits = "ffff7f20"
    chainwork = "2"
    confirmations = 1
    difficulty = 1
    hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    height = 0
    mediantime = 1296688602
    merkleroot = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    n_tx = 1
    nonce = 2
    prev_blockhash = "0000000000000000000000000000000000000000000000000000000000000000"
    size = 285
    strippedsize = 285
    time = 1296688602
    tx = ["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"]
    version = 1
    version_hex = "01000000"
    weight = 1140

    def set_test_params(self):
        """
        Setup a single node
        """
        GetBlockTest.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRPC server and get some data about first block
        """
        self.run_node(GetBlockTest.nodes[0])
        self.wait_for_rpc_connection(GetBlockTest.nodes[0])

        # Test assertions
        node = self.get_node(GetBlockTest.nodes[0])

        # Test verbose level 0
        response = node.get_block(GetBlockTest.block, 0)
        assert response == GetBlockTest.serialized_data

        # Test verbose level 1
        response = node.get_block(GetBlockTest.block, 1)
        assert response["bits"] == GetBlockTest.bits
        assert response["chainwork"] == GetBlockTest.chainwork
        assert response["confirmations"] == GetBlockTest.confirmations
        assert response["difficulty"] == GetBlockTest.difficulty
        assert response["hash"] == GetBlockTest.hash
        assert response["height"] == GetBlockTest.height
        assert response["mediantime"] == GetBlockTest.mediantime
        assert response["merkleroot"] == GetBlockTest.merkleroot
        assert response["n_tx"] == GetBlockTest.n_tx
        assert response["nonce"] == GetBlockTest.nonce
        assert response["previousblockhash"] == GetBlockTest.prev_blockhash
        assert response["size"] == GetBlockTest.size
        assert response["strippedsize"] == GetBlockTest.strippedsize
        assert response["time"] == GetBlockTest.time
        assert len(response["tx"]) == len(GetBlockTest.tx)
        assert response["version"] == GetBlockTest.version
        assert response["versionHex"] == GetBlockTest.version_hex
        assert response["weight"] == GetBlockTest.weight

        # Shutdown node
        self.stop_node(GetBlockTest.nodes[0])


if __name__ == "__main__":
    GetBlockTest().main()
