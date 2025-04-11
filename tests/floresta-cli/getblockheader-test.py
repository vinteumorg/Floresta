"""
floresta_cli_getblockheader.py

This functional test cli utility to interact with a Floresta node with `getblockheader`
"""

from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


class GetBlockheaderHeightZeroTest(FlorestaTestFramework):
    """
    Test `getblockheader` with a fresh node and expect a result like this:
    
    ````bash
    $> ./target/release floresta_cli --network=regtest getblockheader \
        0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
    {
       "version": 1,
       "prev_blockhash": "0000000000000000000000000000000000000000000000000000000000000000",
       "merkle_root": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
       "time": 1296688602,
       "bits": 545259519,
       "nonce": 2
    }
    ```
    """

    nodes = [-1]
    version = 1
    blockhash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    prev_blockhash = "0000000000000000000000000000000000000000000000000000000000000000"
    merkle_root = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    time = 1296688602
    bits = 545259519
    nonce = 2

    def set_test_params(self):
        """
        Setup a single node
        """
        GetBlockheaderHeightZeroTest.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRPC and get the header of the genesis block
        """
        # Start node
        self.run_node(GetBlockheaderHeightZeroTest.nodes[0])
        self.wait_for_rpc_connection(GetBlockheaderHeightZeroTest.nodes[0])

        # Test assertions
        node = self.get_node(GetBlockheaderHeightZeroTest.nodes[0])
        response = node.get_blockheader(GetBlockheaderHeightZeroTest.blockhash)
        self.assertEqual(response["version"], GetBlockheaderHeightZeroTest.version)
        self.assertEqual(
            response["prev_blockhash"], GetBlockheaderHeightZeroTest.prev_blockhash
        )
        self.assertEqual(
            response["merkle_root"], GetBlockheaderHeightZeroTest.merkle_root
        )
        self.assertEqual(response["time"], GetBlockheaderHeightZeroTest.time)
        self.assertEqual(response["bits"], GetBlockheaderHeightZeroTest.bits)
        self.assertEqual(response["nonce"], GetBlockheaderHeightZeroTest.nonce)

        # Shutdown node
        self.stop_node(GetBlockheaderHeightZeroTest.nodes[0])


if __name__ == "__main__":
    GetBlockheaderHeightZeroTest().main()
