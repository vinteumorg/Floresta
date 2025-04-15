"""
floresta_cli_getroots.py

This functional test cli utility to interact with a Floresta node with `getroots`
"""

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


class GetRootsIDBLenZeroTest(FlorestaTestFramework):
    """
    Test `getroots` rpc call,
    """

    nodes = [-1, -1]

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        GetRootsIDBLenZeroTest.nodes[0] = self.add_node(
            extra_args=[],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetRootsIDBLenZeroTest.nodes[0])

        # Test assertions
        node = self.get_node(GetRootsIDBLenZeroTest.nodes[0])
        vec_hashes = node.rpc.get_roots()
        self.assertTrue(len(vec_hashes) == 0)

        # stop the node
        self.stop_node(GetRootsIDBLenZeroTest.nodes[0])


if __name__ == "__main__":
    GetRootsIDBLenZeroTest().main()
