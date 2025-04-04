"""
floresta_cli_getroots.py

This functional test cli utility to interact with a Floresta node with `getroots`
"""

from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


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
        GetRootsIDBLenZeroTest.nodes[0] = self.add_node_settings(
            chain="regtest",
            extra_args=[],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetRootsIDBLenZeroTest.nodes[0])
        self.wait_for_rpc_connection(GetRootsIDBLenZeroTest.nodes[0])

        # Test assertions
        node = self.get_node(GetRootsIDBLenZeroTest.nodes[0])
        vec_hashes = node.get_roots()
        self.assertTrue(len(vec_hashes) == 0)


if __name__ == "__main__":
    GetRootsIDBLenZeroTest().main()
