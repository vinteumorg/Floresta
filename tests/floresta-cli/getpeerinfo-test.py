"""
floresta_cli_getpeerinfo.py

This functional test cli utility to interact with a Floresta node with `getpeerinfo`
"""

from test_framework.floresta_rpc import REGTEST_RPC_SERVER, JSONRPCError
from test_framework.test_framework import FlorestaTestFramework


class GetPeerInfoTest(FlorestaTestFramework):
    """
    Test `getpeerinfo` with a fresh node and its initial state. It should return
    a error because its making a IDB.
    """

    nodes = [-1]
    expected_error = "Node is in initial block download, wait until it's finished"

    def set_test_params(self):
        """
        Setup a single node
        """
        GetPeerInfoTest.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRPC server and get some data about blockchain with only regtest genesis block
        """
        # Start node
        self.run_node(GetPeerInfoTest.nodes[0])
        self.wait_for_rpc_connection(GetPeerInfoTest.nodes[0])

        # Test assertions
        node = self.get_node(GetPeerInfoTest.nodes[0])

        result = node.get_peerinfo()
        self.assertIsSome(result)
        self.assertEqual(len(result), 0)
        self.stop_node(GetPeerInfoTest.nodes[0])


if __name__ == "__main__":
    GetPeerInfoTest().main()
