"""
floresta_cli_getpeerinfo.py

This functional test cli utility to interact with a Floresta node with `getpeerinfo`
"""

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


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
        GetPeerInfoTest.nodes[0] = self.add_node(
            extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRPC server and get some data about blockchain with only regtest genesis block
        """
        # Start node
        self.run_node(GetPeerInfoTest.nodes[0])

        # Test assertions
        node = self.get_node(GetPeerInfoTest.nodes[0])

        result = node.rpc.get_peerinfo()
        self.assertIsSome(result)
        self.assertEqual(len(result), 0)

        # stop the node
        self.stop_node(GetPeerInfoTest.nodes[0])


if __name__ == "__main__":
    GetPeerInfoTest().main()
