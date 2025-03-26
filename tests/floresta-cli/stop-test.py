"""
floresta_cli_stop.py

This functional test cli utility to interact with a Floresta node with `stop`
"""

from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


class StopTest(FlorestaTestFramework):
    """
    Test `stop` command with a fresh node and its initial state.
    """

    nodes = [-1]

    def set_test_params(self):
        """
        Setup a single node
        """
        StopTest.nodes[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    def run_test(self):
        """
        Run JSONRPC server and get some data about blockchain with only regtest genesis block
        """
        # Start node
        self.run_node(StopTest.nodes[0])
        self.wait_for_rpc_connection(StopTest.nodes[0])

        # Test assertions
        node = self.get_node(StopTest.nodes[0])
        result = node.stop()

        # node should be finished, do not call stop_node
        self.assertEqual(result, "florestad stopping")


if __name__ == "__main__":
    StopTest().main()
