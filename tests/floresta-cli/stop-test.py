"""
floresta_cli_stop.py

This functional test cli utility to interact with a Floresta node with `stop`
"""

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


class StopTest(FlorestaTestFramework):
    """
    Test `stop` command with a fresh node and its initial state.
    """

    nodes = [-1]

    def set_test_params(self):
        """
        Setup a single node
        """
        StopTest.nodes[0] = self.add_node(extra_args=[], rpcserver=REGTEST_RPC_SERVER)

    def run_test(self):
        """
        Run JSONRPC server and get some data about blockchain with only regtest genesis block
        """
        # Start node and wait for it to be ready
        # This is important to ensure that the node
        # is fully initialized before we attempt to stop it.
        # This is already made in the `run_node` method
        # but let's wait a bit more to be sure
        self.run_node(StopTest.nodes[0])
        node = self.get_node(StopTest.nodes[0])
        node.rpc.wait_for_connections(opened=True)

        # Generally, the self.stop_node() method
        # do all the work for us, but in this case
        # we're testing the method rpc.stop(), so
        # re-do all the steps  to ensure that it
        # was successful and the ports are closed
        result = node.rpc.stop()
        self.assertEqual(result, "florestad stopping")
        node.rpc.wait_for_connections(opened=False)
        node.daemon.process.wait()


if __name__ == "__main__":
    StopTest().main()
