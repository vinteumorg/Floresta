"""
floresta_cli_stop.py

This functional test cli utility to interact with a Floresta node with `stop`
"""

import re
from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as florestad_rpc
from test_framework.rpc.bitcoin import REGTEST_RPC_SERVER as bitcoin_rpc


class StopTest(FlorestaTestFramework):
    """
    Test `stop` command with a fresh node and its initial state.
    """

    nodes = [-1, -1]

    def set_test_params(self):
        """
        Setup a single node
        """
        StopTest.nodes[0] = self.add_node(
            variant="florestad", extra_args=[], rpcserver=florestad_rpc
        )
        StopTest.nodes[1] = self.add_node(
            variant="bitcoind", extra_args=[], rpcserver=bitcoin_rpc
        )

    def run_test(self):
        """
        Run JSONRPC stop command on both flrestad and bitcoin core nodes and
        check if floresta and bitcoin core nodes are stopped correctly and if
        the floresta's stop message is compliant with bitcoin core's stop message.
        """
        self.run_node(StopTest.nodes[0])
        self.run_node(StopTest.nodes[1])

        floresta = self.get_node(StopTest.nodes[0])
        bitcoin = self.get_node(StopTest.nodes[1])

        # Generally, the self.stop_node() method
        # do all the work for us, but in this case
        # we're testing the method rpc.stop(), so
        # re-do all the steps  to ensure that it
        # was successful and the ports are closed
        result_floresta = floresta.rpc.stop()
        result_bitcoin = bitcoin.rpc.stop()

        # Check if the messages are correct
        for res in [result_floresta, result_bitcoin]:
            self.assertIsSome(res)
            self.assertIn("stopping", res)
            self.assertMatch(res, re.compile(r"^(Floresta|Bitcoin Core) stopping$"))

        # Check that the node is stopped
        floresta.rpc.wait_for_connections(opened=False)
        bitcoin.rpc.wait_for_connections(opened=False)


if __name__ == "__main__":
    StopTest().main()
