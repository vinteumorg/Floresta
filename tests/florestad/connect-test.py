"""
Test the --connect cli option of florestad

This test will start a utreexod, then start a florestad node with
the --connect option pointing to the utreexod node. Then check if
the utreexod node is connected to the florestad node.
"""

from test_framework import UtreexoRPC, FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as florestad_rpc
from test_framework.rpc.utreexo import REGTEST_RPC_SERVER as utreexod_rpc

import time

SLEEP_TIME = 10


class CliConnectTest(FlorestaTestFramework):
    nodes = [-1, -1]

    def set_test_params(self):
        to_connect = f"{utreexod_rpc['host']}:{utreexod_rpc['ports']['server']}"
        CliConnectTest.nodes[0] = self.add_node(
            variant="florestad",
            rpcserver=florestad_rpc,
            extra_args=[
                f"--connect={to_connect}",
            ],
        )

        CliConnectTest.nodes[1] = self.add_node(
            variant="utreexod",
            rpcserver=utreexod_rpc,
        )

    def run_test(self):
        # Start the nodes
        self.log("=== Starting nodes")
        self.run_node(CliConnectTest.nodes[0])
        self.run_node(CliConnectTest.nodes[1])

        time.sleep(SLEEP_TIME)  # Give some time for the nodes to start

        # Check whether the utreexod is connected to florestad
        self.log("=== Checking connection")
        utreexod: UtreexoRPC = self.get_node(CliConnectTest.nodes[1]).rpc
        res = utreexod.get_peerinfo()
        self.assertEqual(len(res), 1)

        # Stop the nodes
        self.log("=== Stopping nodes")
        self.stop()


if __name__ == "__main__":
    CliConnectTest().main()
