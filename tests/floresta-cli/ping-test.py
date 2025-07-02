"""
A test that creates a florestad and a bitcoind node, and connects them. We then
send a ping to bitcoind and check if bitcoind receives it, by calling
`getpeerinfo` and checking that we've received a ping from floresta.
"""

import time
from test_framework import FlorestaTestFramework


class PingTest(FlorestaTestFramework):
    nodes = [-1, -1]
    expected_chain = "regtest"

    def set_test_params(self):
        PingTest.nodes[0] = self.add_node(variant="florestad")
        PingTest.nodes[1] = self.add_node(variant="bitcoind")

    def run_test(self):
        # Start the nodes
        self.run_node(PingTest.nodes[0])
        self.run_node(PingTest.nodes[1])

        bitcoind = self.get_node(PingTest.nodes[1])
        florestad = self.get_node(PingTest.nodes[0])

        # Connect floresta to bitcoind
        host = bitcoind.get_host()
        port = bitcoind.get_port("p2p")
        florestad.rpc.addnode(f"{host}:{port}", "onetry")

        time.sleep(1)

        # Check that we have a connection, but no ping yet
        peer_info = bitcoind.rpc.get_peerinfo()
        self.assertTrue(
            "ping" not in peer_info[0]["bytesrecv_per_msg"],
        )

        # Send a ping to bitcoind
        self.log("Sending ping to bitcoind...")
        florestad.rpc.ping()

        # Check that bitcoind received the ping
        peer_info = bitcoind.rpc.get_peerinfo()
        self.assertTrue(peer_info[0]["bytesrecv_per_msg"]["ping"])

        self.stop()


if __name__ == "__main__":
    PingTest().main()
