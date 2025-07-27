"""
A test that creates a florestad and a bitcoind node, and connects them. We then
send a ping to bitcoind and check if bitcoind receives it, by calling
`getpeerinfo` and checking that we've received a ping from floresta.
"""

import time
from test_framework import FlorestaTestFramework


class PingTest(FlorestaTestFramework):
    expected_chain = "regtest"

    def set_test_params(self):
        self.florestad = self.add_node(variant="florestad")
        self.bitcoind = self.add_node(variant="bitcoind")

    def run_test(self):
        # Start the nodes
        self.run_node(self.florestad)
        self.run_node(self.bitcoind)

        # Connect floresta to bitcoind
        host = self.bitcoind.get_host()
        port = self.bitcoind.get_port("p2p")
        self.florestad.rpc.addnode(f"{host}:{port}", "onetry")

        time.sleep(1)

        # Check that we have a connection, but no ping yet
        peer_info = self.bitcoind.rpc.get_peerinfo()
        self.assertTrue(
            "ping" not in peer_info[0]["bytesrecv_per_msg"],
        )

        # Send a ping to bitcoind
        self.log("Sending ping to bitcoind...")
        self.florestad.rpc.ping()

        # Check that bitcoind received the ping
        peer_info = self.bitcoind.rpc.get_peerinfo()
        self.assertTrue(peer_info[0]["bytesrecv_per_msg"]["ping"])

        self.stop()


if __name__ == "__main__":
    PingTest().main()
