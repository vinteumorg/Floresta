"""
A test that creates a florestad and a bitcoind node, and connects them. We then
send a ping to bitcoind and check if bitcoind receives it, by calling
`getpeerinfo` and checking that we've received a ping from floresta.
"""

from test_framework import FlorestaRPC, BitcoinRPC, FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as florestad_rpc
from test_framework.rpc.bitcoin import REGTEST_RPC_SERVER as bitcoind_rpc

import time


class PingTest(FlorestaTestFramework):
    index = [-1, -1]
    expected_chain = "regtest"

    def set_test_params(self):
        PingTest.index[0] = self.add_node(variant="florestad", rpcserver=florestad_rpc)
        PingTest.index[1] = self.add_node(variant="bitcoind", rpcserver=bitcoind_rpc)

    def run_test(self):
        # Start the nodes
        self.run_node(PingTest.index[0])
        self.run_node(PingTest.index[1])

        bitcoind: BitcoinRPC = self.get_node(PingTest.index[1]).rpc
        florestad: FlorestaRPC = self.get_node(PingTest.index[0]).rpc

        # Connect floresta to bitcoind
        florestad.addnode(
            f"{bitcoind_rpc['host']}:{bitcoind_rpc['ports']['p2p']}", "onetry"
        )

        time.sleep(1)

        # Check that we have a connection, but no ping yet
        peer_info = bitcoind.get_peerinfo()
        self.assertTrue(
            "ping" not in peer_info[0]["bytesrecv_per_msg"],
        )

        # Send a ping to bitcoind
        self.log("Sending ping to bitcoind...")
        florestad.ping()

        # Check that bitcoind received the ping
        peer_info = bitcoind.get_peerinfo()
        self.assertTrue(peer_info[0]["bytesrecv_per_msg"]["ping"])

        self.stop()


if __name__ == "__main__":
    PingTest().main()
