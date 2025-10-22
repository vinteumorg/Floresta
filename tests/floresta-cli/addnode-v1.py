"""
addnode-test.py

This functional test cli utility to interact with a Floresta
node with `addnode` that should be both compliant with the Bitcoin-core
in context of the v1 transport protocol.

(see more at https://bitcoincore.org/en/doc/29.0.0/rpc/network/addnode/)
"""

import re
import time

from test_framework import FlorestaTestFramework

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()
TIMEOUT = 15
PING_TIMEOUT = 40


class AddnodeTestV1(FlorestaTestFramework):
    nodes = [-1, -1]

    def set_test_params(self):
        """
        Setup the two nodes (florestad and bitcoind)
        in the same regtest network.
        """
        name = self.__class__.__name__.lower()
        self.v2transport = False
        self.data_dirs = AddnodeTestV1.create_data_dirs(DATA_DIR, name, 2)

        self.florestad = self.add_node(
            variant="florestad",
            extra_args=[f"--data-dir={self.data_dirs[0]}"],
        )

        self.bitcoind = self.add_node(
            variant="bitcoind",
            extra_args=[
                f"-datadir={self.data_dirs[1]}",
                f"-v2transport={1 if self.v2transport else 0}",
            ],
        )

    def start_both_nodes(self):
        """
        Start both nodes, by calling `run_node` for each node
        and returning the nodes with `get_node` method.
        """
        self.run_node(self.florestad)
        self.run_node(self.bitcoind)

    def test_should_floresta_add_bitcoind(self):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> add false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
          with the bitcoind peer in Ready state.
        """
        self.log("=========== Testing should_floresta_add_bitcoind...")

        # Floresta adds the bitcoind node
        bitcoind_port = self.bitcoind.get_port("p2p")

        # call the rpc
        result = self.florestad.rpc.addnode(
            node=f"127.0.0.1:{bitcoind_port}",
            command="add",
            v2transport=self.v2transport,
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        self.assertIsNone(result)

        # give some time to the node to establish the connection
        time.sleep(1)

        # Floresta should be able to connect almost immediately
        # to the utreexod node after adding it.
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 1)

        # now we expect the node to be in Ready state
        # with some expressive information. The node
        # should be in the `getpeerinfo` list.
        self.assertEqual(peer_info[0]["address"], f"127.0.0.1:{bitcoind_port}")
        self.assertEqual(peer_info[0]["initial_height"], 0)
        self.assertEqual(peer_info[0]["kind"], "regular")

        self.assertEqual(
            peer_info[0]["services"],
            "ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED)",
        )
        self.assertEqual(peer_info[0]["transport_protocol"], "V1")

        self.assertEqual(peer_info[0]["state"], "Ready")
        self.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"\/Satoshi:\d*\.\d*\.\d*\/"),
        )

    def test_should_bitcoind_see_floresta(self):
        """
        The test follows:

        - Call `getpeerinfo` on bitcoind. That should return a list
        with the floresta peer.
        """
        # now see how bitcoind see floresta
        self.log("=========== Testing should bitcoind_see_floresta...")

        # call the rpc
        bitcoind_host = self.bitcoind.get_host()
        bitcoind_port = self.bitcoind.get_port("p2p")
        peer_info = self.bitcoind.rpc.get_peerinfo()

        # Now we expect see the floresta node
        self.assertEqual(len(peer_info), 1)
        self.assertEqual(peer_info[0]["addrbind"], f"{bitcoind_host}:{bitcoind_port}")
        self.assertEqual(peer_info[0]["startingheight"], 0)
        self.assertEqual(peer_info[0]["services"], "0000000001000009")

        pattern = re.compile(
            r"^/Floresta/"
            r"\d+\.\d+\.\d+"
            r"(?:-\d+-g[a-f0-9]+)?"
            r"(?:-dirty)?"
            r"/?$"
        )

        self.assertMatch(peer_info[0]["subver"], pattern)
        self.assertEqual(peer_info[0]["inbound"], True)

    def test_should_bitcoind_disconnect(self):
        """
        The test follows:

        - call `stop` on bitcoind;
        - call `getpeerinfo` on floresta. That should return an empty list
        """
        self.log(
            "=========== Testing should bitcoind disconnect and floresta not see anymore..."
        )

        # lets try to disconnect the node
        # and wait for disconnection to proceed
        # with the test
        self.bitcoind.stop()
        self.florestad.rpc.ping()
        time.sleep(PING_TIMEOUT)

        # now we expect the node to be in the
        # awaiting state. It will be in that state
        # until the node reconnects again
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 0)

    def test_should_florestad_reconnect(self):
        """
        The test follows:
        - call `run_node` on bitcoind;
        - call `getpeerinfo` on floresta. That should return a list
        with the bitcoind peer in Ready state;
        """
        self.log(
            "=========== Testing should bitcoind restart and floresta await for it be ready..."
        )
        # reconnect the bitcoind node
        self.run_node(self.bitcoind)

        # wait for the bitcoind node to be ready
        self.bitcoind.rpc.wait_for_connections(opened=True, timeout=PING_TIMEOUT)
        time.sleep(PING_TIMEOUT)

        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 1)
        self.assertEqual(peer_info[0]["state"], "Ready")

    def test_should_floresta_not_add_bitcoind_again(self):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should the same
        list as before, meaning that the bitcoind peer was not added again.
        """
        self.log("=========== Testing should floresta not add bitcoind again...")
        result = self.florestad.rpc.addnode(
            node="127.0.0.1:18444", command="add", v2transport=self.v2transport
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        self.assertIsNone(result)

        # Check if the list of peers is the same from
        # the previous test, meaning that the
        # `addnode` command was not able to add the node
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 1)

    def test_should_floresta_remove_bitcoind(self):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> remove false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
        with zero peers.
        """
        self.log("=========== Testing should floresta remove bitcoind...")

        # get host and port
        bitcoind_port = self.bitcoind.get_port("p2p")
        result = self.florestad.rpc.addnode(
            node=f"127.0.0.1:{bitcoind_port}",
            command="remove",
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        self.assertIsNone(result)

        # For now the node will be in ready state
        # and will be available in `get_peerinfo`
        # The `addnode remove` just remove the
        # node from the added_peers list but it will
        # still be in the peers list.
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 1)
        self.assertEqual(peer_info[0]["state"], "Ready")

        # to check if removed, let's stop the bitcoind
        # restart it and check the `getpeerinfo` again
        self.bitcoind.stop()

        self.run_node(self.bitcoind)
        self.florestad.rpc.ping()

        # wait some time to guarantee
        # that it will not be in the peers list again
        time.sleep(PING_TIMEOUT)

        # now we expect the node to be in the
        # awaiting state. It will be in that state
        # until the node reconnects again
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 0)

    def test_should_bitcoind_not_see_floresta(self):
        """
        The test follows:
        - Call `getpeerinfo` on bitcoind. That should return a list
        with zero peers.
        """
        self.log("=========== Testing should bitcoind not see floresta...")
        peer_info = self.bitcoind.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 0)

    def test_should_floresta_onetry_connection_with_bitcoind(self):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> onetry false` in the floresta node;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
        with the bitcoind peer in Ready state;
        """
        self.log(
            "=========== Testing should floresta onetry connection with bitcoind..."
        )

        # get the bitcoind port
        bitcoind_port = self.bitcoind.get_port("p2p")
        result = self.florestad.rpc.addnode(
            node=f"127.0.0.1:{bitcoind_port}",
            command="onetry",
            v2transport=self.v2transport,
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        self.assertIsNone(result)

        # add some time to establish the handshake
        time.sleep(TIMEOUT)

        # Check if the added node was added
        # to the peers list with the `getpeerinfo` command
        # but should be in the "Awaiting" state
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 1)
        self.assertEqual(peer_info[0]["address"], f"127.0.0.1:{bitcoind_port}")
        self.assertEqual(peer_info[0]["initial_height"], 0)
        self.assertEqual(peer_info[0]["kind"], "regular")

        self.assertEqual(
            peer_info[0]["services"],
            "ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED)",
        )
        self.assertEqual(peer_info[0]["transport_protocol"], "V1")

        self.assertEqual(peer_info[0]["state"], "Ready")
        self.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"\/Satoshi:\d*\.\d*\.\d*\/"),
        )

        # now we need to force a disconnection by shutdown bitcoind
        # and see if, when bitcoind restart, it will not be reconnected
        self.bitcoind.stop()
        self.run_node(self.bitcoind)

        # wait some time to guarantee
        # that it will not be in the peers list again
        self.florestad.rpc.ping()
        time.sleep(PING_TIMEOUT)

        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertEqual(len(peer_info), 0)

    def run_test(self):
        """
        First initialize both nodes. Then run above tests
        in the following order:

        - should floresta add bitcoind;
        - should bitcoind see floresta;
        - should floresta not add bitcoind again;
        - should floresta remove bitcoind;
        - should bitcoind not see floresta;
        - should floresta onetry connection with bitcoind;
        - should floresta remove onetry connection with bitcoind;
        """
        self.start_both_nodes()
        self.test_should_floresta_add_bitcoind()
        self.test_should_bitcoind_see_floresta()
        self.test_should_bitcoind_disconnect()
        self.test_should_florestad_reconnect()
        self.test_should_floresta_not_add_bitcoind_again()
        self.test_should_floresta_remove_bitcoind()
        self.test_should_bitcoind_not_see_floresta()
        self.test_should_floresta_onetry_connection_with_bitcoind()
        self.stop()


if __name__ == "__main__":
    AddnodeTestV1().main()
