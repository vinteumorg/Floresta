"""
addnode-test.py

This functional test cli utility to interact with a Floresta
node with `addnode` that should be both compliant with the Bitcoin-core
in context of the v1/v2 transport protocol.

(see more at https://bitcoincore.org/en/doc/29.0.0/rpc/network/addnode/)
"""

import os
import re
import time

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as floresta_config
from test_framework.rpc.utreexo import REGTEST_RPC_SERVER as utreexod_config

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()
TIMEOUT = 5


def create_data_dirs(
    base_name: str, nodes: int, v2transport: bool = False
) -> list[str]:
    """
    Create the data directories for the two nodes
    to be used in the test.
    """
    transport = "v2" if v2transport else "v1"
    dir_name = f"{base_name}-{transport}-transport"

    paths = []
    for i in range(nodes):
        p = os.path.join(str(DATA_DIR), "data", dir_name, f"node-{i}")
        os.makedirs(p, exist_ok=True)
        paths.append(p)

    return paths


def run_test(name: str, v2transport: bool = False):

    class _AddnodeTest(FlorestaTestFramework):

        def set_test_params(self):
            self.log(f"**************** Running {name} test")
            self.nodes = [-1, -1]
            self.data_dirs = create_data_dirs(
                self.__class__.__name__, 2, v2transport=v2transport
            )
            self.v2transport = v2transport
            AddnodeTestWrapper.set_test_params(self)

        def run_test(self):
            nodes = AddnodeTestWrapper.start_both_nodes(self)
            AddnodeTestWrapper.run_test(self, nodes)
            for node in nodes:
                node.rpc.wait_for_connections(opened=False)

            self.log(f"**************** Test {name} done!")

    _AddnodeTest().main()


class AddnodeTestWrapper:

    @staticmethod
    def set_test_params(test: FlorestaTestFramework):
        """
        Setup the two nodes (florestad and utreexod)
        in the same regtest network.
        """
        test.nodes[0] = test.add_node(
            variant="florestad",
            extra_args=[f"--data-dir={test.data_dirs[0]}"],
            rpcserver=floresta_config,
            ssl=False,
        )

        # --rpcquirks is used to make the utreexod node
        # to be compliant with the bitcoin-core
        test.nodes[1] = test.add_node(
            variant="utreexod",
            extra_args=[
                "--rpcquirks",
                f"--datadir={test.data_dirs[1]}",
            ],
            rpcserver=utreexod_config,
            ssl=False,
        )

    @staticmethod
    def start_both_nodes(test):
        """
        Start both nodes, by calling `run_node` for each node
        and returning the nodes with `get_node` method.
        """
        for i in test.nodes:
            test.log(f"=========== Starting node {i}...")
            test.run_node(test.nodes[i])

        return [test.get_node(i) for i in test.nodes]

    @staticmethod
    def test_should_floresta_add_utreexod(test, nodes, v2transport=False):
        """
        The test follows:

        - Call `addnode <utreexod ip:port> add false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
          with the utreexod peer in Ready state.
        """
        test.log("=========== Testing should_floresta_add_utreexod...")
        # Floresta adds the utreexod node
        result = nodes[0].rpc.addnode(
            node="127.0.0.1:18444", command="add", v2transport=v2transport
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        test.assertIsNone(result)

        # Floresta should be able to connect almost immediately
        # to the utreexod node after adding it.
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)

        # now we expect the node to be in Ready state
        # with some expressive information. The node
        # should be in the `getpeerinfo` list.
        test.assertEqual(peer_info[0]["address"], "127.0.0.1:18444")
        test.assertEqual(peer_info[0]["initial_height"], 0)
        test.assertEqual(peer_info[0]["kind"], "regular")
        test.assertEqual(
            peer_info[0]["services"], "ServiceFlags(BLOOM|WITNESS|0x1000000)"
        )
        test.assertEqual(peer_info[0]["state"], "Ready")
        test.assertEqual(peer_info[0]["transport_protocol"], "V1")
        test.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"\/btcwire:\d.\d.\d\/utreexod:\d.\d.\d\/"),
        )

    @staticmethod
    def test_should_utreexod_see_floresta(test, nodes):
        """
        The test follows:

        - Call `getpeerinfo` on utreexod. That should return a list
        with the floresta peer.
        """
        # now see how utreexod see floresta
        test.log("=========== Testing should utreexod_see_floresta...")
        peer_info = nodes[1].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)
        test.assertEqual(peer_info[0]["addrlocal"], "127.0.0.1:18444")
        test.assertEqual(peer_info[0]["startingheight"], 0)
        test.assertEqual(peer_info[0]["services"], "16777225")
        test.assertMatch(
            peer_info[0]["subver"],
            re.compile(r"\/Floresta:.*\/"),
        )
        test.assertEqual(peer_info[0]["inbound"], True)

    @staticmethod
    def test_should_utreexod_disconnect(test, nodes):
        """
        The test follows:

        - call `stop` on utreexod;
        - call `getpeerinfo` on floresta. That should return a list
        with the utreexod peer in Awaiting state;
        """
        test.log(
            "=========== Testing should utreexod disconnect and floresta not see anymore..."
        )
        # lets try to disconnect the node
        # and wait for disconnection to proceed
        # with the test
        test.stop_node(1)
        time.sleep(TIMEOUT)

        # now we expect the node to be in the
        # awaiting state. It will be in that state
        # until the node reconnects again
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def test_should_utreexod_reconnect(test, nodes):
        """
        The test follows:
        - call `run_node` on utreexod;
        - call `getpeerinfo` on floresta. That should return a list
        with the utreexod peer in Ready state;
        """
        test.log(
            "=========== Testing should utreexod reconnect and floresta await for it be ready..."
        )
        # reconnect the utreexod node
        test.run_node(1)
        nodes[1].rpc.wait_for_connections(opened=True)
        time.sleep(TIMEOUT)

        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)
        test.assertEqual(peer_info[0]["state"], "Ready")

    @staticmethod
    def test_should_floresta_not_add_utreexod_again(test, nodes, v2transport=False):
        """
        The test follows:

        - Call `addnode <utreexod ip:port> false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should the same
        list as before, meaning that the utreexod peer was not added again.
        """
        test.log("=========== Testing should floresta not add utreexod again...")
        result = nodes[0].rpc.addnode(
            node="127.0.0.1:18444", command="add", v2transport=v2transport
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        test.assertIsNone(result)

        # Check if the list of peers is the same from
        # the previous test, meaning that the
        # `addnode` command was not able to add the node
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)

    @staticmethod
    def test_should_floresta_remove_utreexod(test, nodes):
        """
        The test follows:

        - Call `addnode <utreexod ip:port> remove false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
        with zero peers.
        """
        test.log("=========== Testing should floresta remove utreexod...")
        result = nodes[0].rpc.addnode(
            node="127.0.0.1:18444",
            command="remove",
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        test.assertIsNone(result)

        # For now the node will be in ready state
        # and will be available in `get_peerinfo`
        # The `addnode remove` just remove the
        # node from the added_peers list but it will
        # still be in the peers list.
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)
        test.assertEqual(peer_info[0]["state"], "Ready")

        # to check if removed, let's stop the utreexod
        # restart it and check the `getpeerinfo` again
        test.stop_node(1)
        test.run_node(1)

        # wait some time to guarantee
        # that it will not be in the peers list again
        time.sleep(TIMEOUT)

        # now we expect the node to be in the
        # awaiting state. It will be in that state
        # until the node reconnects again
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def test_should_utreexod_not_see_floresta(test, nodes):
        """
        The test follows:
        - Call `getpeerinfo` on utreexod. That should return a list
        with zero peers.
        """
        test.log("=========== Testing should utreexod not see floresta...")
        peer_info = nodes[1].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def test_should_floresta_onetry_connection_with_utreexod(
        test, nodes, v2transport=False
    ):
        """
        The test follows:

        - Call `addnode <utreexod ip:port> onetry false` in the floresta node;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
        with the utreexod peer in Ready state;
        """
        test.log(
            "=========== Testing should floresta onetry connection with utreexod..."
        )
        result = nodes[0].rpc.addnode(
            node="127.0.0.1:18444", command="onetry", v2transport=v2transport
        )

        # `addnode` bitcoin-core compliant command
        # should return a null json object
        test.assertIsNone(result)

        # add some time to establish the handshake
        time.sleep(TIMEOUT)

        # Check if the added node was added
        # to the peers list with the `getpeerinfo` command
        # but should be in the "Awaiting" state
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)
        test.assertEqual(peer_info[0]["address"], "127.0.0.1:18444")
        test.assertEqual(peer_info[0]["initial_height"], 0)
        test.assertEqual(peer_info[0]["kind"], "regular")
        test.assertEqual(
            peer_info[0]["services"], "ServiceFlags(BLOOM|WITNESS|0x1000000)"
        )
        test.assertEqual(peer_info[0]["state"], "Ready")
        test.assertEqual(peer_info[0]["transport_protocol"], "V1")
        test.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"\/btcwire:\d.\d.\d\/utreexod:\d.\d.\d\/"),
        )

        # now we need to force a disconnection by shutdown utreexod
        # and see if, when utreexod restart, it will not be reconnected
        test.stop_node(1)
        test.run_node(1)

        # wait some time to guarantee
        # that it will not be in the peers list again
        time.sleep(TIMEOUT)

        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def run_test(test, nodes):
        """
        First initialize both nodes. Then run above tests
        in the following order:

        - should floresta add utreexod;
        - should utreexod see floresta;
        - should floresta not add utreexod again;
        - should floresta remove utreexod;
        - should utreexod not see floresta;
        - should floresta onetry connection with utreexod;
        - should floresta remove onetry connection with utreexod;
        """
        AddnodeTestWrapper.test_should_floresta_add_utreexod(
            test, nodes, test.v2transport
        )
        AddnodeTestWrapper.test_should_utreexod_see_floresta(test, nodes)
        AddnodeTestWrapper.test_should_utreexod_disconnect(test, nodes)
        AddnodeTestWrapper.test_should_utreexod_reconnect(test, nodes)
        AddnodeTestWrapper.test_should_floresta_not_add_utreexod_again(
            test, nodes, test.v2transport
        )
        AddnodeTestWrapper.test_should_floresta_remove_utreexod(test, nodes)
        AddnodeTestWrapper.test_should_utreexod_not_see_floresta(test, nodes)
        AddnodeTestWrapper.test_should_floresta_onetry_connection_with_utreexod(
            test, nodes, test.v2transport
        )
        test.stop()


if __name__ == "__main__":
    run_test("addnode_v1_transport", v2transport=False)
    run_test("addnode_v2_transport", v2transport=True)
