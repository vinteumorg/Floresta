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
from test_framework.rpc.bitcoin import REGTEST_RPC_SERVER as bitcoind_config

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()
TIMEOUT = 15
PING_TIMEOUT = 40


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
        Setup the two nodes (florestad and bitcoind)
        in the same regtest network.
        """
        test.nodes[0] = test.add_node(
            variant="florestad",
            extra_args=[f"--data-dir={test.data_dirs[0]}"],
            rpcserver=floresta_config,
            ssl=False,
        )

        test.nodes[1] = test.add_node(
            variant="bitcoind",
            extra_args=[
                f"-datadir={test.data_dirs[1]}",
                f"-v2transport={1 if test.v2transport else 0}",
            ],
            rpcserver=bitcoind_config,
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
    def test_should_floresta_add_bitcoind(test, nodes, v2transport=False):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> add false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
          with the bitcoind peer in Ready state.
        """
        test.log("=========== Testing should_floresta_add_bitcoind...")
        # Floresta adds the bitcoind node
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

        if test.v2transport is True:
            test.assertEqual(
                peer_info[0]["services"],
                "ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED|P2P_V2)",
            )
            test.assertEqual(peer_info[0]["transport_protocol"], "V2")
        else:
            # if v2transport is False, we expect all but P2P_V2
            test.assertEqual(
                peer_info[0]["services"],
                "ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED)",
            )
            test.assertEqual(peer_info[0]["transport_protocol"], "V1")

        test.assertEqual(peer_info[0]["state"], "Ready")
        test.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"\/Satoshi:\d*\.\d*\.\d*\/"),
        )

    @staticmethod
    def test_should_bitcoind_see_floresta(test, nodes):
        """
        The test follows:

        - Call `getpeerinfo` on bitcoind. That should return a list
        with the floresta peer.
        """
        # now see how bitcoind see floresta
        test.log("=========== Testing should bitcoind_see_floresta...")
        peer_info = nodes[1].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)
        test.assertEqual(peer_info[0]["addrlocal"], "127.0.0.1:38332")
        test.assertEqual(peer_info[0]["startingheight"], 0)
        test.assertEqual(peer_info[0]["services"], "0000000001000009")
        test.assertMatch(
            peer_info[0]["subver"],
            re.compile(r"\/Floresta:.*\/"),
        )
        test.assertEqual(peer_info[0]["inbound"], True)

    @staticmethod
    def test_should_bitcoind_disconnect(test, nodes):
        """
        The test follows:

        - call `stop` on bitcoind;
        - call `getpeerinfo` on floresta. That should return an empty list
        """
        test.log(
            "=========== Testing should bitcoind disconnect and floresta not see anymore..."
        )
        # lets try to disconnect the node
        # and wait for disconnection to proceed
        # with the test
        test.stop_node(1)
        nodes[0].rpc.ping()

        time.sleep(PING_TIMEOUT)

        # now we expect the node to be in the
        # awaiting state. It will be in that state
        # until the node reconnects again
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def test_should_florestad_reconnect(test, nodes, v2transport=False):
        """
        The test follows:
        - call `run_node` on bitcoind;
        - call `getpeerinfo` on floresta. That should return a list
        with the bitcoind peer in Ready state;
        """
        test.log(
            "=========== Testing should bitcoind restart and floresta await for it be ready..."
        )
        # reconnect the bitcoind node
        test.run_node(1)
        nodes[1].rpc.wait_for_connections(opened=True)
        time.sleep(PING_TIMEOUT)

        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 1)
        test.assertEqual(peer_info[0]["state"], "Ready")

    @staticmethod
    def test_should_floresta_not_add_bitcoind_again(test, nodes, v2transport=False):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should the same
        list as before, meaning that the bitcoind peer was not added again.
        """
        test.log("=========== Testing should floresta not add bitcoind again...")
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
    def test_should_floresta_remove_bitcoind(test, nodes):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> remove false`;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
        with zero peers.
        """
        test.log("=========== Testing should floresta remove bitcoind...")
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

        # to check if removed, let's stop the bitcoind
        # restart it and check the `getpeerinfo` again
        test.stop_node(1)
        nodes[1].rpc.wait_for_connections(opened=False)

        test.run_node(1)
        nodes[0].rpc.ping()

        # wait some time to guarantee
        # that it will not be in the peers list again
        time.sleep(PING_TIMEOUT)

        # now we expect the node to be in the
        # awaiting state. It will be in that state
        # until the node reconnects again
        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def test_should_bitcoind_not_see_floresta(test, nodes):
        """
        The test follows:
        - Call `getpeerinfo` on bitcoind. That should return a list
        with zero peers.
        """
        test.log("=========== Testing should bitcoind not see floresta...")

        peer_info = nodes[1].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def test_should_floresta_onetry_connection_with_bitcoind(
        test, nodes, v2transport=False
    ):
        """
        The test follows:

        - Call `addnode <bitcoind ip:port> onetry false` in the floresta node;
        - the result should be a null json compliant to bitcoin-core;
        - call `getpeerinfo` on floresta. That should return a list
        with the bitcoind peer in Ready state;
        """
        test.log(
            "=========== Testing should floresta onetry connection with bitcoind..."
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

        if test.v2transport is True:
            test.assertEqual(
                peer_info[0]["services"],
                "ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED|P2P_V2)",
            )
            test.assertEqual(peer_info[0]["transport_protocol"], "V2")
        else:
            # if v2transport is False, we expect all but P2P_V2
            test.assertEqual(
                peer_info[0]["services"],
                "ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED)",
            )
            test.assertEqual(peer_info[0]["transport_protocol"], "V1")

        test.assertEqual(peer_info[0]["state"], "Ready")
        test.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"\/Satoshi:\d*\.\d*\.\d*\/"),
        )

        # now we need to force a disconnection by shutdown bitcoind
        # and see if, when bitcoind restart, it will not be reconnected
        test.stop_node(1)
        test.run_node(1)

        # wait some time to guarantee
        # that it will not be in the peers list again
        nodes[0].rpc.ping()
        time.sleep(PING_TIMEOUT)

        peer_info = nodes[0].rpc.get_peerinfo()
        test.assertEqual(len(peer_info), 0)

    @staticmethod
    def run_test(test, nodes):
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
        AddnodeTestWrapper.test_should_floresta_add_bitcoind(
            test, nodes, test.v2transport
        )
        AddnodeTestWrapper.test_should_bitcoind_see_floresta(test, nodes)
        AddnodeTestWrapper.test_should_bitcoind_disconnect(test, nodes)
        AddnodeTestWrapper.test_should_florestad_reconnect(test, nodes)
        AddnodeTestWrapper.test_should_floresta_not_add_bitcoind_again(
            test, nodes, test.v2transport
        )
        AddnodeTestWrapper.test_should_floresta_remove_bitcoind(test, nodes)
        AddnodeTestWrapper.test_should_bitcoind_not_see_floresta(test, nodes)
        AddnodeTestWrapper.test_should_floresta_onetry_connection_with_bitcoind(
            test, nodes, test.v2transport
        )
        test.stop()


if __name__ == "__main__":
    run_test("addnode_v1_transport", v2transport=False)
    run_test("addnode_v2_transport", v2transport=True)
