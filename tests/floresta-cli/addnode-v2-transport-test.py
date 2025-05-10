"""
addnode-v2-transport-test.py

This functional test cli utility to interact with a Floresta
node with `addnode` that should be Both compliant with the Bitcoin-core
(see more at https://bitcoincore.org/en/doc/29.0.0/rpc/network/addnode/)
in context of the v2 transport protocol.
"""

import os

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


class AddnodeTestV2Transport(FlorestaTestFramework):
    """
    Test `addnode` rpc call, by creating two nodes (in its IDB state),
    where the first one should connect with the second one by calling
    `addnode ip[:port]` through a v2 transport protocol.
    """

    nodes = [-1, -1]

    # The port 50002 do not have any TLS meaning here,
    # it's just another port for another node
    electrum_addrs = ["0.0.0.0:50001", "0.0.0.0:50002"]
    rpc_addrs = ["0.0.0.0:18442", "0.0.0.0:18443"]

    # The transport protocol used in the test (v1)
    v2transport = False

    data_dirs = [
        os.path.normpath(
            os.path.join(
                FlorestaTestFramework.get_integration_test_dir(),
                "data",
                "floresta-cli-addnode-v2-transport",
                "node-0",
            )
        ),
        os.path.normpath(
            os.path.join(
                FlorestaTestFramework.get_integration_test_dir(),
                "data",
                "floresta-cli-addnode-v2-transport",
                "node-1",
            )
        ),
    ]

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        AddnodeTestV2Transport.nodes[0] = self.add_node(
            extra_args=[
                f"--data-dir={AddnodeTestV2Transport.data_dirs[0]}",
                f"--electrum-address={AddnodeTestV2Transport.electrum_addrs[0]}",
                f"--rpc-address={AddnodeTestV2Transport.rpc_addrs[0]}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
            ssl=False,
        )

        AddnodeTestV2Transport.nodes[1] = self.add_node(
            extra_args=[
                f"--data-dir={AddnodeTestV2Transport.data_dirs[1]}",
                f"--electrum-address={AddnodeTestV2Transport.electrum_addrs[1]}",
                f"--rpc-address={AddnodeTestV2Transport.rpc_addrs[1]}",
            ],
            rpcserver={
                "host": "127.0.0.1",
                "ports": {"rpc": 18443, "server": 50002},
                "jsonrpc": "2.0",
                "timeout": 10000,
            },
            ssl=False,
        )

    def start_both_nodes(self):
        """
        Start both nodes, by calling `run_node` for each node
        and returning the nodes
        """
        for i in AddnodeTestV2Transport.nodes:
            self.run_node(AddnodeTestV2Transport.nodes[i])

        return [self.get_node(i) for i in AddnodeTestV2Transport.nodes]

    def test_should_add_each_other_to_peers_list(self, nodes):
        """
        The test follows:

        - Call `addnode <second node> false` in the first node;
        - Call `addnode <first node> false` in the second node;

        In both cases, the `getpeerinfo` will be the tool used to check
        if the nodes are connected and added. That should return a list with one
        peer that have, among other things:

        - the address of the other node;
        - the initial height of 0,
        - the transport protocol of "V2"
        - the kind of "regular";
        - the services of "ServiceFlags(NONE)";
        - oneshot of false.
        """
        peer_addresses = [AddnodeTestV2Transport.rpc_addrs[1 - i] for i in range(2)]
        for i in range(2):
            result = nodes[i].rpc.addnode(
                node=peer_addresses[i],
                command="add",
                v2transport=True,
            )

            # `addnode` bitcoin-core compliant command
            # should return a null json object
            self.assertIsNone(result)

            # Check if the added node was added to the peers list
            # with the `getpeerinfo` command
            peer_info = nodes[i].rpc.get_peerinfo()
            self.assertEqual(len(peer_info), 1)
            self.assertEqual(peer_info[0]["address"], peer_addresses[i])
            self.assertEqual(peer_info[0]["initial_height"], 0)
            self.assertEqual(peer_info[0]["kind"], "regular")
            self.assertEqual(peer_info[0]["services"], "ServiceFlags(NONE)")
            self.assertEqual(peer_info[0]["state"], "Awaiting")
            self.assertEqual(peer_info[0]["transport_protocol"], "V2")
            self.assertEqual(peer_info[0]["user_agent"], "")
            self.assertEqual(peer_info[0]["oneshot"], False)

    def test_should_not_add_each_other_to_peers_list(self, nodes):
        """
        The test follows:

        - Call `addnode <second node> false` in the first node;
        - Call `addnode <first node> false` in the second node;

        In both cases, the `getpeerinfo` will be the tool used to check
        if the nodes are still connected and added. In other words
        the list shouldn't be changed from previous test.
        """
        peer_addresses = [AddnodeTestV2Transport.rpc_addrs[1 - i] for i in range(2)]
        for i in range(2):
            result = nodes[i].rpc.addnode(
                node=peer_addresses[i], command="add", v2transport=True
            )

            # `addnode` bitcoin-core compliant command
            # should return a null json object
            self.assertIsNone(result)

            # Check if the list of peers is the same from
            # the previous test, meaning that the
            # `addnode` command was not able to add the node
            peer_info = nodes[i].rpc.get_peerinfo()
            self.assertEqual(len(peer_info), 1)

    def test_should_remove_each_other_from_peers_list(self, nodes):
        """
        The test follows:

        - Call `addnode <second node> remove false` in the first node;
        - Call `addnode <first node> remove false` in the second node;

        In both cases, the `getpeerinfo` command should return a list
        with zero peers.
        """
        peer_addresses = [AddnodeTestV2Transport.rpc_addrs[1 - i] for i in range(2)]
        for i in range(2):
            result = nodes[i].rpc.addnode(node=peer_addresses[i], command="remove")

            # `addnode` bitcoin-core compliant command
            # should return a null json object
            self.assertIsNone(result)

            # Check if the list of peers is empty and the
            # `addnode <peer> remove` command was able to remove the node.
            peer_info = nodes[i].rpc.get_peerinfo()
            self.assertEqual(len(peer_info), 0)

    def test_should_onetry_connection(self, nodes):
        """
        The test follows:

        - Call `addnode <second node> onetry false` in the first node;
        - Call `addnode <first node> onetry false` in the second node;

        In both cases, the `getpeerinfo` will be the tool used to check
        if the nodes are connected. That should return a list with one
        peer that have, among other things:

        - the address of the other node;
        - the initial height of 0,
        - the transport protocol of "V2" if the v2transport is true, or "V1";
        - the kind of "regular";
        - the services of "ServiceFlags(NONE)";
        - oneshot of true.
        """
        peer_addresses = [AddnodeTestV2Transport.rpc_addrs[1 - i] for i in range(2)]
        for i in range(2):
            result = nodes[i].rpc.addnode(
                node=peer_addresses[i], command="onetry", v2transport=True
            )

            # `addnode` bitcoin-core compliant command
            # should return a null json object
            self.assertIsNone(result)

            # Check if the list of peers is the same from
            # the previous test, meaning that the
            # `addnode` command was not able to add the node
            peer_info = nodes[i].rpc.get_peerinfo()
            self.assertEqual(len(peer_info), 1)
            self.assertEqual(peer_info[0]["address"], peer_addresses[i])
            self.assertEqual(peer_info[0]["initial_height"], 0)
            self.assertEqual(peer_info[0]["kind"], "regular")
            self.assertEqual(peer_info[0]["services"], "ServiceFlags(NONE)")
            self.assertEqual(peer_info[0]["state"], "Awaiting")
            self.assertEqual(peer_info[0]["transport_protocol"], "V2")
            self.assertEqual(peer_info[0]["user_agent"], "")
            self.assertEqual(peer_info[0]["oneshot"], True)

    def test_should_not_remove_each_other_from_peers_list(self, nodes):
        """
        The test follows:

        - Call `addnode <second node> remove false` in the first node;
        - Call `addnode <first node> remove false` in the second node;

        In both cases, the `getpeerinfo` command should return a list
        with one peer.
        """
        peer_addresses = [AddnodeTestV2Transport.rpc_addrs[1 - i] for i in range(2)]
        for i in range(2):
            result = nodes[i].rpc.addnode(node=peer_addresses[i], command="remove")

            # `addnode` bitcoin-core compliant command
            # should return a null json object
            self.assertIsNone(result)

            # Check if the list of peers is empty and the
            # `addnode <peer> remove` command was able to remove the node.
            peer_info = nodes[i].rpc.get_peerinfo()
            self.assertEqual(len(peer_info), 1)

    def run_test(self):
        """
        This main test run a set of tests for the addnode command:

        1. Test `addnode` command with v2 transport in both nodes, and add them
        each other, then remove each other, then onetry each other;

        2. Check if the previous onetry command didnt added each other to
        the list;
        """
        nodes = self.start_both_nodes()

        # test addnode command with v1 transport
        self.test_should_add_each_other_to_peers_list(nodes)
        self.test_should_not_add_each_other_to_peers_list(nodes)
        self.test_should_remove_each_other_from_peers_list(nodes)
        self.test_should_onetry_connection(nodes)

        # make a second call with one try
        # and check if the list didnt changed
        self.test_should_onetry_connection(nodes)

        # Check if the previous onetry command didnt added the node
        # to the list of connected peers. The remove command should
        # be false
        self.test_should_not_remove_each_other_from_peers_list(nodes)

        # stop both nodes
        self.stop()


if __name__ == "__main__":
    AddnodeTestV2Transport().main()
