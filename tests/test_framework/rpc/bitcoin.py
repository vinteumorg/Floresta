"""
tests.test_framework.rpc.bitcoin.py

A test framework for testing JsonRPC calls to a bitocoin node.
"""

import re
from test_framework.rpc.base import BaseRPC

REGTEST_RPC_SERVER = {
    "host": "127.0.0.1",
    "ports": {"rpc": 18443, "p2p": 18444},
    "user": "bitcoin",
    "password": "bitcoin",
    "jsonrpc": "2.0",
    "timeout": 10000,
}


class BitcoinRPC(BaseRPC):
    """
    A class for making RPC calls to a bitcoin-core node.
    """

    def get_blockchain_info(self) -> dict:
        """
        Get the blockchain info by performing `perform_request('getblockchaininfo')`
        """
        return self.perform_request("getblockchaininfo")

    def stop(self):
        """
        Perform the `stop` RPC command to utreexod and some cleanup on process and files
        """
        result = self.perform_request("stop")
        self.wait_for_connections(opened=False)
        return result

    def get_peerinfo(self) -> dict:
        """
        Get the peer information by performing `perform_request('getpeerinfo')`
        """
        return self.perform_request("getpeerinfo")

    def ping(self) -> None:
        """
        Perform the `ping` RPC that checks if our peers are alive.
        """
        self.perform_request("ping")

    def get_rpcinfo(self):
        """
        Returns stats about our RPC server performing
        `perform_request('getrpcinfo')`
        """
        return self.perform_request("getrpcinfo")

    def uptime(self) -> int:
        """
        Get the uptime of the node by performing `perform_request('uptime')`
        """
        return self.perform_request("uptime")

    def get_block_count(self) -> int:
        """
        Get block count of the node by performing `perform_request('getblockcount')
        """
        return self.perform_request("getblockcount")

    # pylint: disable=R0801
    def addnode(self, node: str, command: str, v2transport: bool = False):
        """
        Adds a new node to our list of peers performing
        `perform_request('addnode', params=[str])`

        This will make our node try to connect to this peer.

        Args
            node: A network address with the format ip[:port]

        Returns
            success: Whether we successfully added this node to our list of peers
        """
        # matches, IPv4, IPv6 and optional ports from 0 to 65535
        pattern = re.compile(
            r"^("
            r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|"
            r"\[([a-fA-F0-9:]+)\]"
            r")"
            r"(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-9]?[0-9]{1,4}))?$"
        )

        if not pattern.match(node):
            raise ValueError("Invalid ip[:port] format")

        if command not in ("add", "remove", "onetry"):
            raise ValueError(f"Invalid command '{command}'")

        return self.perform_request("addnode", params=[node, command, v2transport])
