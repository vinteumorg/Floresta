"""
floresta_rpc.py

A test framework for testing JsonRPC calls to a floresta node.
"""

import re

from test_framework.rpc.base import BaseRPC

REGTEST_RPC_SERVER = {
    "host": "127.0.0.1",
    "ports": {"rpc": 18442, "electrum-server": 50001},
    "jsonrpc": "2.0",
    "timeout": 10000,
}

REGTEST_RPC_TLS_SERVER = {
    "host": "127.0.0.1",
    "ports": {"rpc": 18442, "electrum-server": 50001, "electrum-server-tls": 50002},
    "jsonrpc": "2.0",
    "timeout": 10000,
}


class FlorestaRPC(BaseRPC):
    """
    A class for making RPC calls to a floresta node.
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

    def get_blockhash(self, height: int) -> dict:
        """
        Get the blockhash associated with a given height performing
        `perform_request('getblockhash', params=[<int>])`
        """
        return self.perform_request("getblockhash", [height])

    def get_blockheader(self, blockhash: str) -> dict:
        """
        Get the header of a block, giving its hash performing
        `perform_request('getblockheader', params=[<str>])`
        """
        if not bool(re.fullmatch(r"^[a-f0-9]{64}$", blockhash)):
            raise ValueError(f"Invalid blockhash '{blockhash}'.")

        return self.perform_request("getblockheader", params=[blockhash])

    def get_block(self, blockhash: str, verbosity: int = 1):
        """
        Get a full block, given its hash performing
        `perform_request('getblock', params=[str, int])`

        Notice that this rpc will cause a actual network request to our node,
        so it may be slow, and if used too often, may cause more network usage.
        The returns for this rpc are identical to bitcoin core's getblock rpc
        as of version 27.0.

        the `str` param should be a valid 32 bytes hex formated string
        the `int` param should be a integer verbosity level
        """
        if len(blockhash) != 64:
            raise ValueError(f"invalid blockhash param: {blockhash}")

        if verbosity not in (0, 1):
            raise ValueError(f"Invalid verbosity level param: {verbosity}")

        return self.perform_request("getblock", params=[blockhash, verbosity])

    def get_peerinfo(self):
        """
        Get the outpoint associated with a given tx and vout performing
        `perform_request('gettxout', params=[str, int])`
        """
        return self.perform_request("getpeerinfo")

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

    def get_roots(self):
        """
        Returns the roots of our current floresta state performing
        `perform_request('getroots')`
        """
        return self.perform_request("getroots")

    def get_memoryinfo(self, mode: str):
        """
        Returns stats about our memory usage performing
        `perform_request('getmemoryinfo', params=[str])`
        """
        if mode not in ("stats", "mallocinfo"):
            raise ValueError(f"Invalid getmemoryinfo mode: '{mode}'")

        return self.perform_request("getmemoryinfo", params=[mode])

    def get_rpcinfo(self):
        """
        Returns stats about our RPC server performing
        `perform_request('getrpcinfo')`
        """
        return self.perform_request("getrpcinfo")

    def uptime(self):
        """
        Returns for how long florestad has been running, in seconds, performing
        `perform_request('uptime')`
        """
        return self.perform_request("uptime")
