"""
tests.test_framework.rpc.bitcoin.py

A test framework for testing JsonRPC calls to a bitocoin node.
"""

from test_framework.rpc.base import BaseRPC

REGTEST_RPC_SERVER = {
    "host": "127.0.0.1",
    "ports": {"rpc": 18443, "p2p": 18444, "p2p_local": 18445},
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
