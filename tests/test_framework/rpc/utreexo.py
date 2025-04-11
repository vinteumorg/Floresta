"""
tets/test_framework/rpc/utreexo.py

A test framework for testing JsonRPC calls to a utreexo node.
"""

from test_framework.rpc.base import BaseRPC

REGTEST_RPC_SERVER = {
    "host": "127.0.0.1",
    "ports": {"server": 18444, "rpc": 18334},
    "user": "utreexo",
    "password": "utreexo",
    "jsonrpc": "1.0",
    "timeout": 10000,
}


class UtreexoRPC(BaseRPC):
    """
    A class for making RPC calls to a utreexo node.
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

    def get_new_address(self):
        """
        Perform the `getnewaddress` RPC command to utreexod
        """
        return self.perform_request("getnewaddress", [])

    def generate_blocks(self, blocks: int, addr: str = ""):
        """
        Perform the `generatetoaddress` RPC command to utreexod.
        """
        if addr == "" or addr is None:
            raise ValueError("Address is required")

        self.perform_request("generatetoaddress", [blocks, addr])

    def send_to_address(self, address: str, amount: float):
        """
        Perform the `sendtoaddress` RPC command to utreexod
        """
        self.perform_request("sendtoaddress", [address, amount])

    def get_balance(self):
        """
        Perform the `getbalance` RPC command to utreexod
        """
        return self.perform_request("getbalance", [])
