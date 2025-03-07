""" 
floresta_rpc.py

A test framework for testing JsonRPC calls to a floresta node.

The list below describe the python method and the related JSONRPC call:

- get_blockchain_info: `getblochaininfo`;
- get_blockhash: `getblockhash <height>`;
- get_block: `getblock <blockhash>`;
- get_peer_info: `getpeerinfo`; 
- get_stop: `stop`;
- get_addnode `addnode <ip:port>`;
- get_roots: `getroots`;
"""

# commented unused modules since maybe they can be useful
# import os
# import shutil
# import tempfile
# import logging
# import traceback
import re
import time
import json
from subprocess import Popen
from requests import post, exceptions

REGTEST_RPC_SERVER = {
    "host": "127.0.0.1",
    "port": 18442,
    "user": "user",
    "password": "password",
}


class JSONRPCError(Exception):
    """A custom exception for JSONRPC calls"""

    def __init__(self, rpc_id: str, code: str, data: str, message: str):
        """Initialize with message, the error code and the caller id"""
        super().__init__(message)
        self.message = message
        self.rpc_id = rpc_id
        self.code = code
        self.data = data

    def __repr__(self):
        """Format the exception repr"""
        return f"{self.message} for request id={self.rpc_id} (data={self.data})"

    def __str__(self):
        """Format the exception str(<exception>)"""
        return self.__repr__()


class FlorestaRPC:
    """
    A class for making RPC calls to a floresta node.
    """

    # Avoid R0913: Too many arguments by defining
    # a dictionary structure for RPC server
    #
    # Avoid W0102: Dangerous default value as argument
    # See more at https://www.valentinog.com/blog/tirl-python-default-arguments/
    def __init__(self, process: Popen[str], rpcserver: dict[str, str]):
        """
        Initialize a FlorestaRPC object

        Args:
            process: usually, a `cargo run --features json-rpc  --bin florestad` subprocess
            rpcserver: rpc server to be called, generally a regtest (see REGTEST_RPC_SERVER)
        """

        # Avoid R0902: Too many instance attributes
        self._rpcserver = rpcserver

        # Guard clause to ensure it's never None
        if process is None:
            raise ValueError("The 'process' argument cannot be None.")

        self._process = process

    # Define `rpcconn` in a more pythonic way
    # since linter warns for security calls like `rpcconn = None`
    # Defining them with decorators stop it
    @property
    def rpcconn(self):
        """Getter for `rpcconn` property"""
        return self._rpcconn

    @rpcconn.setter
    def rpcconn(self, value: dict):
        """Setter for `rpcconn` property"""
        self._rpcconn = value

    @property
    def process(self) -> Popen[str] | None:
        """Getter for `process` property"""
        return self._process

    @process.setter
    def process(self, value: Popen[str]):
        """Setter for `process` property"""
        self._process = value

    @property
    def rpcserver(self) -> dict[str, str]:
        """Getter for `rpcsserver` property"""
        return self._rpcserver

    @rpcserver.setter
    def rpcserver(self, value: dict[str, str]):
        """Setter for `rpcsserver` property"""
        if "host" not in value:
            raise ValueError("rpcserver should have 'host' property")

        if "port" not in value:
            raise ValueError("rpcserver should have 'port' property")

        self._rpcserver = value

    def wait_for_rpc_connection(self):
        """
        Wait for the RPC connection to be established. This will define
        the `rpcconn` as a dictionary derived from a response performed
        by `perform_request('get')`

        Raises:
            TimeoutError: if a timeout occurs
                          if there are 10 consecutive failed attempts
        """
        timeout = 10
        while True:
            try:
                self.rpcconn = self.get_blockchain_info()
                break

            except exceptions.Timeout as exc:
                raise TimeoutError("Timeout waiting for RPC connection") from exc

            except exceptions.ConnectionError as exc:
                time.sleep(0.5)
                timeout -= 0.1
                if timeout <= 0:
                    raise TimeoutError("Timeout due to a failing connection") from exc
                continue

    def kill(self):
        """
        Kill the floresta node process.
        """
        if self.process is not None:
            self.process.kill()
        else:
            raise RuntimeError("Cannot kill a null process")

    def wait_to_stop(self):
        """
        Wait for the floresta node process to stop.
        """
        if self.process is not None:
            self.process.wait()
        else:
            raise RuntimeError("Cannot wait for null process")

    def perform_request(self, method, params=None) -> dict:
        """
        Perform an JsonRPC request to the floresta node.
        """
        host = self.rpcserver["host"]
        port = self.rpcserver["port"]
        url = f"http://{host}:{port}"
        headers = {"content-type": "application/json"}

        if params is None:
            params = []

        payload = json.dumps(
            {
                "method": method,
                "params": params,
                "jsonrpc": "2.0",
                "id": "0",
            }
        )
        timeout = 10000

        # Provide some timeout to request
        # to avoid W3101: Missing timeout argument for method 'requests.post'
        # can cause your program to hang indefinitely (missing-timeout)
        response = post(url, data=payload, headers=headers, timeout=timeout)
        result = response.json()

        # Log the result, so if anything go wrong
        # (see https://github.com/vinteumorg/Floresta/pull/329)
        # it will be possible to inspect
        print(result)

        # Error could be None or a str
        # If in the future this change,
        # cast the resulted error to str
        if "error" in result and result["error"] is not None:
            raise JSONRPCError(
                rpc_id=result["id"],
                code=result["error"]["code"],
                data=result["error"]["data"],
                message=result["error"]["message"],
            )

        return result["result"]

    def get_blockchain_info(self) -> dict:
        """
        Get the blockchain info by performing `perform_request('getblockchaininfo')`
        """
        return self.perform_request("getblockchaininfo")

    def get_blockhash(self, height: int) -> dict:
        """
        Get the blockhash associated with a given height performing
        `perform_request('getblockhash', params=[<int>])`
        """
        return self.perform_request("getblockhash", params=[height])

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

    def stop(self):
        """
        Gracefully stops the node performing
        `perform_request('stop')`
        """
        return self.perform_request("stop")

    def get_addnode(self, node: str):
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
        return self.perform_request("addnode", params=[node])

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
