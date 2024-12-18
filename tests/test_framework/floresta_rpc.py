""" 
floresta_rpc.py

A test framework for testing JsonRPC calls to a floresta node.

| Method              | Floresta JsonRPC calls  | Comment                            |
| ------------------- | ----------------------- | ---------------------------------- |
| get_blockchain_info | `getblockchaininfo`     | -                                  |
"""

# commented unused modules since maybe they can be useful
# import os
# import shutil
# import tempfile
# import logging
# import traceback
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


class FlorestaRPC:
    """
    A class for making RPC calls to a floresta node.
    """

    # Avoid R0913: Too many arguments by defining
    # a dictionary structure for RPC server
    #
    # Avoid W0102: Dangerous default value as argument
    # See more at https://www.valentinog.com/blog/tirl-python-default-arguments/
    def __init__(
        self, process: Popen, extra_args: list[str], rpcserver: dict[str, str]
    ):
        """
        Initialize a FlorestaRPC object

        Args:
            process: usually, a `cargo run --features json-rpc  --bin florestad` subprocess
            extra_args: TODO: unimplemented on this class
            rpcserver: rpc server to be called, generally a regtest (see REGTEST_RPC_SERVER)
        """

        # Avoid R0902: Too many instance attributes
        self.extra_args = extra_args
        self.rpcserver = rpcserver
        self.process = process

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

    @rpcconn.deleter
    def rpcconn(self):
        """Deleter for `rpcconn` property"""
        self._rpcconn = None

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
                time.sleep(0.1)
                timeout -= 0.1
                if timeout <= 0:
                    raise TimeoutError("Timeout due to a failing connection") from exc
                continue

    def kill(self):
        """
        Kill the floresta node process.
        """
        self.process.kill()

    def wait_to_stop(self):
        """
        Wait for the floresta node process to stop.
        """
        self.process.wait()

    def perform_request(self, method, params=None) -> dict:
        """
        Perform an JsonRPC request to the floresta node.
        """
        host = self.rpcserver["host"]
        port = self.rpcserver["port"]
        url = f"http://{host}:{port}"
        headers = {"content-type": "application/json"}
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
        return response.json()["result"]

    def get_blockchain_info(self) -> dict:
        """
        Get the blockchain info by performing `perform_request('getblockchaininfo')`
        """
        return self.perform_request("getblockchaininfo")
