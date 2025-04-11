"""
tests/test_framework/electrum/base.py

base client to connect to Floresta's electrum server
"""

import json
import socket
from datetime import datetime, timezone
from typing import Any, List, Tuple


# pylint: disable=too-few-public-methods
class BaseClient:
    """
    A little class to help connect to Floresta's electrum server
    """

    def __init__(self, host, port=8080):
        self._conn = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

    @property
    def conn(self) -> socket.socket:
        """
        Return the socket connection
        """
        return self._conn

    @conn.setter
    def conn(self, value: socket.socket):
        """
        Set the socket connection
        """
        self._conn = value

    def log(self, msg):
        """
        Log a message to the console
        """
        print(f"[{self.__class__.__name__.upper()} {datetime.now(timezone.utc)}] {msg}")

    def request(self, method, params) -> str:
        """
        Request something to Floresta server
        """
        request = json.dumps(
            {"jsonrpc": "2.0", "id": 0, "method": method, "params": params}
        )

        mnt_point = "/".join(method.split("."))
        self.log(f"GET electrum://{mnt_point}?params={params}")
        self.conn.sendall(request.encode("utf-8") + b"\n")

        response = b""
        while True:
            chunk = self.conn.recv(1)
            if not chunk:
                break
            response += chunk
            if b"\n" in response:
                break
        response = response.decode("utf-8").strip()
        self.log(response)
        return response

    def batch_request(self, calls: List[Tuple[str, List[Any]]]) -> str:
        """
        Send batch JSON-RPC requests to electrum's server.
        """
        request_map = {
            i: {"jsonrpc": "2.0", "id": i, "method": method, "params": params}
            for i, (method, params) in enumerate(calls)
        }

        request_list = list(request_map.values())
        self.log(
            "BATCH "
            + ", ".join(
                f"electrum://{'/'.join(m.split('.'))}?params={p}" for m, p in calls
            )
        )
        self.conn.sendall(json.dumps(request_list).encode("utf-8") + b"\n")

        response = b""
        while True:
            chunk = self.conn.recv(1)
            if not chunk:
                break
            response += chunk
            if b"\n" in response:
                break

        response = response.decode("utf-8").strip()
        self.log(response)
        return response
