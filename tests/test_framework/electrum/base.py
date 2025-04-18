"""
tests/test_framework/electrum/base.py

base client to connect to Floresta's electrum server
"""

import json
import socket
from datetime import datetime


# pylint: disable=too-few-public-methods
class BaseClient:
    """
    A little class to help connect to Floresta
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
        print(f"{self.__class__.__name__.upper()} {datetime.utcnow()} {msg}")

    def request(self, method, params):
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
