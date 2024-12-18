"""
utreexod.py

A test framework for testing RPC calls to utreexod.

| Method          | utreexo RPC calls                 | Comment                            |
| --------------- | --------------------------------- | ---------------------------------- |
| start           | `getblockchaininfo`               | define a TexIOWrapper and Popen    |
| generate_blocks | `getnewaddress`, `generateblocks` | -                                  |
| send_to_address | `sendtoaddress`                   | -                                  |
| get_balance     | `getbalance`                      | -                                  |
| stop            | `stop`                            | delete the TextIOWrapper and Popen |
"""

import time
import os
import shutil
import json
from io import TextIOWrapper
from subprocess import Popen
from requests import post
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError, Timeout


class UtreexoDaemon:
    """
    Spawn a new utreexod process on background and run it on
    regtest mode for tests. You can use it to generate blocks
    and utreexo proofs for tests.
    """

    def __init__(
        self,
        datadir: str,
        utreexod_path: str,
        rpc_port: int = 18334,
        p2p_port: int = 8333,
    ):
        self.datadir = datadir
        self.utreexod_path = utreexod_path
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port

    # Define `utreexod` and `utreexod_log` in a more pythonic way
    # since linter warns for security calls like `utreexod = None`
    # or `utreexod_log = None`. Defining them with decorators stop it
    @property
    def utreexod(self):
        """Getter for `utreexod` property"""
        return self._utreexod

    @utreexod.setter
    def utreexod(self, value: Popen):
        """Setter for `utreexod` property"""
        self._utreexod = value

    @utreexod.deleter
    def utreexod(self):
        """Deleter for `utreexod` property"""
        self._utreexod = None

    @property
    def utreexod_log(self):
        """Getter for `utreexod_log` property"""
        return self._utreexod

    @utreexod_log.setter
    def utreexod_log(self, value: TextIOWrapper):
        """Setter for `utreexod_log` property"""
        self._utreexod = value

    @utreexod_log.deleter
    def utreexod_log(self):
        """Deleter for `utreexod_log` property"""
        self._utreexod = None

    # define a default [] for list argument in python, in our case, 'args', can be dangerous:
    # (W0102: Dangerous default value [] as argument (dangerous-default-value)).
    # See more at https://www.valentinog.com/blog/tirl-python-default-arguments/
    def perform(self, command: str, args: list[int | str | float | dict]) -> dict:
        """
        Perform a RPC command to utreexod and return the result
        """
        url = f"http://localhost:{self.rpc_port}/"
        headers = {"content-type": "application/json"}
        data = {"jsonrpc": "1.0", "id": "curltest", "method": command, "params": args}
        username = "utreexo"
        password = "utreexo"
        auth = HTTPBasicAuth(username, password)
        payload = json.dumps(data)
        timeout = 10000

        # Provide some timeout to request
        # to avoid W3101: Missing timeout argument for method 'requests.post'
        # can cause your program to hang indefinitely (missing-timeout)
        response = post(url, data=payload, headers=headers, auth=auth, timeout=timeout)

        # Instead raise an broader-exception
        # raise a more contextualized exception
        # (this avoid some linter's warns)
        if response.status_code != 200:
            raise HTTPError(
                f"RPC error: {response.status_code} {response.reason} {response.text}"
            )
        return response.json()["result"]

    def start(self):
        """
        Start a new utreexod process on background and wait for it to be ready.

        Raises:
            TimeoutError: if the RPC call `getblockchaininfo` fails wit a request.Timeout
                          if the RPC call `getblockchaininfo` fails 10 times with request.HTTPError
        """
        if not os.path.isdir(self.datadir):
            os.makedirs(self.datadir)

        logfile_path = os.path.join(self.datadir, "utreexod.log")

        # pylint: disable=consider-using-with
        self.utreexod_log = open(logfile_path, "wt", encoding="utf-8")
        self.utreexod = Popen(
            [
                self.utreexod_path,
                "--regtest",
                "--datadir",
                self.datadir,
                "-u",
                "utreexo",
                "-P",
                "utreexo",
                "--utreexoproofindex",
                "--notls",
            ],
            stdout=self.utreexod_log,
            stderr=self.utreexod_log,
        )

        # Wait for utreexod to be ready
        timeout = 10
        while 42:
            try:
                self.perform("getblockchaininfo", [])
                break

            except Timeout as exc:
                raise TimeoutError("utreexod failed to start") from exc

            except HTTPError as exc:
                time.sleep(10)
                timeout -= 1
                if timeout == 0:
                    raise TimeoutError("utreexod failed to start") from exc

    def generate_blocks(self, blocks: int):
        """
        Perform the `getnewaddress` RPC command to utreexod
        """
        addr = self.perform("getnewaddress", [])
        self.perform("generatetoaddress", [blocks, addr])

    def send_to_address(self, address: str, amount: float):
        """
        Perform the `sendtoaddress` RPC command to utreexod
        """
        self.perform("sendtoaddress", [address, amount])

    def get_balance(self):
        """
        Perform the `getbalance` RPC command to utreexod
        """
        return self.perform("getbalance", [])

    def stop(self):
        """
        Perform the `stop` RPC command to utreexod and some cleanup on process and files
        """
        self.perform("stop", [])
        self.utreexod.wait()
        self.utreexod_log.close()
        shutil.rmtree(self.datadir)
        del self.utreexod
        del self.utreexod_log

    def __del__(self):
        """
        Stop utreexod and delete me
        """
        if self.utreexod:
            self.stop()
