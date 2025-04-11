"""
tests/test_framework/rpc/base.py

Define a base class for making RPC calls to a
`test_framework.daemon.floresta.BaseDaemon`.
"""

import json
import socket
import time
from datetime import datetime
from subprocess import Popen
from typing import Any, Dict, List

from requests import post
from requests.exceptions import HTTPError
from requests.models import HTTPBasicAuth
from test_framework.rpc.exceptions import JSONRPCError


class BaseRpcMetaClass(type):
    """
    Metaclass for BaseDaemon.

    Ensures that any attempt to register a subclass of `BaseDaemon` will
    adheres to a standard whereby the subclass DOES NOT override either
    `__init__`, `log`, `perform_request`, `is_connection_open`,
    `wait_for_connection`, `wait_for_connections`, `get_blockchain_info`
    and `stop`.

    If any of those standards are violated, a ``TypeError`` is raised.
    """

    # pylint: disable=too-many-boolean-expressions
    def __new__(mcs, clsname, bases, dct):
        if not clsname == "BaseRPC":

            if (
                "__init__" in dct
                and "log" in dct
                and "perform_request" in dct
                and "is_connection_open" in dct
                and "wait_for_connection" in dct
                and "wait_for_connections" in dct
                and "get_blockchain_info" in dct
                and "stop" in dct
            ):
                raise TypeError(
                    "BaseRPC subclasses must not override '__init__', 'log',"
                    + "'perform_request', 'is_connection_open', "
                    + "'wait_for_connection', 'wait_for_connections', "
                    + "'get_blockchain_info' and 'stop'"
                )

        return super().__new__(mcs, clsname, bases, dct)


# pylint: disable=too-few-public-methods
class RPCServerConfig:
    """
    A class for storing the RPC server configuration.
    """

    def __init__(self, **kwargs):
        self.host = kwargs.get("host", "127.0.0.1")
        self.ports = kwargs.get("ports", {})
        self.user = kwargs.get("user", None)
        self.password = kwargs.get("password", None)
        self.jsonrpc_version = kwargs.get("jsonrpc", "1.0")
        self.timeout = kwargs.get("timeout", 10000)


class BaseRPC(metaclass=BaseRpcMetaClass):
    """
    A class for making RPC calls to a `test_framework.daemon.floresta.BaseDaemon`.

    The instantiation of a superclass of `BaseRPC` will create a new
    RPC connection to the daemon process. The RPC connection is
    established using the `requests` library, using the method
    `perform_request`.

    Every desired RPC call would be implemented using that method. Although
    two of them cannot be implemented using `perform_request`: `get_blockchain_info`
    and `stop`. Those two methods are implemented in this class.

    For example:

    ```python
    class MyRPC(BaseRPC):
        def get_blockhash(self, height: int) -> dict:
            self.perform_request("getblockhash", [height])

        def get_blockheader(self, blockhash: str) -> dict:
            self.perform_request("getblockheader", [blockhash])

        def get_stuff(self, stuff: str) -> dict:
            self.perform_request("getstuff", [stuff])
    ```

    mydaemon = MyDaemon()
    mydaemon.add_daemon_settings(["--mydaemon-arg=value"])
    mydaemon.start()

    MY_RPC_SERVER = {
        "host": "127.0.0.1",
        "ports": {"rpc": 18442, "server": 50001},
        "jsonrpc": "2.0",
        "timeout": 10000,
    }

    myrpc = MyRPC(mydaemon.process, MY_RPC_SERVER)
    myrpc.get_blockhash(0)
    myrpc.get_blockheader("0000000000000000000c6f8e4a2b3d5f7c5e4f4f4f4f4f4f4f4f4f4f4f4f4f")
    myrpc.get_stuff("stuff")
    """

    def __init__(self, process: Popen[str], rpcserver: Dict[str, str | Dict[str, str]]):
        self._rpcserver = RPCServerConfig(**rpcserver)
        self._process = process
        self._rpcconn = None
        self._is_running = False

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
    def rpcserver(self) -> RPCServerConfig:
        """Getter for `rpcsserver` property"""
        return self._rpcserver

    @rpcserver.setter
    def rpcserver(self, value: RPCServerConfig):
        """Setter for `rpcserver` property"""
        self._rpcserver = value

    def log(self, message: str):
        """Log a message to the console"""
        print(f"[{self.__class__.__name__.upper()} {datetime.utcnow()}] {message}")

    # pylint: disable=unused-argument,dangerous-default-value
    def perform_request(
        self,
        method: str,
        params: List[int | str | float | Dict[str, str | Dict[str, str]]] = [],
    ) -> Any:
        """
        Perform a JSON-RPC request to the RPC server given the method
        and params. The params should be a list of arguments to the
        method. The method should be a string with the name of the
        method to be called.

        The method will return the result of the request or raise
        a JSONRPCError if the request failed.
        """
        # Create basic information for the requests
        # inside the `kwargs` dictionary
        # - url
        # - headers
        # - data (payload)
        # - timeout
        host = getattr(self.rpcserver, "host")
        ports = getattr(self.rpcserver, "ports")
        rpc_port = ports["rpc"]
        user = getattr(self.rpcserver, "user")
        password = getattr(self.rpcserver, "password")
        jsonrpc_version = getattr(self.rpcserver, "jsonrpc_version")
        timeout = getattr(self.rpcserver, "timeout")
        kwargs = {
            "url": f"http://{host}:{rpc_port}/",
            "headers": {"content-type": "application/json"},
            "data": json.dumps(
                {
                    "jsonrpc": jsonrpc_version,
                    "id": "0",
                    "method": method,
                    "params": params,
                }
            ),
            "timeout": timeout,
        }

        # Check if the RPC server has a username and password
        # and set the auth accordingly to HTTPBasicAuth.
        logmsg = "GET "
        if user is not None and password is not None:
            logmsg += f"<{user}:{password}>@"
            kwargs["auth"] = HTTPBasicAuth(user, password)

        # Now make the POST request to the RPC server
        logmsg += f"{kwargs['url']}{method}?params={params}"
        response = post(**kwargs)

        # wait a little to avoid overloading the daemon.
        # maybe it not overload, but it is a good practice
        # time.sleep(0.3)

        # If response isnt 200, raise an HTTPError
        if response.status_code != 200:
            raise HTTPError

        result = response.json()

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

        self.log(logmsg)
        self.log(result["result"])
        return result["result"]

    def is_connection_open(self, host: str, port: int) -> bool:
        """Returns True if a TCP port is open (connection succeeded)."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            connected = sock.connect_ex((host, port))
            return connected == 0

    def wait_for_connection(
        self, host: str, port: int, opened: bool, timeout: int = 10
    ):
        """
        Wait for the RPC connection to reach the desired state.
        If the connection does not reach the desired state in time,
        raise a TimeoutError.
        """
        start = time.time()
        while time.time() - start < timeout:
            if self.is_connection_open(host, port) == opened:
                state = "open" if opened else "closed"
                self.log(f"{host}:{port} {state}")
                return
            time.sleep(0.5)

        state = "open" if opened else "closed"
        raise TimeoutError(f"{host}:{port} not {state} after {timeout} seconds")

    def wait_for_connections(self, opened: bool = True):
        """Wait for all port connections in the host reach the desired state."""
        host = getattr(self.rpcserver, "host")
        for _, port in getattr(self.rpcserver, "ports").items():
            self.wait_for_connection(host, port, opened)
