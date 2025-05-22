"""
tets/test_framework/daemon/base.py

Define a base class for a daemon process for florestad and utreexod
(or any other future implementation) that can be started in
regtest mode.
"""

import os
from datetime import datetime, timezone
from subprocess import Popen
from typing import List


class BaseDaemonMetaClass(type):
    """
    Metaclass for BaseDaemon.

    Ensures that any attempt to register a subclass of `BaseDaemon`
    will adheres to a standard whereby the subclass override `create`
    and `valid_daemon_args` but DOES NOT override either `__init__`,
    `start` and `add_daemon_settings`.

    If any of those standards are violated, a ``TypeError`` is raised.
    """

    def __new__(mcs, clsname, bases, dct):
        if not clsname == "BaseDaemon":
            if "valid_daemon_args" not in dct or "create" not in dct:
                raise TypeError(
                    "BaseDaemon subclasses must override 'valid_daemon_args'"
                    + " and 'create'"
                )

            if any(
                method in dct for method in ("__init__", "start", "add_daemon_settings")
            ):
                raise TypeError(
                    "BaseDaemon subclasses may not override '__init__',"
                    + "'start' and 'add_daemon_settings'"
                )

        return super().__new__(mcs, clsname, bases, dct)


class BaseDaemon(metaclass=BaseDaemonMetaClass):
    """
    Base class for a daemon process (florestad or utreexod)
    that can be started in regtest mode. The daemon process

    After instantiation, the daemon can be defined with
    `add_daemon_settings` method and then started with `start` method.

    Another thing important to mention is to not kill directly the
    underlying daemon child process defined by your class (something
    that could be done with `process.kill` or `process.wait` methods).

    Every attempt to stop the daemon should be done by the JSONRPC
    method 'stop', so it will be gracefully stopped, by checking all
    opened connections, wait for closing them and the process stop
    itself.

    Reason: the prompt is a parent of the `tests/run_test.py`, that
    is a parent process of the test process, that is a parent of daemon
    processes. If a test fail and the daemon process isnt properly
    stopped, the `tests/run_test.py` and the test itself will be killed,
    but the daemon process will be reparented before the ports beign closed,
    therefore, the ports will remain opened.

    For example:

    ```python
    class MyDaemon(BaseDaemon):

        def create(self, target: str):
            self.name = "mydaemon"
            self.target = target

        def valid_daemon_args(self) -> List[str]:
            return ["--mydaemon-arg", "--another-arg"]

    class MyRPC(BaseRPC):

        def get_blockchain_info(self) -> dict:
            return self.perform_request("getblockchaininfo")

        def stop(self):
            result = self.perform_request("stop")

    # this is how you would
    # define how the daemon
    # will be started
    daemon = MyDaemon()
    daemon.add_daemon_settings(["--mydaemon-arg=value"])

    # start in a child process
    daemon.start()

    # Start the rpc connection
    myrpc = MyRPC(mydaemon.process, MY_RPC_SERVER_CONFIG)
    info = myrpc.get_blockchain_info()

    # Stop the daemon
    # myrpc.stop()
    ```
    """

    def __init__(self):
        self._target = None
        self._name = None
        self._process = None
        self._settings = []

    def log(self, message: str):
        """Log a message to the console"""
        print(f"[{str(self._name).upper()} {datetime.now(timezone.utc)}] {message}")

    @property
    def target(self) -> str:
        """Getter for `target` property"""
        if self._target is None:
            raise ValueError("target is not set")
        return self._target

    @target.setter
    def target(self, value: str):
        """Setter for `target` property"""
        if not os.path.exists(value):
            raise ValueError(f"Target path {value} does not exist")
        self._target = value

    @property
    def name(self) -> str:
        """Getter for `name` property"""
        if self._name is None:
            raise ValueError("name is not set")
        return self._name

    @name.setter
    def name(self, value: str):
        """Setter for `name` property"""
        if value not in ("florestad", "utreexod", "bitcoind"):
            raise ValueError("name should be 'floresta', 'utreexod' or 'bitcoind'")
        self._name = value

    @property
    def process(self) -> Popen:
        """Getter for `process` property"""
        if self._process is None:
            raise ValueError("process is not set")
        return self._process

    @process.setter
    def process(self, value: Popen):
        """Setter for `process` property"""
        self._process = value

    @property
    def settings(self) -> List[str]:
        """Getter for `settings` property"""
        return self._settings

    @settings.setter
    def settings(self, value: List[str]):
        """Setter for `settings` property"""
        self._settings = value

    def start(self):
        """
        Start the daemon process in regtest mode. If any extra-arg is needed,
        append it with add_daemon_settings. Not all possible arguments
        are valid for tests
        """
        daemon = os.path.normpath(os.path.join(self.target, self.name))
        if not os.path.exists(daemon):
            raise ValueError(f"Daemon path {daemon} does not exist")

        cmd = [daemon]

        # verify which daemon is running and add the correct settings
        if self.name == "utreexod":
            cmd.extend(
                [
                    "--regtest",
                    "--rpcuser=utreexo",
                    "--rpcpass=utreexo",
                    "--utreexoproofindex",
                ]
            )

        elif self.name == "florestad":
            cmd.extend(["--network=regtest"])

        elif self.name == "bitcoind":
            cmd.extend(
                [
                    "-chain=regtest",
                    "-rpcuser=bitcoin",
                    "-rpcpassword=bitcoin",
                ]
            )

        if len(self._settings) >= 1:
            cmd.extend(self._settings)

        # pylint: disable=consider-using-with
        self.process = Popen(cmd, text=True)
        self.log(f"Starting node '{self.name}': {' '.join(cmd)}")

    def add_daemon_settings(self, settings: List[str]):
        """
        Add node settings to the list of settings.

        settings are the CLI arguments to be passed to the node and
        are based on the `valid_deamon_args` method.

        Not all possible arguments are valid for tests
        (for example, "--version" or "--help" are not valid).
        """

        if len(settings) >= 1:
            for extra in settings:
                option = extra.split("=") if "=" in extra else extra.split(" ")
                if option[0] in self.valid_daemon_args():
                    self.settings.append(extra)
                else:
                    raise ValueError(f"Invalid extra_arg '{option}'")

    # pylint: disable=unused-argument
    def create(self, target: str):
        """
        Create a new instance of the daemon.
        Every subclass must implement this method.

        Args:
            target: The path to the folder where the executable exists
        """
        raise NotImplementedError

    # pylint: disable=unused-argument
    def valid_daemon_args(self) -> List[str]:
        """
        valid_daemon_args are CLI arguments to be passed
        to the node.
        """
        raise NotImplementedError
