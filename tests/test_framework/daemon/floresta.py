"""
test_framework.daemon.floresta.py

A test framework for testing florestad daemon in regtest mode.
"""

from typing import List

from test_framework.daemon.base import BaseDaemon


class FlorestaDaemon(BaseDaemon):
    """
    Spawn a new Florestad process on background and run it on
    regtest mode for tests.
    """

    def create(self, target: str):
        """
        Create a new instance of Florestad.
        Args:
            target: The path to the executable.
        """
        self.name = "florestad"
        self.target = target

    def valid_daemon_args(self) -> List[str]:
        return [
            "-c",
            "--config-file",
            "-d",
            "--debug",
            "--log-to-file",
            "--data-dir",
            "--no-cfilters",
            "-p",
            "--proxy",
            "--wallet-xpub",
            "--wallet-descriptor",
            "--assume-valid",
            "-z",
            "--zmq-address",
            "--connect",
            "--rpc-address",
            "--electrum-address",
            "--filters-start-height",
            "--assume-utreexo",
            "--pid-file",
            "--enable-electrum-tls",
            "--electrum-address-tls",
            "--generate-cert",
            "--tls-cert-path",
            "--tls-key-path",
        ]
