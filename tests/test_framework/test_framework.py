"""
test_framework.py

Adapted from
https://github.com/bitcoin/bitcoin/blob/master/test/functional/test_framework/test_framework.py

BitcoinCore functional tests define a metaclass that checks if some important methods are defined
or not defined.

Floresta functional tests will follow this since it is a good practice for a framework.

The difference is that our node will run withing a `cargo run` subprocess, defined at
`add_node_settings`.
"""

import os
import subprocess
from test_framework.floresta_rpc import FlorestaRPC
from test_framework.crypto.pkcs8 import (
    create_pkcs8_private_key,
    create_pkcs8_self_signed_certificate,
)

VALID_FLORESTAD_EXTRA_ARGS = [
    "-c",
    "--config-file",
    "-d",
    "--debug",
    "--log-to-file",
    "--data-dir",
    "--cfilters",
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
    "--ssl-electrum-address",
    "--ssl-cert-path",
    "--ssl-key-path",
]


class FlorestaTestMetaClass(type):
    """
    Metaclass for FlorestaTestFramework.

    Ensures that any attempt to register a subclass of `FlorestaTestFramework`
    adheres to a standard whereby the subclass override `set_test_params` and
    `run_test but DOES NOT override either `__init__` or `main`.

    If any of those standards are violated, a ``TypeError`` is raised.
    """

    def __new__(mcs, clsname, bases, dct):
        if not clsname == "FlorestaTestFramework":
            if not ("run_test" in dct and "set_test_params" in dct):
                raise TypeError(
                    "FlorestaTestFramework subclasses must override 'run_test'"
                    "and 'set_test_params'"
                )

            if "__init__" in dct or "main" in dct:
                raise TypeError(
                    "FlorestaTestFramework subclasses may not override "
                    "'__init__' or 'main'"
                )

        return super().__new__(mcs, clsname, bases, dct)


class FlorestaTestFramework(metaclass=FlorestaTestMetaClass):
    """
    Base class for a floresta test script.

    Individual floresta test scripts should subclass this class and override the:

    - set_test_params(); and
    - run_test() methods.
    """

    def __init__(self):
        """
        Sets test framework defaults.

        Do not override this method. Instead, override the set_test_params() method
        """
        self._tests = []
        self._nodes = []

    def log(self, msg: str) -> str:
        """Log a message with the class caller"""
        print(f"[{self.__class__.__name__} INFO] {msg}")

    def main(self):
        """
        Main function.

        This should not be overridden by the subclass test scripts.
        """
        self.set_test_params()
        self.run_test()
        self.stop()

    # Should be overrided by individual tests
    def set_test_params(self):
        """
        Tests must override this method to change default values for number of nodes, topology, etc
        """
        raise NotImplementedError

    def run_test(self):
        """
        Tests must override this method to run nodes, etc.
        """
        raise NotImplementedError

    @staticmethod
    def get_integration_test_dir():
        """
        Get path for florestad used in integration tests, generally set on
        $FLORESTA_TEMP_DIR/binaries
        """
        return os.path.normpath(
            os.path.join(os.environ.get("FLORESTA_TEMP_DIR"), "binaries")
        )

    @staticmethod
    def get_target_release_dir():
        """ "
        Get path for built florestad, generally on
        ./target/release/florestad
        """
        dirname = os.path.dirname(__file__)
        return os.path.normpath(os.path.join(dirname, "..", "..", "target", "release"))

    def create_ssl_keys(self) -> tuple[str, str]:
        """
        Create a PKCS#8 formatted private key and a self-signed certificate.
        These keys are intended to be used with florestad's --ssl-key-path and --ssl-cert-path
        options.
        """
        # Check if we're in CI or not
        if "/tmp/floresta-integration-tests" in os.getenv("PATH"):
            ssl_path = os.path.normpath(
                os.path.abspath(
                    os.path.join(self.get_integration_test_dir(), "..", "..", "ssl")
                )
            )
        else:
            home = os.path.expanduser("~")  # Fixed: '~user' -> '~' for current user
            ssl_path = os.path.normpath(
                os.path.abspath(os.path.join(home, ".floresta", "ssl"))
            )

        # Create the folder if not exists
        os.makedirs(ssl_path, exist_ok=True)

        # Create certificates
        pk_path, private_key = create_pkcs8_private_key(ssl_path)
        self.log(f"Created PKCS#8 key at {pk_path}")

        cert_path = create_pkcs8_self_signed_certificate(
            ssl_path, private_key, common_name="florestad", validity_days=365
        )
        self.log(f"Created self-signed certificate at {cert_path}")

        return (pk_path, cert_path)

    # Framework
    def add_node_settings(
        self, chain: str, extra_args: list[str], rpcserver: dict, ssl: bool = False
    ) -> int:
        """
        Add a node settings to be run. Use this on set_test_params method many times you want.

        extra_args should be a list of string in the --key=value strings
        (see florestad --help for a list of available commands)
        """
        # PR #331 introduced a preparatory environment at
        # /tmp/floresta-integration-tests.$(git rev-parse HEAD).
        tmpdir = FlorestaTestFramework.get_integration_test_dir()
        targetdir = FlorestaTestFramework.get_target_release_dir()

        # So, check for it first before define the florestad path.
        if os.path.exists(tmpdir):
            florestad = os.path.normpath(os.path.join(tmpdir, "florestad"))

        # If not exists, define the one at ./target/release.
        elif os.path.exists(targetdir):
            florestad = os.path.normpath(os.path.join(targetdir, "florestad"))

        # In case any test florestad is found, raise an exception
        else:
            raise RuntimeError(
                f"Not found 'florestad' in '{tmpdir}' or '{targetdir}'. "
                "Run 'tests/prepare.sh' or 'cargo build --release'."
            )

        print(f"Using {florestad}")
        setting = {
            "chain": chain,
            "config": [florestad, "--network", chain],
            "rpcserver": rpcserver,
        }

        # If any extra-arg is needed
        # (see ./target/release/florestad --help)
        # append it after --no-ssl arg
        # Not all possible arguments are valid for tests
        # (for example, --version, --help, --ssl ones...)
        if extra_args is not None and len(extra_args) >= 1:
            for extra in extra_args:
                option = extra.split("=")[0] if "=" in extra else extra.split(" ")[0]
                if option in VALID_FLORESTAD_EXTRA_ARGS:
                    setting["config"].append(extra)
                else:
                    raise ValueError(f"Invalid extra_arg '{extra}'")

        # If ssl isnt enabled, add --no-ssl
        # if ssl is enabled, user can add:
        #   --ssl-cert-path
        #   --ssl-key-path
        # Either way, we need to create PKCS#8 key and certificate
        if not ssl:
            setting["config"].append("--no-ssl")
        else:
            (key, cert) = self.create_ssl_keys()
            setting["config"].append("--ssl-key-path")
            setting["config"].append(key)
            setting["config"].append("--ssl-cert-path")
            setting["config"].append(cert)

        self._tests.append(setting)
        return len(self._tests) - 1

    def get_node_settings(self, index: int) -> dict:
        """
        Given an index, return a node configuration
        """
        return self._tests[index]

    def run_node(self, index: int):
        """
        Run a node given an index on self._tests.

        If the node not exists raise a IndexError. At the time
        the tests will only run nodes configured to run on regtest.
        """
        node = self._tests[index]

        if node["chain"] == "regtest":
            # pylint: disable=consider-using-with
            # add text=True to treat all outputs as texts (jsons or python stack traces)
            cmd = " ".join(node["config"])
            self.log(f"Running '{cmd}'")
            process_node = subprocess.Popen(node["config"], text=True)
            json_rpc = FlorestaRPC(process=process_node, rpcserver=node["rpcserver"])
            self._nodes.append(json_rpc)

        else:
            chain = node["chain"]
            raise RuntimeError(f"Uninmplemented test_framework for chain '{chain}'")

    def get_node(self, index: int) -> FlorestaRPC:
        """
        Given an index, return a node configuration
        """
        return self._nodes[index]

    def wait_for_rpc_connection(self, index: int):
        """
        Wait for rpc in a given node index
        """
        node = self._nodes[index]
        node.wait_for_rpc_connection()

    def stop_node(self, index: int):
        """
        Stop a node given an index
        """
        node = self._nodes[index]
        node.kill()
        node.wait_to_stop()

    def stop(self):
        """
        Stop all nodes
        """
        for i in range(len(self._nodes)):
            self.stop_node(i)
