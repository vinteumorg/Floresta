import pytest

from test_framework.electrum.client import ElectrumClient


EXPECTED_VERSION = ["Floresta 0.4.0", "1.4"]


@pytest.mark.example
def test_electrum(florestad_node):
    host = florestad_node.get_host()
    port = florestad_node.get_port("electrum-server")
    electrum = ElectrumClient(host, port)

    rpc_response = electrum.get_version()

    assert rpc_response["result"][0] == EXPECTED_VERSION[0]
    assert rpc_response["result"][1] == EXPECTED_VERSION[1]
