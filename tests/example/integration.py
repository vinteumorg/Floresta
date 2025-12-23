import pytest

from conftest import TEST_CHAIN


@pytest.mark.example
def test_integration(florestad_node, utreexod_node, bitcoind_node):
    floresta_response = florestad_node.rpc.get_blockchain_info()
    utreexo_response = utreexod_node.rpc.get_blockchain_info()
    bitcoin_response = bitcoind_node.rpc.get_blockchain_info()

    assert floresta_response["chain"] == TEST_CHAIN
    assert utreexo_response["chain"] == TEST_CHAIN
    assert bitcoin_response["chain"] == TEST_CHAIN
