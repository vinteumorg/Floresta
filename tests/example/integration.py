import pytest


@pytest.mark.integration
def test_blockchain_info_three_nodes(three_node_setup):
    florestad = three_node_setup["florestad"]
    utreexod = three_node_setup["utreexod"]
    bitcoind = three_node_setup["bitcoind"]

    floresta_response = florestad.rpc.get_blockchain_info()
    utreexo_response = utreexod.rpc.get_blockchain_info()
    bitcoin_response = bitcoind.rpc.get_blockchain_info()

    expected_chain = "regtest"

    assert floresta_response["chain"] == expected_chain
    assert utreexo_response["chain"] == expected_chain
    assert bitcoin_response["chain"] == expected_chain
