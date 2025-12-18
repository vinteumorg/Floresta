import pytest

from conftest import TEST_CHAIN, GENESIS_BLOCK_BLOCK, GENESIS_BLOCK_DIFFICULTY_INT


@pytest.mark.example
def test_utreexod(utreexod_node):
    response = utreexod_node.rpc.get_blockchain_info()

    assert response["chain"] == TEST_CHAIN
    assert response["bestblockhash"] == GENESIS_BLOCK_BLOCK
    assert response["difficulty"] == GENESIS_BLOCK_DIFFICULTY_INT
