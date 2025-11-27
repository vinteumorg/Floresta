import pytest
from conftest import EXPECTED_CHAIN, EXPECTED_BLOCK, EXPECTED_DIFFICULTY_FLOAT


class TestBitcoind:
    @pytest.mark.bitcoind
    def test_bitcoind_blockchain_info(self, bitcoind_node):
        response = bitcoind_node.rpc.get_blockchain_info()
        assert response["chain"] == EXPECTED_CHAIN
        assert response["bestblockhash"] == EXPECTED_BLOCK
        assert response["difficulty"] == EXPECTED_DIFFICULTY_FLOAT
