import pytest
from conftest import EXPECTED_CHAIN, EXPECTED_BLOCK, EXPECTED_DIFFICULTY_INT


class TestUtreexod:
    @pytest.mark.utreexod
    def test_utreexod_blockchain_info(self, utreexod_node):
        utreexo_response = utreexod_node.rpc.get_blockchain_info()
        assert utreexo_response["chain"] == EXPECTED_CHAIN
        assert utreexo_response["bestblockhash"] == EXPECTED_BLOCK
        assert utreexo_response["difficulty"] == EXPECTED_DIFFICULTY_INT
