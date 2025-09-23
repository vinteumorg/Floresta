import pytest
from conftest import (
    EXPECTED_HEIGHT,
    EXPECTED_BLOCK,
    EXPECTED_DIFFICULTY_INT,
    EXPECTED_LEAF_COUNT,
)


class TestFunctional:
    @pytest.mark.integration
    def test_florestad_blockchain_info(self, florestad_node):
        inf_response = florestad_node.rpc.get_blockchain_info()
        assert inf_response["height"] == EXPECTED_HEIGHT
        assert inf_response["best_block"] == EXPECTED_BLOCK
        assert inf_response["difficulty"] == EXPECTED_DIFFICULTY_INT
        assert inf_response["leaf_count"] == EXPECTED_LEAF_COUNT
