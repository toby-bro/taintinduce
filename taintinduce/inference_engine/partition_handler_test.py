"""Tests for superset detection and output bit reference filtering.

Tests the logic that determines which output bits should be included as references
when processing flows with superset input relationships.
"""

from taintinduce.rules.conditions import OutputBitRef
from taintinduce.types import BitPosition

from .partition_handler import find_output_bit_refs_from_subsets


class TestFindOutputBitRefsFromSubsets:
    """Tests for find_output_bit_refs_from_subsets function."""

    def test_subset_flow_included(self) -> None:
        """Test that output bits from subset flows ARE included.

        Scenario:
        - Current flow: bits [0, 1] -> output bit 1
        - Other flow: bit [0] -> output bit 0
        - Since [0] ⊂ [0, 1], output bit 0 should be included
        """
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows = {
            frozenset([BitPosition(0)]): {BitPosition(0)},  # Subset flow
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is not None
        assert len(result) == 1
        assert OutputBitRef(BitPosition(0)) in result

    def test_superset_flow_excluded(self) -> None:
        """Test that output bits from superset flows are NOT included.

        Scenario:
        - Current flow: bits [0, 1] -> output bit 1
        - ZF flow: bits [0, 1, 2, 3] -> ZF
        - Since [0, 1, 2, 3] ⊃ [0, 1], ZF should NOT be included
        """
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows = {
            # ZF-like flow - requires MORE inputs
            frozenset([BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)]): {
                BitPosition(10),  # ZF at bit 10
            },
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        # Should be None or empty - no valid subsets
        assert result is None or len(result) == 0

    def test_mixed_flows_filters_correctly(self) -> None:
        """Test filtering with both subset and superset flows.

        Scenario:
        - Current flow: bits [0, 1, 2] -> output bit 2
        - Subset flow 1: bit [0] -> output bit 0 ✓ Include
        - Subset flow 2: bits [0, 1] -> output bit 1 ✓ Include
        - Superset flow: bits [0, 1, 2, 3] -> ZF ✗ Exclude
        - Equal flow: bits [0, 1, 2] -> self ✗ Exclude (same inputs)
        """
        current_inputs = frozenset([BitPosition(0), BitPosition(1), BitPosition(2)])
        all_flows = {
            frozenset([BitPosition(0)]): {BitPosition(0)},  # Subset ✓
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(1)},  # Subset ✓
            frozenset([BitPosition(0), BitPosition(1), BitPosition(2)]): {
                BitPosition(2),
            },  # Equal ✗
            frozenset([BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)]): {
                BitPosition(10),
            },  # Superset ✗
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is not None
        assert len(result) == 2
        assert OutputBitRef(BitPosition(0)) in result
        assert OutputBitRef(BitPosition(1)) in result
        # ZF (bit 10) should NOT be included
        assert OutputBitRef(BitPosition(10)) not in result
        # Self (bit 2) should NOT be included
        assert OutputBitRef(BitPosition(2)) not in result

    def test_zf_scenario_realistic(self) -> None:
        """Test realistic ADD scenario with ZF flag.

        ADD eax, ebx scenario:
        - Bit 0: XOR-like, depends on [bit0_eax, bit0_ebx]
        - Bit 1: ADD with carry, depends on [bit0_eax, bit0_ebx, bit1_eax, bit1_ebx]
        - Bit 2: ADD with carry, depends on [bit0-2 of both]
        - ZF: depends on ALL bits [bit0-31 of both]

        When processing bit 2, we should:
        - Include bit 0 output ✓ ([0, 1] ⊂ [0, 1, 2, 3])
        - Include bit 1 output ✓ ([0, 1, 2, 3] ⊂ [0, 1, 2, 3, 4, 5])
        - NOT include ZF ✗ ([0-63] ⊃ [0, 1, 2, 3, 4, 5])
        """
        # Inputs for bit 2 output: eax[0-2] and ebx[0-2] = 6 inputs
        current_inputs = frozenset(
            [
                BitPosition(0),
                BitPosition(1),
                BitPosition(2),  # eax bits
                BitPosition(32),
                BitPosition(33),
                BitPosition(34),  # ebx bits
            ],
        )

        all_flows = {
            # Bit 0: only needs eax[0], ebx[0]
            frozenset([BitPosition(0), BitPosition(32)]): {BitPosition(64)},  # Output bit 0
            # Bit 1: needs eax[0-1], ebx[0-1]
            frozenset(
                [
                    BitPosition(0),
                    BitPosition(1),
                    BitPosition(32),
                    BitPosition(33),
                ],
            ): {
                BitPosition(65),
            },  # Output bit 1
            # ZF: needs ALL bits eax[0-31], ebx[0-31]
            frozenset(
                [BitPosition(i) for i in range(32)] + [BitPosition(32 + i) for i in range(32)],
            ): {
                BitPosition(96),
            },  # ZF output
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is not None
        # Should include bit 0 and bit 1, but NOT ZF
        assert len(result) == 2
        assert OutputBitRef(BitPosition(64)) in result  # Bit 0
        assert OutputBitRef(BitPosition(65)) in result  # Bit 1
        assert OutputBitRef(BitPosition(96)) not in result  # ZF

    def test_empty_flows(self) -> None:
        """Test with no other flows."""
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows: dict[frozenset[BitPosition], set[BitPosition]] = {}

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is None

    def test_no_subset_flows(self) -> None:
        """Test when all other flows are disjoint or supersets."""
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows = {
            # Disjoint
            frozenset([BitPosition(5), BitPosition(6)]): {BitPosition(10)},
            # Superset
            frozenset([BitPosition(0), BitPosition(1), BitPosition(2)]): {BitPosition(11)},
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is None or len(result) == 0

    def test_multiple_outputs_from_single_subset(self) -> None:
        """Test that all output bits from a subset flow are included."""
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows = {
            # Subset flow with multiple outputs
            frozenset([BitPosition(0)]): {BitPosition(10), BitPosition(11), BitPosition(12)},
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is not None
        assert len(result) == 3
        assert OutputBitRef(BitPosition(10)) in result
        assert OutputBitRef(BitPosition(11)) in result
        assert OutputBitRef(BitPosition(12)) in result

    def test_progressive_subset_chain(self) -> None:
        """Test chain of subsets: [0] ⊂ [0,1] ⊂ [0,1,2].

        When processing [0,1,2], should include outputs from both [0] and [0,1].
        """
        current_inputs = frozenset([BitPosition(0), BitPosition(1), BitPosition(2)])
        all_flows = {
            frozenset([BitPosition(0)]): {BitPosition(100)},
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(101)},
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is not None
        assert len(result) == 2
        assert OutputBitRef(BitPosition(100)) in result
        assert OutputBitRef(BitPosition(101)) in result


class TestSubsetLogicEdgeCases:
    """Edge cases for subset detection logic."""

    def test_single_bit_cannot_have_subsets(self) -> None:
        """Single input bit has no proper subsets."""
        current_inputs = frozenset([BitPosition(0)])
        all_flows = {
            frozenset([BitPosition(1)]): {BitPosition(10)},  # Disjoint
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is None

    def test_equal_inputs_excluded(self) -> None:
        """Flows with equal inputs should not be included (not proper subset)."""
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows = {
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(100)},
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        # Equal inputs -> not a proper subset -> should not be included
        assert result is None or BitPosition(100) not in [ref.output_bit for ref in (result or [])]

    def test_overlapping_but_not_subset(self) -> None:
        """Test flows that overlap but neither is a subset.

        [0, 1] and [1, 2] overlap at bit 1, but neither is a subset.
        """
        current_inputs = frozenset([BitPosition(0), BitPosition(1)])
        all_flows = {
            frozenset([BitPosition(1), BitPosition(2)]): {BitPosition(100)},
        }

        result = find_output_bit_refs_from_subsets(current_inputs, all_flows)

        assert result is None or len(result) == 0
