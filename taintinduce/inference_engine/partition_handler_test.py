"""Tests for superset detection and output bit reference filtering.

Tests the logic that determines which output bits should be included as references
when processing flows with superset input relationships.
"""

from taintinduce.rules.conditions import OutputBitRef
from taintinduce.types import BitPosition

from .partition_handler import exclude_input_bits_covered_by_output_refs, find_output_bit_refs_from_subsets


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


class TestExcludeInputBitsCoveredByOutputRefs:
    """Tests for exclude_input_bits_covered_by_output_refs function."""

    def test_no_output_refs_returns_all_bits(self) -> None:
        """When no output refs provided, all input bits should be returned."""
        relevant_input_bits = frozenset([BitPosition(0), BitPosition(1), BitPosition(2)])
        output_bit_refs = None
        completed_flows: dict[frozenset[BitPosition], set[BitPosition]] = {}

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        assert result == relevant_input_bits

    def test_excludes_bits_from_subset_flow(self) -> None:
        """Test that input bits from single subset flow are NOT excluded.

        Scenario:
        - Relevant input bits: {0, 1, 2}
        - Output bit ref: 10 (generated by input bits {0, 1})
        - Expected: ALL bits remain (bits {0, 1} only appear in 1 flow, need count >= 2)
        """
        relevant_input_bits = frozenset([BitPosition(0), BitPosition(1), BitPosition(2)])
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        completed_flows = {
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(10)},
        }

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # All bits should remain (no bit appears in 2+ flows)
        assert result == relevant_input_bits

    def test_excludes_multiple_subset_flows(self) -> None:
        """Test with multiple output bit refs but no overlapping input bits.

        Scenario:
        - Relevant input bits: {0, 1, 2, 3, 4}
        - Output bit ref 10: generated by {0, 1}
        - Output bit ref 11: generated by {2, 3}
        - Expected: ALL bits remain (each bit appears in only 1 flow)
        """
        relevant_input_bits = frozenset(
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3), BitPosition(4)],
        )
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10)), OutputBitRef(BitPosition(11))])
        completed_flows = {
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(10)},
            frozenset([BitPosition(2), BitPosition(3)]): {BitPosition(11)},
        }

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # All bits should remain (no bit appears in 2+ flows)
        assert result == relevant_input_bits

    def test_overlapping_subset_flows(self) -> None:
        """Test exclusion when subset flows overlap - only multiply-covered bits excluded.

        Scenario:
        - Relevant input bits: {0, 1, 2}
        - Output bit ref 10: generated by {0, 1}
        - Output bit ref 11: generated by {1, 2}
        - Bit 0: appears in 1 flow -> keep
        - Bit 1: appears in 2 flows -> EXCLUDE
        - Bit 2: appears in 1 flow -> keep
        - Expected: only bit {1} excluded, bits {0, 2} remain
        """
        relevant_input_bits = frozenset([BitPosition(0), BitPosition(1), BitPosition(2)])
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10)), OutputBitRef(BitPosition(11))])
        completed_flows = {
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(10)},
            frozenset([BitPosition(1), BitPosition(2)]): {BitPosition(11)},
        }

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # Only bit 1 should be excluded (appears in 2 flows)
        assert result == frozenset([BitPosition(0), BitPosition(2)])
        assert BitPosition(1) not in result

    def test_output_ref_not_in_completed_flows(self) -> None:
        """Test when output bit ref doesn't match any completed flow.

        This is a safety case - shouldn't happen in practice but should handle gracefully.
        """
        relevant_input_bits = frozenset([BitPosition(0), BitPosition(1)])
        output_bit_refs = frozenset([OutputBitRef(BitPosition(99))])  # Non-existent
        completed_flows = {
            frozenset([BitPosition(0)]): {BitPosition(10)},
        }

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # No exclusion should occur
        assert result == relevant_input_bits

    def test_realistic_add_scenario(self) -> None:
        """Test realistic ADD scenario with carry propagation.

        ADD eax, ebx where we're processing output bit 30:
        - Relevant input bits: {0-30 from eax, 0-30 from ebx} = 62 bits
        - Output bit refs from subsets:
          - Bit 0: from inputs {eax[0], ebx[0]}
          - Bit 1: from inputs {eax[0-1], ebx[0-1]}
          - ...
          - Bit 29: from inputs {eax[0-29], ebx[0-29]}

        Occurrence count for each bit:
        - eax[0], ebx[0]: appear in flows 0-29 (30 times) -> EXCLUDE
        - eax[1], ebx[1]: appear in flows 1-29 (29 times) -> EXCLUDE
        - ...
        - eax[28], ebx[28]: appear in flows 28-29 (2 times) -> EXCLUDE
        - eax[29], ebx[29]: appear in flow 29 only (1 time) -> KEEP
        - eax[30], ebx[30]: appear in no subset flows (0 times) -> KEEP

        Expected: Only eax[29], ebx[29], eax[30], ebx[30] remain
        """
        # Simplified: eax bits 0-30, ebx bits 32-62 (offset by 32)
        relevant_input_bits = frozenset(
            [BitPosition(i) for i in range(31)] + [BitPosition(i) for i in range(32, 63)],  # eax[0-30]  # ebx[0-30]
        )

        # Output bit refs from bits 0-29 (64 output bits starting at 64)
        output_bit_refs = frozenset([OutputBitRef(BitPosition(64 + i)) for i in range(30)])

        # Each output bit i is generated by eax[0-i] and ebx[0-i]
        completed_flows = {}
        for i in range(30):
            input_bits = frozenset(
                [BitPosition(j) for j in range(i + 1)]
                + [BitPosition(32 + j) for j in range(i + 1)],  # eax[0-i]  # ebx[0-i]
            )
            completed_flows[input_bits] = {BitPosition(64 + i)}

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # eax[29], ebx[29], eax[30], ebx[30] should remain
        expected = frozenset([BitPosition(29), BitPosition(61), BitPosition(30), BitPosition(62)])
        assert result == expected

    def test_empty_output_refs_set(self) -> None:
        """Test with empty output_bit_refs frozenset."""
        relevant_input_bits = frozenset([BitPosition(0), BitPosition(1)])
        output_bit_refs: frozenset[OutputBitRef] = frozenset()  # Empty but not None
        completed_flows = {
            frozenset([BitPosition(0)]): {BitPosition(10)},
        }

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # Should return all bits since output_refs is empty
        assert result == relevant_input_bits

    def test_partial_coverage(self) -> None:
        """Test when only some input bits are covered by output refs (but only once each).

        Scenario:
        - Relevant input bits: {0, 1, 2, 3}
        - Output bit ref: 10 (generated by {0, 1})
        - Bits {2, 3} are not covered by any output ref
        - Bits {0, 1} appear in only 1 flow
        - Expected: ALL bits remain (no bit appears in 2+ flows)
        """
        relevant_input_bits = frozenset(
            [BitPosition(0), BitPosition(1), BitPosition(2), BitPosition(3)],
        )
        output_bit_refs = frozenset([OutputBitRef(BitPosition(10))])
        completed_flows = {
            frozenset([BitPosition(0), BitPosition(1)]): {BitPosition(10)},
        }

        result = exclude_input_bits_covered_by_output_refs(
            relevant_input_bits,
            output_bit_refs,
            completed_flows,
        )

        # All bits should remain
        assert result == relevant_input_bits
