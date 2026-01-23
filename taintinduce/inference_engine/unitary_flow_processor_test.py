"""Tests for unitary_flow_processor module."""

from taintinduce.types import BitPosition

from .unitary_flow_processor import transpose_condition_bits


class TestTransposeConditionBits:
    """Tests for transpose_condition_bits function."""

    def test_transpose_input_bits_only(self) -> None:
        """Test transposing condition with only input bits."""
        # Simplified coordinates: bits 0, 1, 2
        # Original coordinates: bits 5, 10, 15
        condition_ops = frozenset(
            [
                (0b111, 0b101),  # bits 0,1,2 with values 1,0,1
                (0b011, 0b010),  # bits 0,1 with values 0,1
            ],
        )
        input_positions = frozenset([BitPosition(5), BitPosition(10), BitPosition(15)])

        result = transpose_condition_bits(condition_ops, input_positions, [])

        # Expected: bit 0->5, bit 1->10, bit 2->15
        # (0b111, 0b101) -> mask has bits 5,10,15, value has bits 5,15
        expected = frozenset(
            [
                (1 << 5 | 1 << 10 | 1 << 15, 1 << 5 | 1 << 15),
                (1 << 5 | 1 << 10, 1 << 10),
            ],
        )
        assert result == expected

    def test_transpose_with_output_bits(self) -> None:
        """Test transposing condition with both input and output bits."""
        # Simplified: bits 0,1 are inputs, bits 2,3 are outputs
        # Original input positions: bits 8, 12
        # Output positions: bits 0, 1 (for taint-by-induction)
        condition_ops = frozenset(
            [
                (0b1111, 0b1010),  # All 4 bits: inputs 0,1 and outputs 2,3
                (0b0011, 0b0001),  # Only inputs 0,1
                (0b1100, 0b0100),  # Only outputs 2,3
            ],
        )
        input_positions = frozenset([BitPosition(8), BitPosition(12)])
        output_positions = [BitPosition(0), BitPosition(1)]

        result = transpose_condition_bits(condition_ops, input_positions, output_positions)

        # Expected:
        # - Input bit 0 -> position 8
        # - Input bit 1 -> position 12
        # - Output bit 2 -> stays at position 2 (simplified space)
        # - Output bit 3 -> stays at position 3 (simplified space)
        expected = frozenset(
            [
                # (0b1111, 0b1010): bits 8,12,2,3 with values at 12,3
                (1 << 8 | 1 << 12 | 1 << 2 | 1 << 3, 1 << 12 | 1 << 3),
                # (0b0011, 0b0001): bits 8,12 with value at 8
                (1 << 8 | 1 << 12, 1 << 8),
                # (0b1100, 0b0100): bits 2,3 with value at 2
                (1 << 2 | 1 << 3, 1 << 2),
            ],
        )
        assert result == expected

    def test_transpose_empty_condition(self) -> None:
        """Test transposing empty condition."""
        condition_ops: frozenset[tuple[int, int]] = frozenset()
        input_positions = frozenset([BitPosition(0), BitPosition(1)])

        result = transpose_condition_bits(condition_ops, input_positions, [])

        assert result == frozenset()

    def test_transpose_single_input_bit(self) -> None:
        """Test transposing condition with single input bit."""
        # Simplified bit 0 -> original bit 7
        condition_ops = frozenset(
            [
                (0b1, 0b1),  # bit 0 = 1
                (0b1, 0b0),  # bit 0 = 0
            ],
        )
        input_positions = frozenset([BitPosition(7)])

        result = transpose_condition_bits(condition_ops, input_positions, [])

        expected = frozenset(
            [
                (1 << 7, 1 << 7),
                (1 << 7, 0),
            ],
        )
        assert result == expected

    def test_transpose_output_bits_only(self) -> None:
        """Test transposing condition with only output bits (no input bits)."""
        # No input bits, only output bits at positions 0,1 in simplified space
        condition_ops = frozenset(
            [
                (0b11, 0b10),  # Output bits 0,1 with values 0,1
            ],
        )
        input_positions: frozenset[BitPosition] = frozenset()
        output_positions = [BitPosition(5), BitPosition(10)]

        result = transpose_condition_bits(condition_ops, input_positions, output_positions)

        # Output bits stay in simplified space (positions 0,1)
        expected = frozenset(
            [
                (0b11, 0b10),
            ],
        )
        assert result == expected

    def test_transpose_preserves_output_bit_order(self) -> None:
        """Test that output bits maintain their simplified position order."""
        # 2 input bits, 3 output bits
        # Input bits 0,1 -> positions 100, 200
        # Output bits 2,3,4 -> stay at positions 2,3,4
        condition_ops = frozenset(
            [
                (0b11111, 0b10101),  # All 5 bits
            ],
        )
        input_positions = frozenset([BitPosition(100), BitPosition(200)])
        output_positions = [BitPosition(0), BitPosition(1), BitPosition(2)]

        result = transpose_condition_bits(condition_ops, input_positions, output_positions)

        # Input bits map to 100,200; output bits stay at 2,3,4
        expected = frozenset(
            [
                (1 << 100 | 1 << 200 | 1 << 2 | 1 << 3 | 1 << 4, 1 << 100 | 1 << 2 | 1 << 4),
            ],
        )
        assert result == expected


class TestTransposeConditionBitsWithExclusion:
    """Tests for transpose_condition_bits with input bit exclusion optimization."""

    def test_transpose_with_excluded_middle_bits(self) -> None:
        """Test transposition when middle input bits are excluded.

        Scenario: Processing output bit that depends on inputs {0, 1, 2, 3, 4}
        But bits {1, 2} are covered by output_bit_refs, so filtered set is {0, 3, 4}
        Simplified positions: 0, 1, 2 map to original positions 0, 3, 4
        """
        # Condition in simplified space uses bits 0, 1, 2
        # These map to original bits 0, 3, 4 (bits 1, 2 were excluded)
        condition_ops = frozenset(
            [
                (0b111, 0b101),  # bits 0,1,2 with values 1,0,1
                (0b011, 0b010),  # bits 0,1 with values 0,1
            ],
        )
        # After exclusion, only bits 0, 3, 4 remain
        filtered_input_positions = frozenset([BitPosition(0), BitPosition(3), BitPosition(4)])

        result = transpose_condition_bits(condition_ops, filtered_input_positions, [])

        # Expected: simplified bit 0->0, bit 1->3, bit 2->4
        expected = frozenset(
            [
                # (0b111, 0b101): mask bits 0,3,4; values at 0,4
                (1 << 0 | 1 << 3 | 1 << 4, 1 << 0 | 1 << 4),
                # (0b011, 0b010): mask bits 0,3; value at 3
                (1 << 0 | 1 << 3, 1 << 3),
            ],
        )
        assert result == expected

    def test_transpose_with_excluded_lower_bits(self) -> None:
        """Test when lower input bits are excluded.

        Scenario: Original bits {0, 1, 2, 3}, bits {0, 1} excluded
        Filtered set: {2, 3}
        Simplified positions 0, 1 map to original positions 2, 3
        """
        condition_ops = frozenset(
            [
                (0b11, 0b10),  # bits 0,1 with values 0,1
            ],
        )
        # Only bits 2, 3 remain after exclusion
        filtered_input_positions = frozenset([BitPosition(2), BitPosition(3)])

        result = transpose_condition_bits(condition_ops, filtered_input_positions, [])

        # Simplified bit 0->2, bit 1->3
        expected = frozenset(
            [
                (1 << 2 | 1 << 3, 1 << 3),
            ],
        )
        assert result == expected

    def test_transpose_realistic_add_scenario(self) -> None:
        """Test realistic ADD carry propagation scenario with exclusion.

        Processing EAX[30] in ADD EAX, EBX:
        - Original: depends on EAX[0-30], EBX[0-30] = 62 input bits
        - After exclusion: only EAX[30], EBX[30] remain (other bits covered by output refs)
        - Simplified space: bits 0, 1
        - Original space: bits 30 (EAX), 62 (EBX with offset)
        """
        # Condition: both input bits must be 1 for carry propagation
        condition_ops = frozenset(
            [
                (0b11, 0b11),  # Both bits = 1
            ],
        )
        # After exclusion: only bit 30 from EAX and bit 62 from EBX (bit 30 with offset 32)
        filtered_input_positions = frozenset([BitPosition(30), BitPosition(62)])

        result = transpose_condition_bits(condition_ops, filtered_input_positions, [])

        # Simplified bits 0,1 -> original bits 30,62
        expected = frozenset(
            [
                (1 << 30 | 1 << 62, 1 << 30 | 1 << 62),
            ],
        )
        assert result == expected

    def test_transpose_with_exclusion_and_output_bits(self) -> None:
        """Test transposition with both exclusion and output bit refs.

        Scenario:
        - Original inputs: {0, 1, 2, 3, 4}
        - Excluded: {0, 1, 2} (covered by output_bit_refs)
        - Filtered: {3, 4}
        - Simplified space: bits 0,1 are inputs, bits 2,3 are outputs
        """
        # Condition uses simplified bits 0,1 (inputs) and 2,3 (outputs)
        condition_ops = frozenset(
            [
                (0b1111, 0b1010),  # All 4 bits
                (0b0011, 0b0010),  # Only input bits 0,1
                (0b1100, 0b0100),  # Only output bits 2,3
            ],
        )
        # After exclusion: only bits 3, 4 remain
        filtered_input_positions = frozenset([BitPosition(3), BitPosition(4)])
        output_positions = [BitPosition(100), BitPosition(101)]

        result = transpose_condition_bits(
            condition_ops,
            filtered_input_positions,
            output_positions,
        )

        # Simplified input bits 0,1 -> original bits 3,4
        # Output bits 2,3 stay at positions 2,3
        expected = frozenset(
            [
                # (0b1111, 0b1010): bits 3,4,2,3 with values at 4,3
                (1 << 3 | 1 << 4 | 1 << 2 | 1 << 3, 1 << 4 | 1 << 3),
                # (0b0011, 0b0010): bits 3,4 with value at 4
                (1 << 3 | 1 << 4, 1 << 4),
                # (0b1100, 0b0100): bits 2,3 with value at 2
                (1 << 2 | 1 << 3, 1 << 2),
            ],
        )
        assert result == expected

    def test_transpose_sparse_input_bits(self) -> None:
        """Test with very sparse input bits after exclusion.

        Scenario: After exclusion, only bits 5, 20, 100 remain
        Simplified positions 0, 1, 2 map to 5, 20, 100
        """
        condition_ops = frozenset(
            [
                (0b101, 0b100),  # bits 0,2 with value at 2
                (0b111, 0b010),  # bits 0,1,2 with value at 1
            ],
        )
        # Very sparse remaining bits
        filtered_input_positions = frozenset([BitPosition(5), BitPosition(20), BitPosition(100)])

        result = transpose_condition_bits(condition_ops, filtered_input_positions, [])

        expected = frozenset(
            [
                # (0b101, 0b100): bits 5,100 with value at 100
                (1 << 5 | 1 << 100, 1 << 100),
                # (0b111, 0b010): bits 5,20,100 with value at 20
                (1 << 5 | 1 << 20 | 1 << 100, 1 << 20),
            ],
        )
        assert result == expected

    def test_transpose_single_remaining_bit_after_exclusion(self) -> None:
        """Test when all but one input bit is excluded.

        Scenario: Originally many bits, but only bit 42 remains after exclusion
        Simplified position 0 maps to original position 42
        """
        condition_ops = frozenset(
            [
                (0b1, 0b1),  # bit 0 = 1
                (0b1, 0b0),  # bit 0 = 0
            ],
        )
        # Only one bit remains
        filtered_input_positions = frozenset([BitPosition(42)])

        result = transpose_condition_bits(condition_ops, filtered_input_positions, [])

        expected = frozenset(
            [
                (1 << 42, 1 << 42),
                (1 << 42, 0),
            ],
        )
        assert result == expected
