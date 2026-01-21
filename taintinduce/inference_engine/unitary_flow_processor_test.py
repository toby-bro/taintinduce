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

        result = transpose_condition_bits(condition_ops, input_positions)

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

        result = transpose_condition_bits(condition_ops, input_positions)

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

        result = transpose_condition_bits(condition_ops, input_positions)

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
