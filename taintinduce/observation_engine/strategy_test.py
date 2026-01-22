"""Unit tests for strategy generators."""

from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_EBX
from taintinduce.observation_engine.strategy import ByteBlocks


class TestByteBlocks:
    """Test ByteBlocks strategy."""

    def test_byteblocks_32bit_register(self):
        """Test ByteBlocks strategy with a 32-bit register (EAX)."""
        strategy = ByteBlocks(num_runs=1)
        reg = X86_REG_EAX()

        variations = strategy.generator([reg])

        # For a 32-bit register, we have 4 bytes, so 2^4 = 16 combinations
        assert len(variations) == 16

        # Expected values (all combinations of 0x00 and 0xFF for 4 bytes)
        expected_values = [
            0x00000000,  # 0000
            0x000000FF,  # 0001
            0x0000FF00,  # 0010
            0x0000FFFF,  # 0011
            0x00FF0000,  # 0100
            0x00FF00FF,  # 0101
            0x00FFFF00,  # 0110
            0x00FFFFFF,  # 0111
            0xFF000000,  # 1000
            0xFF0000FF,  # 1001
            0xFF00FF00,  # 1010
            0xFF00FFFF,  # 1011
            0xFFFF0000,  # 1100
            0xFFFF00FF,  # 1101
            0xFFFFFF00,  # 1110
            0xFFFFFFFF,  # 1111
        ]

        # Extract values from variations
        actual_values = [var.values[0] for var in variations]

        # Check that all expected values are present
        assert sorted(actual_values) == sorted(expected_values)

        # Verify that all variations have the correct register
        for var in variations:
            assert len(var.registers) == 1
            assert var.registers[0].name == 'EAX'
            assert len(var.values) == 1

    def test_byteblocks_16bit_register(self):
        """Test ByteBlocks strategy with a 16-bit register."""

        strategy = ByteBlocks(num_runs=1)
        reg = X86_REG_AX()

        variations = strategy.generator([reg])

        # For a 16-bit register, we have 2 bytes, so 2^2 = 4 combinations
        assert len(variations) == 4

        expected_values = [
            0x0000,  # 00
            0x00FF,  # 01
            0xFF00,  # 10
            0xFFFF,  # 11
        ]

        actual_values = [var.values[0] for var in variations]
        assert sorted(actual_values) == sorted(expected_values)

    def test_byteblocks_8bit_register(self):
        """Test ByteBlocks strategy with an 8-bit register."""

        strategy = ByteBlocks(num_runs=1)
        reg = X86_REG_AL()

        variations = strategy.generator([reg])

        # For an 8-bit register, we have 1 byte, so 2^1 = 2 combinations
        assert len(variations) == 2

        expected_values = [0x00, 0xFF]
        actual_values = [var.values[0] for var in variations]
        assert sorted(actual_values) == sorted(expected_values)

    def test_byteblocks_multiple_registers(self):
        """Test ByteBlocks strategy with multiple registers."""

        strategy = ByteBlocks(num_runs=1)
        eax = X86_REG_EAX()
        ebx = X86_REG_EBX()

        variations = strategy.generator([eax, ebx])

        # Each 32-bit register generates 16 variations
        assert len(variations) == 32

        # Check that we have variations for both registers
        eax_variations = [var for var in variations if var.registers[0].name == 'EAX']
        ebx_variations = [var for var in variations if var.registers[0].name == 'EBX']

        assert len(eax_variations) == 16
        assert len(ebx_variations) == 16

    def test_byteblocks_non_byte_aligned_register_skipped(self):
        """Test that registers with bits not divisible by 8 are skipped."""
        # Create a mock register with non-byte-aligned size

        class MockReg(Register):
            def __init__(self):
                self.name = 'MOCK'
                self.bits = 12  # Not divisible by 8
                self.structure = [12]
                self.value = None
                self.address = None

        strategy = ByteBlocks(num_runs=1)
        reg = MockReg()

        variations = strategy.generator([reg])

        # Should produce no variations for non-byte-aligned register
        assert len(variations) == 0
