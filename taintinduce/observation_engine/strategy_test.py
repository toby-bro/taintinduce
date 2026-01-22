"""Unit tests for strategy generators."""

from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import (
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_EAX,
    X86_REG_EBX,
    X86_REG_EFLAGS,
    X86_REG_RAX,
    X86_REG_RBX,
)
from taintinduce.observation_engine.strategy import ByteBlocks


class TestByteBlocks:
    """Test ByteBlocks strategy."""

    def test_byteblocks_32bit_register(self):
        """Test ByteBlocks strategy with a 32-bit register (EAX)."""
        strategy = ByteBlocks(num_runs=1)
        reg = X86_REG_EAX()

        variations = strategy.generator([reg])

        # Optimized: bits 0-15 (4 patterns) * bits 16-31 (2 patterns) = 8 patterns
        assert len(variations) == 8

        # Expected values with optimized block sizes:
        # Lower 16 bits: 0x0000, 0x00FF, 0xFF00, 0xFFFF
        # Upper 16 bits: 0x0000, 0xFFFF
        expected_values = [
            0x00000000,  # lower=0x0000, upper=0x0000
            0xFFFF0000,  # lower=0x0000, upper=0xFFFF
            0x000000FF,  # lower=0x00FF, upper=0x0000
            0xFFFF00FF,  # lower=0x00FF, upper=0xFFFF
            0x0000FF00,  # lower=0xFF00, upper=0x0000
            0xFFFFFF00,  # lower=0xFF00, upper=0xFFFF
            0x0000FFFF,  # lower=0xFFFF, upper=0x0000
            0xFFFFFFFF,  # lower=0xFFFF, upper=0xFFFF
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
        """Test ByteBlocks strategy with multiple registers.

        When multiple registers are provided, ByteBlocks now generates
        all combinations across registers instead of treating them independently.
        """
        strategy = ByteBlocks(num_runs=1)
        eax = X86_REG_EAX()
        ebx = X86_REG_EBX()

        variations = strategy.generator([eax, ebx])

        # Optimized: each 32-bit register generates 8 variations
        # With combinations: 8 * 8 = 64
        assert len(variations) == 64

        # All variations should set both registers
        for var in variations:
            assert len(var.registers) == 2
            assert var.registers[0].name == 'EAX'
            assert var.registers[1].name == 'EBX'
            assert len(var.values) == 2

    def test_byteblocks_non_byte_aligned_register_skipped(self):
        """Test that registers with bits not divisible by 8 are skipped."""

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

    def test_byteblocks_two_32bit_registers_combinations(self):
        """Test ByteBlocks generates all combinations across two 32-bit registers.

        For arithmetic operations like ADD EAX, EBX, we need to test all
        combinations of byte patterns across both registers to capture
        carry propagation effects. With two 32-bit registers:
        - Each register has 8 patterns (4 for bits 0-15, 2 for bits 16-31)
        - Total combinations: 8 * 8 = 64
        """
        strategy = ByteBlocks(num_runs=1)
        eax = X86_REG_EAX()
        ebx = X86_REG_EBX()

        variations = strategy.generator([eax, ebx])

        # Should generate all combinations across both registers
        assert len(variations) == 64, f'Expected 64 combinations, got {len(variations)}'

        # Verify that all variations set both registers
        for var in variations:
            assert len(var.registers) == 2, 'Each variation should set both registers'
            assert var.registers[0].name == 'EAX'
            assert var.registers[1].name == 'EBX'
            assert len(var.values) == 2

        # Check that we have specific important combinations
        # ByteBlocks only generates byte patterns (0x00 or 0xFF per byte)
        found_specific_patterns = {
            'both_all_ones': False,  # EAX=0xFFFFFFFF, EBX=0xFFFFFFFF
            'one_all_ones': False,  # EAX=0xFFFFFFFF, EBX=0x000000FF
            'both_zeros': False,  # EAX=0x00000000, EBX=0x00000000
        }
        for var in variations:
            if var.values[0] == 0xFFFFFFFF and var.values[1] == 0xFFFFFFFF:
                found_specific_patterns['both_all_ones'] = True
            if var.values[0] == 0xFFFFFFFF and var.values[1] == 0x000000FF:
                found_specific_patterns['one_all_ones'] = True
            if var.values[0] == 0x00000000 and var.values[1] == 0x00000000:
                found_specific_patterns['both_zeros'] = True

        for pattern_name, found in found_specific_patterns.items():
            assert found, f'Should include pattern {pattern_name}'

        # Verify no duplicates
        unique_combos = {(var.values[0], var.values[1]) for var in variations}
        assert len(unique_combos) == 64, 'All combinations should be unique'

    def test_byteblocks_with_eflags_register(self):
        """Test ByteBlocks with EFLAGS register - should set EFLAGS to 0."""
        strategy = ByteBlocks(num_runs=1)
        eflags = X86_REG_EFLAGS()
        eax = X86_REG_EAX()

        variations = strategy.generator([eflags, eax])

        # Should generate 8 combinations (only EAX varies, EFLAGS is always 0)
        assert len(variations) == 8, f'Expected 8 combinations, got {len(variations)}'

        # Verify EFLAGS is always 0
        for var in variations:
            assert len(var.registers) == 2
            assert var.registers[0].name == 'EFLAGS'
            assert var.registers[1].name == 'EAX'
            assert var.values[0] == 0, 'EFLAGS should always be 0'

    def test_byteblocks_64bit_registers(self):
        """Test ByteBlocks with 64-bit registers.

        For 64-bit registers:
        - Bits 0-15: 4 patterns (8-bit blocks)
        - Bits 16-31: 2 patterns (16-bit block)
        - Bits 32-63: 2 patterns (32-bit block)
        - Total per register: 4 * 2 * 2 = 16 patterns
        - For two 64-bit registers: 16 * 16 = 256 combinations
        """
        strategy = ByteBlocks(num_runs=1)
        rax = X86_REG_RAX()
        rbx = X86_REG_RBX()

        variations = strategy.generator([rax, rbx])

        # Should generate 16 * 16 = 256 combinations
        assert len(variations) == 256, f'Expected 256 combinations, got {len(variations)}'

        # Verify that all variations set both registers
        for var in variations:
            assert len(var.registers) == 2
            assert var.registers[0].name == 'RAX'
            assert var.registers[1].name == 'RBX'
            assert len(var.values) == 2

        # Check specific patterns exist
        found_patterns = {
            'lower_all_ones': False,  # 0x00000000FFFFFFFF
            'upper_all_ones': False,  # 0xFFFFFFFF00000000
            'all_ones': False,  # 0xFFFFFFFFFFFFFFFF
        }

        for var in variations:
            if var.values[0] == 0x00000000FFFFFFFF:
                found_patterns['lower_all_ones'] = True
            if var.values[0] == 0xFFFFFFFF00000000:
                found_patterns['upper_all_ones'] = True
            if var.values[0] == 0xFFFFFFFFFFFFFFFF:
                found_patterns['all_ones'] = True

        for pattern_name, found in found_patterns.items():
            assert found, f'Should include pattern {pattern_name}'
