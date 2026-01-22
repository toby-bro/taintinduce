import itertools
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence

from taintinduce.isa.register import Register

"""
All Strategy classes must implement generator(regs) that returns a list of seed_variations.

Each seed variation represents registers to modify and the values to set them to.
"""


@dataclass(frozen=True)
class SeedVariation:
    """Represents a seed variation: which registers to modify and what values to set."""

    registers: Sequence[Register]
    values: Sequence[int]


class Strategy(ABC):
    def __init__(self, num_runs: int = 1) -> None:
        self.num_runs: int = num_runs

    @abstractmethod
    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        """Generate seed variations for the given registers."""


class SpecialIMM(Strategy):
    """Generate special value that same with the imm."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        imm_value = self.num_runs
        inputs = []
        for reg in regs:
            inputs.append(SeedVariation(registers=[reg], values=[imm_value]))
        return inputs


class RandomNumber(Strategy):
    """Generate random values for each register."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        for reg in regs:
            for _ in range(self.num_runs):
                random_value = random.getrandbits(reg.bits)
                inputs.append(SeedVariation(registers=[reg], values=[random_value]))
        return inputs


class Bitwalk(Strategy):
    """Walk a single bit through each register."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        for reg in regs:
            pattern = 1
            for x in range(reg.bits):
                inputs.append(SeedVariation(registers=[reg], values=[pattern << x]))
        return inputs


class BitFill(Strategy):
    """Fill bits progressively from LSB to MSB."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        for reg in regs:
            pattern = 1
            for x in range(reg.bits + 1):
                inputs.append(SeedVariation(registers=[reg], values=[(pattern << x) - 1]))
        return inputs


class ZeroWalk(Strategy):
    """Walk a zero bit through all-ones pattern."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        for reg in regs:
            pattern = (1 << reg.bits) - 1
            for x in range(reg.bits):
                flip_bit = 1 << x
                inputs.append(SeedVariation(registers=[reg], values=[pattern ^ flip_bit]))
        return inputs


class TwoSame(Strategy):
    """Set two registers to the same random value."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        for pair in itertools.combinations(regs, 2):
            if pair[0].bits == pair[1].bits:
                for _ in range(self.num_runs):
                    pattern = random.getrandbits(pair[0].bits)
                    inputs.append(SeedVariation(registers=list(pair), values=[pattern, pattern]))
        return inputs


class TwoDiff(Strategy):
    """Set two registers to different random values."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        for pair in itertools.combinations(regs, 2):
            if pair[0].bits == pair[1].bits:
                for _ in range(self.num_runs):
                    while True:
                        val1 = random.getrandbits(pair[0].bits)
                        val2 = random.getrandbits(pair[1].bits)
                        if val1 != val2:
                            break
                    inputs.append(SeedVariation(registers=list(pair), values=[val1, val2]))
        return inputs


class IEEE754Extended(Strategy):
    """Generate IEEE 754 extended precision (80-bit) floating point values."""

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []
        regs_80bit = [x for x in regs if x.bits == 80]

        for _ in range(self.num_runs):
            for reg in regs_80bit:
                # Generate random exponent (avoid all 0s, all 1s, and values < 16383)
                exponent = 0
                while exponent == 0 or exponent == 2**15 - 1 or exponent < 16383:
                    exponent = random.getrandbits(15)
                exponent <<= 63

                variation = self._gen_big_small(reg, regs_80bit, exponent)
                self._check_val(variation.values)
                inputs.append(variation)

                variation = self._gen_small_big(reg, regs_80bit, exponent)
                self._check_val(variation.values)
                inputs.append(variation)

        return inputs

    def _check_val(self, vals: Sequence[int]) -> None:
        """Verify that the sign bit is not set."""
        for val in vals:
            assert (val & 0x80000000000000000000) == 0

    def _gen_small_big(self, small_reg: Register, regs: list[Register], exponent: int) -> SeedVariation:
        """Generate variation with small mantissa for one register, big for others."""
        registers_list = []
        float_values = []

        sign = 0
        mantissa = random.getrandbits(6)
        float_value = mantissa + exponent + sign
        registers_list.append(small_reg)
        float_values.append(float_value)

        for reg in regs:
            if reg != small_reg:
                mantissa = random.getrandbits(62)
                float_value = mantissa + exponent + sign
                registers_list.append(reg)
                float_values.append(float_value)

        return SeedVariation(registers=registers_list, values=float_values)

    def _gen_big_small(self, big_reg: Register, regs: list[Register], exponent: int) -> SeedVariation:
        """Generate variation with big mantissa for one register, small for others."""
        registers_list = []
        float_values = []

        sign = 0
        mantissa = random.getrandbits(62)
        float_value = mantissa + exponent + sign
        registers_list.append(big_reg)
        float_values.append(float_value)

        for reg in regs:
            if reg != big_reg:
                mantissa = random.getrandbits(6)
                float_value = mantissa + exponent + sign
                registers_list.append(reg)
                float_values.append(float_value)

        return SeedVariation(registers=registers_list, values=float_values)


class SystematicRange(Strategy):
    """Generate systematic values across the full range of a register.

    For small registers (<= 16 bits), generates all possible values.
    For larger registers, generates a systematic sample with good coverage.
    Useful for arithmetic operations where edge cases matter.
    """

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []

        for reg in regs:
            if reg.bits <= 8:
                # For 8-bit or smaller, test ALL values (0-255)
                for value in range(2**reg.bits):
                    inputs.append(SeedVariation(registers=[reg], values=[value]))

            elif reg.bits <= 16:
                # For 16-bit, test every 256th value + edge cases
                for value in range(0, 2**reg.bits, 256):
                    inputs.append(SeedVariation(registers=[reg], values=[value]))
                # Add edge cases
                edge_cases = [
                    0,
                    1,
                    2,
                    3,  # Near zero
                    2**reg.bits - 4,
                    2**reg.bits - 3,  # Near max
                    2**reg.bits - 2,
                    2**reg.bits - 1,
                    2 ** (reg.bits - 1) - 1,
                    2 ** (reg.bits - 1),  # Sign boundary
                    2 ** (reg.bits - 1) + 1,
                ]
                for value in edge_cases:
                    inputs.append(SeedVariation(registers=[reg], values=[value]))

            else:
                # For 32/64-bit, use systematic sampling with edge cases
                # Sample every 2^16 values for coverage
                step = max(2**16, (2**reg.bits) // self.num_runs)
                for value in range(0, 2**reg.bits, step):
                    inputs.append(SeedVariation(registers=[reg], values=[value]))

                # Add critical edge cases
                edge_cases = [
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                    10,  # Low values
                    127,
                    128,
                    129,  # Signed byte boundary
                    254,
                    255,
                    256,
                    257,  # Unsigned byte boundary
                    32767,
                    32768,
                    32769,  # Signed word boundary
                    65534,
                    65535,
                    65536,
                    65537,  # Unsigned word boundary
                    2**reg.bits - 10,
                    2**reg.bits - 9,  # Near max
                    2**reg.bits - 2,
                    2**reg.bits - 1,
                ]
                for value in edge_cases:
                    if value < 2**reg.bits:
                        inputs.append(SeedVariation(registers=[reg], values=[value]))

        return inputs


class ByteBlocks(Strategy):
    """Generate combinations with progressively larger block sizes to optimize observation count.

    Block size strategy:
    - Bits 0-15 (lower 16 bits): 8-bit blocks (0x00 or 0xFF per byte) -> 2^2 = 4 patterns
    - Bits 16-31: 16-bit block (all 0s or all 1s) -> 2 patterns
    - Bits 32-63: 32-bit block (all 0s or all 1s) -> 2 patterns

    Special handling:
    - EFLAGS registers are set to all zeros (not included in combinations)
    - For 32-bit registers: 8 base patterns * 2 (with highest bit flipped) = 15 patterns per register
    - For 64-bit registers: 16 base patterns * 2 (with highest bit flipped) = 31 patterns per register
    - Combinations are generated across all non-EFLAGS registers

    For ADD EAX, EBX: 15 * 15 = 225 combinations
    For ADD RAX, RBX: 31 * 31 = 961 combinations
    """

    def _build_value_from_byte_blocks(self, combination: int, num_bytes: int) -> int:
        """Build a value from byte block combination."""
        value = 0
        for byte_idx in range(num_bytes):
            if combination & (1 << byte_idx):
                value |= 0xFF << (byte_idx * 8)
        return value

    def _generate_32bit_patterns(self) -> list[int]:
        """Generate 8 patterns for 32-bit registers.

        - Bits 0-15: 8-bit blocks -> 4 patterns
        - Bits 16-31: 16-bit block -> 2 patterns
        Total: 4 * 2 = 8 patterns
        """
        patterns = []
        # Lower 16 bits: 8-bit blocks (2 bytes)
        for lower_combo in range(2**2):  # 4 patterns
            lower_value = self._build_value_from_byte_blocks(lower_combo, 2)
            # Upper 16 bits: single 16-bit block
            for upper_pattern in [0, 1]:  # 2 patterns
                value = lower_value
                if upper_pattern == 1:
                    value |= 0xFFFF0000
                patterns.append(value)
        return patterns

    def _generate_64bit_patterns(self) -> list[int]:
        """Generate 16 patterns for 64-bit registers.

        - Bits 0-15: 8-bit blocks -> 4 patterns
        - Bits 16-31: 16-bit block -> 2 patterns
        - Bits 32-63: 32-bit block -> 2 patterns
        Total: 4 * 2 * 2 = 16 patterns
        """
        patterns = []
        # Bits 0-15: 8-bit blocks (2 bytes)
        for lower_combo in range(2**2):  # 4 patterns
            lower_value = self._build_value_from_byte_blocks(lower_combo, 2)
            # Bits 16-31: 16-bit block
            for mid_pattern in [0, 1]:  # 2 patterns
                mid_value = lower_value
                if mid_pattern == 1:
                    mid_value |= 0xFFFF0000
                # Bits 32-63: 32-bit block
                for upper_pattern in [0, 1]:  # 2 patterns
                    value = mid_value
                    if upper_pattern == 1:
                        value |= 0xFFFFFFFF00000000
                    patterns.append(value)
        return patterns

    def _flip_highest_bit(self, value: int) -> int | None:
        """Flip the highest 1 bit to 0. Returns None if value is 0."""
        if value == 0:
            return None
        # Find the position of the highest 1 bit
        highest_bit = value.bit_length() - 1
        # Flip it
        return value ^ (1 << highest_bit)

    def _generate_patterns_for_register(self, reg: Register) -> list[int]:
        """Generate byte block patterns for a single register.

        For each pattern, also generate a variant with the highest 1 bit flipped to 0.
        This doubles the number of patterns while preventing combinatorial explosion.
        """
        base_patterns = []
        if reg.bits == 32:
            base_patterns = self._generate_32bit_patterns()
        elif reg.bits == 64:
            base_patterns = self._generate_64bit_patterns()
        else:
            # For other sizes, use all combinations
            num_bytes = reg.bits // 8
            base_patterns = [self._build_value_from_byte_blocks(combo, num_bytes) for combo in range(2**num_bytes)]

        # Double the patterns by flipping the highest bit
        patterns = []
        for pattern in base_patterns:
            patterns.append(pattern)
            flipped = self._flip_highest_bit(pattern)
            if flipped is not None:
                patterns.append(flipped)

        return patterns

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs: list[SeedVariation] = []

        # Separate EFLAGS registers from others
        eflags_regs = [reg for reg in regs if 'EFLAGS' in reg.name or 'FLAGS' in reg.name]
        non_eflags_regs = [reg for reg in regs if reg not in eflags_regs]

        # Filter to only registers with bits divisible by 8
        valid_regs = [reg for reg in non_eflags_regs if reg.bits % 8 == 0]

        if not valid_regs:
            return inputs

        # Generate byte patterns for each register
        reg_patterns: list[list[int]] = []
        for reg in valid_regs:
            patterns = self._generate_patterns_for_register(reg)
            reg_patterns.append(patterns)

        # Generate all combinations across non-EFLAGS registers
        for pattern_combo in itertools.product(*reg_patterns):
            # Build complete register list with EFLAGS set to 0
            all_regs = list(eflags_regs) + list(valid_regs)
            all_values = [0] * len(eflags_regs) + list(pattern_combo)
            inputs.append(SeedVariation(registers=all_regs, values=all_values))

        return inputs
