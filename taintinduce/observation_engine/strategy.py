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
