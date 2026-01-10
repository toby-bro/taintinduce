"""Utility functions for taint rule manipulation."""

from typing import Sequence

from taintinduce.isa.register import Register
from taintinduce.state.state_utils import reg_pos

from .conditions import LogicType, TaintCondition


def shift_espresso(
    espresso_cond: frozenset[tuple[int, int]],
    reg: Register,
    state_format: Sequence[Register],
) -> frozenset[tuple[int, int]]:
    """Shift ESPRESSO conditions to match register position in state."""
    reg_start_pos = reg_pos(reg, state_format)
    new_espresso_cond: set[tuple[int, int]] = set()
    for conditional_bitmask, conditional_value in espresso_cond:
        new_bitmask = conditional_bitmask << reg_start_pos
        new_value = conditional_value << reg_start_pos
        new_espresso_cond.add((new_bitmask, new_value))
    return frozenset(new_espresso_cond)


def espresso2cond(espresso_cond: frozenset[tuple[int, int]]) -> TaintCondition:
    """Converts ESPRESSO conditions into TaintCondition object."""
    return TaintCondition(LogicType.DNF, espresso_cond)
