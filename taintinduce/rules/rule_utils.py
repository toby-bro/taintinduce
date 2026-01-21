"""Utility functions for taint rule manipulation."""

from typing import Optional, Sequence

from taintinduce.isa.register import Register
from taintinduce.state.state_utils import reg_pos

from .conditions import LogicType, OutputBitRef, TaintCondition


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


def espresso2cond(
    espresso_cond: frozenset[tuple[int, int]],
    output_bit_refs: Optional[frozenset['OutputBitRef']] = None,
) -> TaintCondition:
    """Converts ESPRESSO conditions into TaintCondition object.

    Args:
        espresso_cond: Frozenset of (mask, value) tuples from ESPRESSO
        output_bit_refs: Optional frozenset of OutputBitRef for output bit conditions

    Returns:
        TaintCondition with the specified conditions and output bit references
    """
    return TaintCondition(LogicType.DNF, espresso_cond, output_bit_refs=output_bit_refs)
