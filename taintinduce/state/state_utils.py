"""Utility functions for State manipulation and conversion."""

from typing import Sequence

from taintinduce.isa.register import Register
from taintinduce.state.state import State
from taintinduce.types import CpuRegisterMap, StateValue


def reg2pos(all_regs: Sequence[Register], reg: Register) -> int:
    """Get the start position of a register in the State bitvector.

    Args:
        all_regs: a list of reg class
        reg: reg class
    Returns:
        pos (int): Starting bit position
    """
    regs_list = sorted(all_regs, key=lambda reg: reg.uc_const)
    pos = 0
    for r in regs_list:
        if r == reg:
            break
        pos += r.bits
    return pos


def reg_pos(reg: Register, state_format: Sequence[Register]) -> int:
    """Get the start position of a register in the State bitvector."""
    reg_start_pos = 0
    for reg2 in state_format:
        if reg == reg2:
            break
        reg_start_pos += reg2.bits
    return reg_start_pos


def bitpos2reg(bitpos: int, state_format: Sequence[Register]) -> Register:
    """Find which register contains a given bit position."""
    remaining_pos = bitpos
    for reg in state_format:
        remaining_pos -= reg.bits
        if remaining_pos <= 0:
            break
    return reg


def regs2bits(cpustate: CpuRegisterMap, state_format: Sequence[Register]) -> State:
    """Converts CpuRegisterMap into a State bitvector using state_format.

    Args:
        cpustate: Register-value mapping
        state_format: Ordered list of registers defining bit layout
    Returns:
        State object (bitvector representation)
    """
    bits = 0
    value = 0
    for reg in state_format:
        value |= cpustate[reg] << bits
        bits += reg.bits
    return State(bits, StateValue(value))


def regs2bits2(cpustate: CpuRegisterMap, state_format: Sequence[Register]) -> State:
    """Converts CpuRegisterMap into a State with debug printing."""
    bits = 0
    value = 0
    for reg in state_format:
        print('bin:{:0128b}'.format(cpustate[reg] << bits))
        value |= cpustate[reg] << bits
        bits += reg.bits
    return State(bits, StateValue(value))


def bits2regs(state: State, regs: Sequence[Register]) -> CpuRegisterMap:
    """Convert State bitvector to cpu_state dict.

    Args:
        state: State object
        regs: Register list
    Returns:
        Register-value mapping
    """
    cpu_state = CpuRegisterMap()
    value = state.state_value
    regs_list = sorted(regs, key=lambda reg: reg.uc_const)
    for reg in regs_list:
        cpu_state[reg] = ((2**reg.bits) - 1) & value
        value = StateValue(value >> reg.bits)
    return cpu_state


def extract_reg2bits(state: State, reg: Register, state_format: Sequence[Register]) -> State:
    """Extract a specific register's value from a State bitvector.

    Args:
        state: State object
        reg: Register to extract
        state_format: Register layout
    Returns:
        State containing only the register's bits
    """
    reg_start_pos = reg_pos(reg, state_format)
    reg_mask = (1 << reg.bits) - 1

    # mask for the state to isolate the register
    state_mask = reg_mask << reg_start_pos
    isolated_reg_value = state.state_value & state_mask
    reg_value = isolated_reg_value >> reg_start_pos

    return State(reg.bits, StateValue(reg_value))


def pos2reg(state1: State, state2: State, regs: Sequence[Register]) -> list[tuple[Register, int]]:
    """Convert position values to registers."""
    pos_val = list(state1.diff(state2))
    pos_val = sorted(pos_val, reverse=True)
    regs_list = sorted(regs, key=lambda reg: reg.uc_const)
    pos = 0
    res_regs = set()

    for reg in regs_list:
        bpos = pos
        pos += reg.bits
        while pos_val:
            p = pos_val[-1]
            if p < pos:
                res_regs.add((reg, p - bpos))
                pos_val.pop()
            else:
                break

    return list(res_regs)


def convert2rpn(
    all_regs: Sequence[Register],
    regs: Sequence[Register],
    masks: Sequence[int],
    values: Sequence[int],
) -> tuple[int | None, int | None]:
    """Convert reg+mask+values to condition RPN.

    Args:
        regs: a list of reg class
        masks: a list of reg mask
        values: a list of reg value
    Returns:
        rpn tuple (see Condition class)
    """
    if len(regs) == 1:
        reg = regs[0]
        mask = masks[0]
        val = values[0]
        state_mask = mask << reg2pos(all_regs, reg)
        state_val = val << reg2pos(all_regs, reg)
        return state_mask, state_val
    if len(regs) == 2:
        arg = []
        for reg in regs:
            arg.append(((1 << reg.bits) - 1) << reg2pos(all_regs, reg))
        arg1 = arg[0]
        arg2 = arg[1]
        return arg1, arg2
    return None, None


# Bit manipulation functions
def set_bit(value: int, pos: int) -> int:
    """Set a bit at position pos."""
    return value | (1 << pos)


def unset_bit(value: int, pos: int) -> int:
    """Unset a bit at position pos."""
    return value & (~(1 << pos))


def invert_bit(value: int, pos: int) -> int:
    """Invert a bit at position pos."""
    return value ^ (1 << pos)


def print_bin(value: int) -> None:
    """Print value as 64-bit binary."""
    print('{:064b}'.format(value))
