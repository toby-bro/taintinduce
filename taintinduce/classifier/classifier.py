import logging
from typing import Set

from taintinduce.isa.register import CondRegister, Register
from taintinduce.state.state import Observation
from taintinduce.types import BitPosition

logger = logging.getLogger(__name__)


def _get_flag_bits(obs: Observation) -> Set[BitPosition]:
    """Returns the set of bit positions corresponding to flags/condition registers."""
    flag_bits = set()
    start_pos = 0
    for reg in obs.state_format:
        if isinstance(reg, CondRegister) or getattr(reg, 'name', '') in ('EFLAGS', 'RFLAGS', 'NZCV', 'FPSW'):
            for i in range(reg.bits):
                flag_bits.add(BitPosition(start_pos + i))
        start_pos += reg.bits
    return flag_bits


def get_register_layouts(state_format: list[Register]) -> list[tuple[int, int, str]]:
    """Returns a list of (start_bit, end_bit_exclusive, reg_name) for registers."""
    layout = []
    pos = 0
    for reg in state_format:
        layout.append((pos, pos + reg.bits, getattr(reg, 'name', 'UNKNOWN')))
        pos += reg.bits
    return layout


def get_local_bit(bit: int, layout: list[tuple[int, int, str]]) -> tuple[int, str]:
    for start, end, name in layout:
        if start <= bit < end:
            return bit - start, name
    return bit, 'UNKNOWN'


def extract_flipped_bits(val1: int, val2: int) -> set[int]:
    val = val1 ^ val2
    bits = set()
    while val:
        lsb = val & -val
        bits.add(lsb.bit_length() - 1)
        val &= val - 1
    return bits


def is_bitwise_non_decreasing(obs_list: list[Observation], input_bit: BitPosition, flag_bits: Set[BitPosition]) -> bool:
    """Check if the instruction behaves as bitwise non-decreasing for a specific input bit."""
    flag_mask = sum(1 << b for b in flag_bits)
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            if (in_xor.bit_length() - 1) != input_bit:
                continue

            input_rose = (mutate_in.state_value & in_xor) > 0
            if input_rose:
                fell_bits = seed_out.state_value & ~mutate_out.state_value
            else:
                fell_bits = ~seed_out.state_value & mutate_out.state_value

            if (fell_bits & ~flag_mask) != 0:
                return False
    return True


def is_bitwise_non_increasing(obs_list: list[Observation], input_bit: BitPosition, flag_bits: Set[BitPosition]) -> bool:
    """Check if the instruction behaves as bitwise non-increasing for a specific input bit."""
    flag_mask = sum(1 << b for b in flag_bits)
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            if (in_xor.bit_length() - 1) != input_bit:
                continue

            input_rose = (mutate_in.state_value & in_xor) > 0
            if input_rose:
                rose_bits = ~seed_out.state_value & mutate_out.state_value
            else:
                rose_bits = seed_out.state_value & ~mutate_out.state_value

            if (rose_bits & ~flag_mask) != 0:
                return False
    return True


def is_monotonic(obs_list: list[Observation]) -> bool:  # noqa: C901
    """An instruction is monotonic if it is bitwise non-increasing or non-decreasing with respect to each input bit."""
    if not obs_list:
        return True

    flag_bits = _get_flag_bits(obs_list[0])
    flag_mask = sum(1 << b for b in flag_bits)

    ND_possible = set()
    NI_possible = set()
    seen_in_bits = set()

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        seed_out_val = seed_out.state_value

        for mutate_in, mutate_out in obs.mutated_ios:
            val_in_xor = seed_in.state_value ^ mutate_in.state_value
            if val_in_xor == 0 or (val_in_xor & (val_in_xor - 1)) != 0:
                continue

            in_bit = val_in_xor.bit_length() - 1

            if in_bit not in seen_in_bits:
                seen_in_bits.add(in_bit)
                ND_possible.add(in_bit)
                NI_possible.add(in_bit)

            if in_bit not in ND_possible and in_bit not in NI_possible:
                return False  # Early exit

            input_rose = (mutate_in.state_value & val_in_xor) > 0
            mut_out_val = mutate_out.state_value

            if input_rose:
                fell_bits = seed_out_val & ~mut_out_val & ~flag_mask
                rose_bits = ~seed_out_val & mut_out_val & ~flag_mask
            else:
                fell_bits = ~seed_out_val & mut_out_val & ~flag_mask
                rose_bits = seed_out_val & ~mut_out_val & ~flag_mask

            if fell_bits and in_bit in ND_possible:
                ND_possible.remove(in_bit)
            if rose_bits and in_bit in NI_possible:
                NI_possible.remove(in_bit)

            if in_bit not in ND_possible and in_bit not in NI_possible:
                return False  # Early exit

    return True


def _extract_dependencies(obs_list: list[Observation]) -> dict[BitPosition, set[BitPosition]]:
    """Helper to extract which output bits are affected by which input bits across all observations."""
    deps: dict[BitPosition, set[BitPosition]] = {}
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            in_bit = BitPosition(in_xor.bit_length() - 1)

            out_xor = seed_out.state_value ^ mutate_out.state_value
            diff_out = {BitPosition(b) for b in extract_flipped_bits(0, out_xor)}

            if in_bit not in deps:
                deps[in_bit] = set()
            deps[in_bit].update(diff_out)
    return deps


def is_transportable(obs_list: list[Observation]) -> bool:  # noqa: C901
    if not obs_list:
        return True

    state_format = obs_list[0].state_format
    layout = get_register_layouts(state_format)
    flag_bits = _get_flag_bits(obs_list[0])
    flag_mask = sum(1 << b for b in flag_bits)

    flow_exists = set()

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            in_bit = in_xor.bit_length() - 1

            out_xor = seed_out.state_value ^ mutate_out.state_value
            out_xor &= ~flag_mask
            if out_xor == 0:
                continue

            in_local, in_reg = get_local_bit(in_bit, layout)
            diff_out = extract_flipped_bits(0, out_xor)

            for out_bit in diff_out:
                out_local, out_reg = get_local_bit(out_bit, layout)
                flow_exists.add((in_reg, out_reg))

                if out_local < in_local:
                    return False  # Early exit

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            in_bit = in_xor.bit_length() - 1

            out_xor = seed_out.state_value ^ mutate_out.state_value
            in_local, in_reg = get_local_bit(in_bit, layout)

            for start, _end, target_reg in layout:
                if (in_reg, target_reg) in flow_exists:
                    expected_out_bit = start + in_local
                    if expected_out_bit not in flag_bits and not ((out_xor >> expected_out_bit) & 1):
                        return False  # Early exit

    return True


def is_translatable(obs_list: list[Observation]) -> bool:  # noqa: C901
    if not obs_list:
        return True

    state_format = obs_list[0].state_format
    layout = get_register_layouts(state_format)
    flag_bits = _get_flag_bits(obs_list[0])
    flag_mask = sum(1 << b for b in flag_bits)

    has_non_zero_shift = False

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        flips_by_in_reg: dict[str, dict[int, set[int]]] = {}

        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            in_bit = in_xor.bit_length() - 1

            out_xor = seed_out.state_value ^ mutate_out.state_value
            out_xor &= ~flag_mask

            if out_xor:
                in_local, in_reg = get_local_bit(in_bit, layout)
                if in_reg not in flips_by_in_reg:
                    flips_by_in_reg[in_reg] = {}
                flips_by_in_reg[in_reg][in_local] = extract_flipped_bits(0, out_xor)

        valid_data_operand_found = False

        for _in_reg, local_flips in flips_by_in_reg.items():
            deltas = set()
            for in_local, out_bits in local_flips.items():
                out_locals = [get_local_bit(b, layout)[0] for b in out_bits]
                primary_out = min(out_locals) if out_locals else 0
                deltas.add(primary_out - in_local)

            if len(deltas) == 1:
                valid_data_operand_found = True
                delta = next(iter(deltas))
                if delta != 0:
                    has_non_zero_shift = True

        if flips_by_in_reg and not valid_data_operand_found:
            return False  # Early exit

    return has_non_zero_shift


def is_cond_transportable(obs_list: list[Observation]) -> bool:
    if not obs_list:
        return False

    flag_bits = _get_flag_bits(obs_list[0]) if obs_list else set()
    flag_mask = sum(1 << b for b in flag_bits)

    input_bits_affecting: dict[int, set[int]] = {}

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue
            in_bit = in_xor.bit_length() - 1

            out_xor = seed_out.state_value ^ mutate_out.state_value
            out_xor &= ~flag_mask

            if out_xor:
                if out_xor not in input_bits_affecting:
                    input_bits_affecting[out_xor] = set()
                input_bits_affecting[out_xor].add(in_bit)

    if not input_bits_affecting:
        return False

    if len(input_bits_affecting) == 1:
        _out_xor, in_bits = next(iter(input_bits_affecting.items()))
        if len(in_bits) >= 2:
            return True

    return False


def classify_instruction(obs_list: list[Observation]) -> str:
    has_outputs = False
    flag_bits = _get_flag_bits(obs_list[0]) if obs_list else set()
    flag_mask = sum(1 << b for b in flag_bits)

    for obs in obs_list:
        if has_outputs:
            break
        for _mut_in, mut_out in obs.mutated_ios:
            out_xor = obs.seed_io[1].state_value ^ mut_out.state_value
            if (out_xor & ~flag_mask) != 0:
                has_outputs = True
                break

    if not has_outputs:
        return 'No Data Outputs'

    logger.info('Checking monotonic...')
    if is_monotonic(obs_list):
        return 'Monotonic'
    logger.info('Not monotonic, checking transportable...')
    if is_transportable(obs_list):
        return 'Transportable'
    logger.info('Not transportable, checking translatable...')
    if is_translatable(obs_list):
        return 'Translatable'
    logger.info('Not translatable, checking conditionally transportable...')
    if is_cond_transportable(obs_list):
        return 'Conditionally Transportable'
    return 'Unknown'
