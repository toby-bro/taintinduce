from typing import Set

from taintinduce.isa.register import CondRegister, Register
from taintinduce.state.state import Observation
from taintinduce.types import BitPosition


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


def is_bitwise_non_decreasing(obs_list: list[Observation], input_bit: BitPosition, flag_bits: Set[BitPosition]) -> bool:
    """Check if the instruction behaves as bitwise non-decreasing for a specific input bit."""
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            diff = seed_in.diff(mutate_in)
            if len(diff) != 1 or next(iter(diff)) != input_bit:
                continue

            input_rose = (mutate_in.state_value & (1 << input_bit)) > 0
            if input_rose:
                # If I_j raised from 0 to 1, no output bit can fall from 1 to 0
                fell_bits = seed_out.state_value & ~mutate_out.state_value
            else:
                # If I_j fell from 1 to 0, no output bit can rise from 0 to 1
                fell_bits = ~seed_out.state_value & mutate_out.state_value

            # Filter out flag bits
            for bit in range(seed_out.num_bits):
                if bit not in flag_bits and ((fell_bits >> bit) & 1):
                    return False
    return True


def is_bitwise_non_increasing(obs_list: list[Observation], input_bit: BitPosition, flag_bits: Set[BitPosition]) -> bool:
    """Check if the instruction behaves as bitwise non-increasing for a specific input bit."""
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            diff = seed_in.diff(mutate_in)
            if len(diff) != 1 or next(iter(diff)) != input_bit:
                continue

            input_rose = (mutate_in.state_value & (1 << input_bit)) > 0
            if input_rose:
                # If I_j raised from 0 to 1, no output bit can rise from 0 to 1
                rose_bits = ~seed_out.state_value & mutate_out.state_value
            else:
                # If I_j fell from 1 to 0, no output bit can fall from 1 to 0
                rose_bits = seed_out.state_value & ~mutate_out.state_value

            # Filter out flag bits
            for bit in range(seed_out.num_bits):
                if bit not in flag_bits and ((rose_bits >> bit) & 1):
                    return False
    return True


def is_monotonic(obs_list: list[Observation]) -> bool:
    """An instruction is monotonic if it is bitwise non-increasing or non-decreasing with respect to each input bit."""
    if not obs_list:
        return True

    flag_bits = _get_flag_bits(obs_list[0])
    num_bits = obs_list[0].seed_io[0].num_bits

    for i in range(num_bits):
        input_bit = BitPosition(i)
        if not is_bitwise_non_decreasing(obs_list, input_bit, flag_bits) and not is_bitwise_non_increasing(
            obs_list,
            input_bit,
            flag_bits,
        ):
            return False

    return True


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


def _extract_dependencies(obs_list: list[Observation]) -> dict[BitPosition, set[BitPosition]]:
    """Helper to extract which output bits are affected by which input bits across all observations."""
    deps: dict[BitPosition, set[BitPosition]] = {}
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            diff_in = seed_in.diff(mutate_in)
            if len(diff_in) != 1:
                continue
            in_bit = next(iter(diff_in))
            diff_out = seed_out.diff(mutate_out)

            if in_bit not in deps:
                deps[in_bit] = set()
            deps[in_bit].update(diff_out)
    return deps


def is_transportable(obs_list: list[Observation]) -> bool:  # noqa: C901
    """
    Check if the instruction behaves as Transportable (like Add, Sub).
    Rules:
    1. No input bit $j_{local}$ of an operand affects any output bit $k_{local} < j_{local}$ in the output.
    2. Input bit $j_{local}$ ALWAYS affects output bit $j_{local}$ (i.e. information flows to the corresponding bit).
       Wait, dynamic observation might not show ALWAYS affects if we only have some seeds,
       but if it NEVER affects $j_{local}$, it's definitely not transportable for that operand.
       Actually, for adder, if we flip A_j, Y_j ALWAYS flips because Y_j = A_j ^ B_j ^ C_{j-1}.
       So YES, flipping A_j ALWAYS flips Y_j.
    """
    if not obs_list:
        return True

    state_format = obs_list[0].state_format
    layout = get_register_layouts(state_format)
    flag_bits = _get_flag_bits(obs_list[0])

    # We will check dynamically: for each mutation, if input bit local j is flipped,
    # what output bits are flipped?

    # Track for each (input_reg, output_reg) pair if there's any dataflow
    flow_exists = set()

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            diff_in = seed_in.diff(mutate_in)
            if len(diff_in) != 1:
                continue
            in_bit = next(iter(diff_in))
            diff_out = seed_out.diff(mutate_out)
            diff_out_no_flags = {b for b in diff_out if b not in flag_bits}

            in_local, in_reg = get_local_bit(in_bit, layout)

            # If no output non-flag bits changed, this might just be an observation where
            # the change was swallowed? Wait, in Add/Sub, Y_j ALWAYs flips!
            # So if Y_j doesn't flip, maybe it's not a direct operand, or not transportable.

            for out_bit in diff_out_no_flags:
                out_local, out_reg = get_local_bit(out_bit, layout)
                flow_exists.add((in_reg, out_reg))

                # Rule 1: No transportable flow backwards
                if out_local < in_local:
                    return False

    # Rule 2: If there is flow from in_reg to out_reg, then in_bit_j MUST ALWAYS flip out_bit_j
    # We can check this by seeing if in every observation where in_bit was flipped,
    # out_bit corresponding to the same local index also flipped.
    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            diff_in = seed_in.diff(mutate_in)
            if len(diff_in) != 1:
                continue
            in_bit = next(iter(diff_in))
            diff_out = frozenset(seed_out.diff(mutate_out))

            in_local, in_reg = get_local_bit(in_bit, layout)

            for start, _end, target_reg in layout:
                if (in_reg, target_reg) in flow_exists:
                    expected_out_bit = start + in_local
                    if expected_out_bit not in diff_out and expected_out_bit not in flag_bits:
                        return False

    return True


def is_translatable(obs_list: list[Observation]) -> bool:  # noqa: C901
    """
    Check if the instruction behaves as Translatable (like Shift).
    For a given seed, there must be a constant shift amount DELTA for the data operand.
    When a bit j of the data operand is flipped, it should flip bit j + DELTA of the output.
    (For arithmetic shift, it might flip a contiguous range of bits).
    We require at least one seed where DELTA != 0 to confirm it's a shift and not just an identity/transportable.
    Wait, the user just wants to know if it fits the category.
    Let's check if for EVERY seed, there exists some DELTA such that flipping bit j in some input register
    flips exactly bit j + DELTA in some output register (ignoring flags).
    """
    if not obs_list:
        return True

    state_format = obs_list[0].state_format
    layout = get_register_layouts(state_format)
    flag_bits = _get_flag_bits(obs_list[0])

    # We look for a pattern where for each observation, an input register's bits
    # are shifted by a constant amount to an output register.

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io

        # Group by input register
        flips_by_in_reg: dict[str, dict[int, set[BitPosition]]] = {}

        for mutate_in, mutate_out in obs.mutated_ios:
            diff_in = seed_in.diff(mutate_in)
            if len(diff_in) != 1:
                continue
            in_bit = next(iter(diff_in))
            diff_out = {b for b in seed_out.diff(mutate_out) if b not in flag_bits}

            in_local, in_reg = get_local_bit(in_bit, layout)

            if in_reg not in flips_by_in_reg:
                flips_by_in_reg[in_reg] = {}
            if diff_out:
                flips_by_in_reg[in_reg][in_local] = diff_out

        # For this observation, is there at least one input register that acts like a shifted data operand?
        # A data operand will have its bits shifted by a constant DELTA to an output register.
        # However, the shift operand (B) will have chaotic effects. We just need to verify that
        # for registers that HAVE 1-to-1 or 1-to-range mapping, the shift is constant.

        for _in_reg, local_flips in flips_by_in_reg.items():
            # Find if there is a consistent shift offset for this register to some output register
            # Only consider input bits that actually caused a change
            if len(local_flips) < 2:
                # Need at least 2 bits to verify a pattern for this register
                continue

            deltas = set()

            for in_local, out_bits in local_flips.items():
                # Get the "primary" shifted bit: the min or max bit.
                # For logical shift, len(out_bits) == 1.
                # For arithmetic right shift, out_bits can be multiple (sign extension).
                # The minimum output bit would correspond to the shifted bit.
                out_locals = [get_local_bit(b, layout)[0] for b in out_bits]
                primary_out = min(out_locals)

                deltas.add(primary_out - in_local)

            # If all flipped bits in this register show the SAME delta, it's a shift operand!
            if len(deltas) > 1:
                # If deltas aren't consistent, this register isn't a shift operand.
                # BUT wait, if NO register in this observation has a consistent shift, then
                # maybe it's not a translatable instruction?
                # Actually, maybe the shift amount was 0, so it looks like transportable.
                pass

    # To truly classify it as translatable and not just transportable,
    # we should see if there is ANY observation where DELTA != 0.

    # Let's do a stricter check:
    # For every observation, across all bit flips, the instruction must exhibit either:
    # 1. 1-to-1 mapping with shift (logical)
    # 2. 1-to-many mapping with shift (arithmetic)
    # 3. Chaotic mapping (this would be the shift amount operand, which we ignore)
    # A translatable instruction MUST have a shifted data operand.

    has_non_zero_shift = False
    is_valid_translatable = True

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io

        flips_by_in_reg = {}
        for mutate_in, mutate_out in obs.mutated_ios:
            diff_in = seed_in.diff(mutate_in)
            if len(diff_in) != 1:
                continue
            in_bit = next(iter(diff_in))
            diff_out = {b for b in seed_out.diff(mutate_out) if b not in flag_bits}

            if diff_out:
                in_local, in_reg = get_local_bit(in_bit, layout)
                if in_reg not in flips_by_in_reg:
                    flips_by_in_reg[in_reg] = {}
                flips_by_in_reg[in_reg][in_local] = diff_out

        # Check if there is AT LEAST ONE register that acts as a data operand with a shift
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

        # Every instruction must either have no effect (delta=0) or have a valid data operand
        # If no valid data operand is found, but outputs changed, it might not be translatable
        # Let's say if anything changed, we MUST find a valid data operand (where len(deltas) == 1)
        if flips_by_in_reg and not valid_data_operand_found:
            is_valid_translatable = False
            break

    return is_valid_translatable and has_non_zero_shift


def is_cond_transportable(obs_list: list[Observation]) -> bool:
    """
    Conditionally transportable (like Equality/Inequality).
    For these, checking A == B or A != B maps ALL bits of A and B to the same output bit
    (or same set of output bits for SETE).
    If we exclude flags, this only applies to instructions that emit equality checks to a GPR.
    Usually, flipping ANY bit of the operand changes the EXACT SAME output bit(s).
    """
    if not obs_list:
        return False

    flag_bits = _get_flag_bits(obs_list[0]) if obs_list else set()

    input_bits_affecting: dict[frozenset[BitPosition], set[BitPosition]] = {}

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            diff_in = seed_in.diff(mutate_in)
            if len(diff_in) != 1:
                continue
            in_bit = next(iter(diff_in))
            diff_out = frozenset([b for b in seed_out.diff(mutate_out) if b not in flag_bits])

            if diff_out:
                if diff_out not in input_bits_affecting:
                    input_bits_affecting[diff_out] = set()
                input_bits_affecting[diff_out].add(in_bit)

    if not input_bits_affecting:
        return False

    # Find any output set that is affected by a LARGE number of different input bits.
    # An equality check on a 32-bit register means 32 or 64 different bits affect the very same output bit.
    # For small tests, our mock uses 2 input bits. If ALL observed input bits converge to EXACTLY the same out_set,
    # and there's more than 1 input bit, we can classify it as conditionally transportable.

    # Check if there is exactly ONE main output set that gets flipped by multiple inputs
    # Actually, let's just say if any output set is targeted by >= 2 different input bits,
    # and it's the ONLY behavior (or the dominant one).

    # Are all diff_out the same?
    if len(input_bits_affecting) == 1:
        _out_set, in_bits = next(iter(input_bits_affecting.items()))
        if len(in_bits) >= 2:
            return True

    return False


def classify_instruction(obs_list: list[Observation]) -> str:
    """
    Returns the CellIFT category of the instruction represented by obs_list.
    Excludes flags. Categories checked: Monotonic, Transportable, Translatable.
    """
    has_outputs = False
    flag_bits = _get_flag_bits(obs_list[0]) if obs_list else set()

    for obs in obs_list:
        if has_outputs:
            break
        for _mut_in, mut_out in obs.mutated_ios:
            diff = obs.seed_io[1].diff(mut_out)
            if any(b not in flag_bits for b in diff):
                has_outputs = True
                break

    if not has_outputs:
        return 'No Data Outputs'

    if is_monotonic(obs_list):
        return 'Monotonic'
    if is_transportable(obs_list):
        return 'Transportable'
    if is_translatable(obs_list):
        return 'Translatable'
    if is_cond_transportable(obs_list):
        return 'Conditionally Transportable'
    return 'Unknown'
