from collections import defaultdict

from taintinduce.classifier.categories import InstructionCategory
from taintinduce.classifier.classifier import get_register_layouts
from taintinduce.inference_engine.observation_processor import extract_observation_dependencies
from taintinduce.inference_engine.unitary_flow_processor import group_unitary_flows_by_output
from taintinduce.instrumentation.ast import (
    BinaryExpr,
    Constant,
    Expr,
    InstructionCellExpr,
    LogicCircuit,
    Op,
    TaintAssignment,
    TaintOperand,
    UnaryExpr,
)
from taintinduce.state.state import Observation
from taintinduce.types import BitPosition


def _build_flow_map(obs_list: list[Observation]) -> dict[tuple[str, int, int], set[tuple[str, int, int]]]:
    state_format = obs_list[0].state_format
    layout = get_register_layouts(state_format)

    def get_reg_info(global_bit: int) -> tuple[str | None, int | None]:
        for start, end, name in layout:
            if start <= global_bit < end:
                return name, global_bit - start
        return None, None

    deps = extract_observation_dependencies(obs_list)
    output_to_inputs = group_unitary_flows_by_output(deps)

    out_reg_to_bits: dict[str, set[int]] = defaultdict(set)
    for out_bit in output_to_inputs:
        name, idx = get_reg_info(out_bit)
        if name is not None and idx is not None:
            out_reg_to_bits[name].add(idx)

    flow_map: dict[tuple[str, int, int], set[tuple[str, int, int]]] = {}
    for out_name, out_bits in out_reg_to_bits.items():
        out_min = min(out_bits)
        out_max = max(out_bits)

        in_globals: set[int] = set()
        for b in out_bits:
            global_out = next(start for start, end, name in layout if name == out_name) + b
            if BitPosition(global_out) in output_to_inputs:
                in_globals.update(output_to_inputs[BitPosition(global_out)])

        in_reg_to_bits: dict[str, set[int]] = defaultdict(set)
        for in_bit in in_globals:
            in_name, in_idx = get_reg_info(in_bit)
            if in_name is not None and in_idx is not None:
                in_reg_to_bits[in_name].add(in_idx)

        in_slices = set()
        for in_name, in_bits in in_reg_to_bits.items():
            in_slices.add((in_name, min(in_bits), max(in_bits)))

        flow_map[(out_name, out_min, out_max)] = in_slices

    return flow_map


def instrument_mapped(obs_list: list[Observation]) -> LogicCircuit:
    """Generates trivial 1-to-N copying cells for MAPPED instructions."""
    # Based on the Mapped category, inputs definitively and directly copy to outputs.
    # To determine precisely which input flows to which output, we cross-reference mutations:
    assignments: list[TaintAssignment] = []

    if not obs_list:
        raise RuntimeError('No observations provided for instrumentation!')

    state_format = obs_list[0].state_format
    archstring = obs_list[0].archstring
    bytestring = obs_list[0].bytestring
    layout = get_register_layouts(state_format)
    # Using the first successful observation where logic is fully observable

    flow_map = _build_flow_map(obs_list)
    FLAGS_REGS = {'EFLAGS', 'RFLAGS', 'NZCV', 'CPSR', 'FPSW'}

    for (out_name, out_min, out_max), in_regs in flow_map.items():
        if not in_regs:
            continue
        if out_name in FLAGS_REGS:
            continue

        target = TaintOperand(out_name, out_min, out_max, is_taint=True)
        dependencies = [TaintOperand(r_name, r_min, r_max, is_taint=True) for r_name, r_min, r_max in in_regs]
        assignments.append(TaintAssignment(target=target, dependencies=dependencies))

    return LogicCircuit(
        assignments=assignments,
        architecture=archstring,
        instruction=bytestring,
        state_format=state_format,
    )


def compute_di_vector(
    obs_list: list[Observation],
    global_bit_start: int,
    bit_len: int,
    out_global_start: int,
    out_bit_len: int,
) -> int:
    """Computes the di mask (1 for non-decreasing, 0 for non-increasing) for a bit slice"""
    out_mask = ((1 << out_bit_len) - 1) << out_global_start
    d_mask = 0
    for local_bit in range(bit_len):
        global_bit = global_bit_start + local_bit

        is_non_decreasing = True
        is_non_increasing = True

        for obs in obs_list:
            seed_in, seed_out = obs.seed_io
            for mut_in, mut_out in obs.mutated_ios:
                diff = seed_in.diff(mut_in)
                if len(diff) != 1:
                    continue
                flipped_bit = next(iter(diff))
                if flipped_bit != global_bit:
                    continue

                orig_in = (seed_in.state_value >> global_bit) & 1
                mut_val = (mut_in.state_value >> global_bit) & 1

                if orig_in == 0 and mut_val == 1:
                    src_out = seed_out.state_value & out_mask
                    dst_out = mut_out.state_value & out_mask
                elif orig_in == 1 and mut_val == 0:
                    src_out = mut_out.state_value & out_mask
                    dst_out = seed_out.state_value & out_mask
                else:
                    continue

                out_diff = src_out ^ dst_out
                if out_diff == 0:
                    continue

                fell_mask = src_out & ~dst_out
                if fell_mask & out_diff:
                    is_non_decreasing = False

                raised_mask = ~src_out & dst_out
                if raised_mask & out_diff:
                    is_non_increasing = False

        if is_non_decreasing and is_non_increasing:
            d_mask |= 1 << local_bit
        elif is_non_decreasing:
            d_mask |= 1 << local_bit
        elif is_non_increasing:
            pass  # 0
        else:
            raise RuntimeError(
                f'Input bit {global_bit} is neither non-decreasing nor non-increasing! This instruction is not monotonic.',
            )

    return d_mask


def instrument_monotonic(obs_list: list[Observation]) -> LogicCircuit:
    assignments: list[TaintAssignment] = []
    if not obs_list:
        raise RuntimeError('No observations provided for instrumentation!')

    state_format = obs_list[0].state_format
    archstring = obs_list[0].archstring
    bytestring = obs_list[0].bytestring
    layout = get_register_layouts(state_format)

    flow_map = _build_flow_map(obs_list)

    FLAGS_REGS = {'EFLAGS', 'RFLAGS', 'NZCV', 'CPSR', 'FPSW'}

    for (out_name, out_min, out_max), in_regs in flow_map.items():
        if not in_regs:
            continue
        if out_name in FLAGS_REGS:
            continue

        target = TaintOperand(out_name, out_min, out_max, is_taint=True)
        dependencies = []
        for r_name, r_min, r_max in in_regs:
            dependencies.append(TaintOperand(r_name, r_min, r_max, is_taint=True))

        if len(in_regs) == 1:
            r_name, r_min, r_max = list(in_regs)[0]
            if r_name == out_name and r_min == out_min and r_max == out_max:
                assignments.append(TaintAssignment(target=target, dependencies=dependencies))
                continue

        cell_inputs_rep1: dict[str, Expr] = {}
        cell_inputs_rep2: dict[str, Expr] = {}

        for r_name, r_min, r_max in in_regs:
            local_len = r_max - r_min + 1
            global_start = next(start for start, end, name in layout if name == r_name) + r_min

            out_bit_len = out_max - out_min + 1
            out_global_start = next(start for start, end, name in layout if name == out_name) + out_min

            d_mask = compute_di_vector(obs_list, global_start, local_len, out_global_start, out_bit_len)

            V_in = TaintOperand(r_name, r_min, r_max, is_taint=False)
            T_in = TaintOperand(r_name, r_min, r_max, is_taint=True)

            # Rep 1: (V & ~T) | (D & T)
            v_and_not_t = BinaryExpr(Op.AND, V_in, UnaryExpr(Op.NOT, T_in))

            D_const = Constant(d_mask, local_len)
            d_and_t = BinaryExpr(Op.AND, D_const, T_in)

            rep1_expr = BinaryExpr(Op.OR, v_and_not_t, d_and_t)

            # Rep 2: (V & ~T) | (~D & T)
            not_d_mask = (~d_mask) & ((1 << local_len) - 1)
            Not_D_const = Constant(not_d_mask, local_len)
            not_d_and_t = BinaryExpr(Op.AND, Not_D_const, T_in)

            rep2_expr = BinaryExpr(Op.OR, v_and_not_t, not_d_and_t)

            cell_inputs_rep1[r_name] = rep1_expr
            cell_inputs_rep2[r_name] = rep2_expr

        C1 = InstructionCellExpr(archstring, bytestring, out_name, out_min, out_max, cell_inputs_rep1)
        C2 = InstructionCellExpr(archstring, bytestring, out_name, out_min, out_max, cell_inputs_rep2)

        expression = BinaryExpr(Op.XOR, C1, C2)

        assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=expression))

    return LogicCircuit(
        assignments=assignments,
        architecture=archstring,
        instruction=bytestring,
        state_format=state_format,
    )


def instrument_instruction(obs_list: list[Observation], category: InstructionCategory) -> LogicCircuit:
    if category == InstructionCategory.MAPPED:
        return instrument_mapped(obs_list)
    if category == InstructionCategory.MONOTONIC:
        return instrument_monotonic(obs_list)
    if category == InstructionCategory.TRANSPORTABLE:
        # Fallback to mapped abstraction for structural analysis
        return instrument_mapped(obs_list)

    if not obs_list:
        raise RuntimeError('No observations provided for instrumentation!')

    archstring = obs_list[0].archstring
    bytestring = obs_list[0].bytestring
    state_format = obs_list[0].state_format

    if category == InstructionCategory.NO_DATA_OUTPUTS:
        return LogicCircuit(assignments=[], architecture=archstring, instruction=bytestring, state_format=state_format)

    # Defaults to a black-box abstract dependency graph representing anything complex
    return LogicCircuit(assignments=[], architecture=archstring, instruction=bytestring, state_format=state_format)
