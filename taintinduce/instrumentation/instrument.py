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


def _build_flow_map(  # noqa: C901
    obs_list: list[Observation],
) -> dict[tuple[str, int, int], set[tuple[str, int, int]]]:
    state_format = obs_list[0].state_format
    layout = get_register_layouts(state_format)

    def get_reg_info(global_bit: int) -> tuple[str | None, int | None]:
        for start, end, name in layout:
            if start <= global_bit < end:
                return name, global_bit - start
        return None, None

    deps = extract_observation_dependencies(obs_list)
    output_to_inputs = group_unitary_flows_by_output(deps)

    # NEW LOGIC: group by the set of input registers.
    out_reg_to_bits: dict[str, dict[int, set[str]]] = defaultdict(dict)

    for out_bit in output_to_inputs:
        name, idx = get_reg_info(out_bit)
        if name is not None and idx is not None:
            # get all input registers this bit depends on
            in_regs_for_bit = set()
            for in_global in output_to_inputs[out_bit]:
                in_name, in_idx = get_reg_info(in_global)
                if in_name is not None:
                    in_regs_for_bit.add(in_name)
            out_reg_to_bits[name][idx] = in_regs_for_bit

    flow_map: dict[tuple[str, int, int], set[tuple[str, int, int]]] = {}

    for out_name, bits_dict in out_reg_to_bits.items():
        # Group bits by their in_regs_for_bit
        # We need to find contiguous ranges that have the same in_regs_for_bit
        sorted_bits = sorted(bits_dict.keys())

        # Group adjacent bits with the exact same dependency signatures
        groups = []
        if not sorted_bits:
            continue

        current_group = [sorted_bits[0]]
        current_deps = bits_dict[sorted_bits[0]]

        for i in range(1, len(sorted_bits)):
            b = sorted_bits[i]
            b_deps = bits_dict[b]
            if b_deps == current_deps and b == current_group[-1] + 1:
                current_group.append(b)
            else:
                groups.append((current_group, current_deps))
                current_group = [b]
                current_deps = b_deps
        groups.append((current_group, current_deps))

        for g_bits, _g_deps in groups:
            out_min = min(g_bits)
            out_max = max(g_bits)

            in_globals: set[int] = set()
            for b in g_bits:
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
    _layout = get_register_layouts(state_format)
    # Using the first successful observation where logic is fully observable

    flow_map = _build_flow_map(obs_list)
    FLAGS_REGS = {'EFLAGS', 'RFLAGS', 'NZCV', 'CPSR', 'FPSW'}

    for (out_name, out_min, out_max), in_regs in flow_map.items():
        if not in_regs:
            continue
        if out_name in FLAGS_REGS:
            continue

        target = TaintOperand(out_name, out_min, out_max, is_taint=True)
        dependencies = []
        cell_inputs = {}
        for r_name, r_min, r_max in in_regs:
            T_in = TaintOperand(r_name, r_min, r_max, is_taint=True)
            dependencies.append(T_in)
            cell_inputs[r_name] = T_in
        expr = InstructionCellExpr(archstring, bytestring, out_name, out_min, out_max, cell_inputs)
        assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=expr))

    return LogicCircuit(
        assignments=assignments,
        architecture=archstring,
        instruction=bytestring,
        state_format=state_format,
    )


def compute_di_vector(  # noqa: C901
    obs_list: list[Observation],
    global_bit_start: int,
    bit_len: int,
    out_global_start: int,
    out_bit_len: int,
) -> int:
    """Computes the di mask (1 for non-decreasing, 0 for non-increasing) for a bit slice"""

    def get_signed_val(val: int, bits: int) -> int:
        if val & (1 << (bits - 1)):
            return val - (1 << bits)
        return val

    # First, try to determine if this operand as a whole acts additively or subtractively
    pos_corr = 0
    neg_corr = 0

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mut_in, mut_out in obs.mutated_ios:
            # isolate the bit slices
            seed_val = (seed_in.state_value >> global_bit_start) & ((1 << bit_len) - 1)
            mut_val = (mut_in.state_value >> global_bit_start) & ((1 << bit_len) - 1)

            # only consider mutations in this slice
            diff = seed_in.diff(mut_in)
            if not diff or not all(global_bit_start <= b < global_bit_start + bit_len for b in diff):
                continue

            seed_out_val = (seed_out.state_value >> out_global_start) & ((1 << out_bit_len) - 1)
            mut_out_val = (mut_out.state_value >> out_global_start) & ((1 << out_bit_len) - 1)

            s_diff = get_signed_val(mut_val, bit_len) - get_signed_val(seed_val, bit_len)
            o_diff = get_signed_val(mut_out_val, out_bit_len) - get_signed_val(seed_out_val, out_bit_len)

            if s_diff > 0 and o_diff > 0:
                pos_corr += 1
            elif s_diff > 0 and o_diff < 0:
                neg_corr += 1
            elif s_diff < 0 and o_diff < 0:
                pos_corr += 1
            elif s_diff < 0 and o_diff > 0:
                neg_corr += 1

    acts_negatively = neg_corr > pos_corr

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

        if is_non_increasing and not is_non_decreasing:
            pass  # 0
        elif is_non_decreasing and not is_non_increasing:
            d_mask |= 1 << local_bit
        else:
            # Monotonicity violated (e.g., transportable cell)
            if not acts_negatively:
                d_mask |= 1 << local_bit

    return d_mask


def _infer_bitwise_gate(  # noqa: C901
    obs_list: list[Observation],
    layout: list[tuple[int, int, str]],
    out_name: str,
    out_min: int,
    in_regs: list[tuple[str, int, int]],
) -> Op | None:
    if len(in_regs) != 2:
        return None
    r1_name, r1_min, r1_max = in_regs[0]
    r2_name, r2_min, r2_max = in_regs[1]

    r1_global = next(start for start, end, name in layout if name == r1_name) + r1_min
    r2_global = next(start for start, end, name in layout if name == r2_name) + r2_min
    out_global = next(start for start, end, name in layout if name == out_name) + out_min

    # Also we need the bit length
    num_bits = min(r1_max - r1_min, r2_max - r2_min)
    if num_bits <= 0:
        return None

    tt = {}

    def update_tt(in_val: int, out_val: int) -> None:
        for bit in range(num_bits):
            b1 = (in_val >> (r1_global + bit)) & 1
            b2 = (in_val >> (r2_global + bit)) & 1
            bo = (out_val >> (out_global + bit)) & 1
            tt[(b1, b2)] = bo

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        update_tt(seed_in.state_value, seed_out.state_value)

        for mut_in, mut_out in obs.mutated_ios:
            update_tt(mut_in.state_value, mut_out.state_value)

        if len(tt) == 4:
            break

    if len(tt) == 4:
        if tt == {(0, 0): 0, (0, 1): 0, (1, 0): 0, (1, 1): 1}:
            return Op.AND
        if tt == {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 1}:
            return Op.OR
        if tt == {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}:
            return Op.XOR

    return None


def _instrument_polarized(  # noqa: C901
    obs_list: list[Observation],
    add_transportability: bool = False,
) -> LogicCircuit:
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

            v_and_not_t = BinaryExpr(Op.AND, V_in, UnaryExpr(Op.NOT, T_in))

            if d_mask == ((1 << local_len) - 1):
                rep1_expr = BinaryExpr(Op.OR, V_in, T_in)
            elif d_mask == 0:
                rep1_expr = v_and_not_t
            else:
                D_const = Constant(d_mask, local_len)
                d_and_t = BinaryExpr(Op.AND, D_const, T_in)
                rep1_expr = BinaryExpr(Op.OR, v_and_not_t, d_and_t)

            not_d_mask = (~d_mask) & ((1 << local_len) - 1)

            if not_d_mask == ((1 << local_len) - 1):
                rep2_expr = BinaryExpr(Op.OR, V_in, T_in)
            elif not_d_mask == 0:
                rep2_expr = v_and_not_t
            else:
                Not_D_const = Constant(not_d_mask, local_len)
                not_d_and_t = BinaryExpr(Op.AND, Not_D_const, T_in)
                rep2_expr = BinaryExpr(Op.OR, v_and_not_t, not_d_and_t)

            cell_inputs_rep1[r_name] = rep1_expr
            cell_inputs_rep2[r_name] = rep2_expr

        in_regs_list = list(in_regs)
        bitwise_op = _infer_bitwise_gate(obs_list, layout, out_name, out_min, in_regs_list)

        # Mathematical shortcut: The polarized circuit for bitwise XOR strictly simplifies to ORing the taints
        if bitwise_op == Op.XOR:
            expr: Expr = dependencies[0]
            for dep in dependencies[1:]:
                expr = BinaryExpr(Op.OR, expr, dep)
            assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=expr))
            continue

        if bitwise_op is not None and len(in_regs_list) == 2:
            r1_name = in_regs_list[0][0]
            r2_name = in_regs_list[1][0]
            C1_bin = BinaryExpr(bitwise_op, cell_inputs_rep1[r1_name], cell_inputs_rep1[r2_name])
            C2_bin = BinaryExpr(bitwise_op, cell_inputs_rep2[r1_name], cell_inputs_rep2[r2_name])
            C1_expr: Expr = C1_bin
            C2_expr: Expr = C2_bin
        else:
            C1_cell = InstructionCellExpr(archstring, bytestring, out_name, out_min, out_max, cell_inputs_rep1)
            C2_cell = InstructionCellExpr(archstring, bytestring, out_name, out_min, out_max, cell_inputs_rep2)
            C1_expr = C1_cell
            C2_expr = C2_cell

        expression: Expr = BinaryExpr(Op.XOR, C1_expr, C2_expr)

        if add_transportability and len(dependencies) >= 1:
            # transport term is the bitwise OR of all dependencies taints
            transport_term: Expr = dependencies[0]
            for dep in dependencies[1:]:
                transport_term = BinaryExpr(Op.OR, transport_term, dep)
            expression = BinaryExpr(Op.OR, expression, transport_term)

        assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=expression))

    return LogicCircuit(
        assignments=assignments,
        architecture=archstring,
        instruction=bytestring,
        state_format=state_format,
    )


def instrument_monotonic(obs_list: list[Observation]) -> LogicCircuit:
    return _instrument_polarized(obs_list, add_transportability=False)


def instrument_transportable(obs_list: list[Observation]) -> LogicCircuit:
    return _instrument_polarized(obs_list, add_transportability=True)


def instrument_instruction(obs_list: list[Observation], category: InstructionCategory) -> LogicCircuit:
    if category == InstructionCategory.MAPPED:
        return instrument_mapped(obs_list)
    if category == InstructionCategory.MONOTONIC:
        return instrument_monotonic(obs_list)
    if category == InstructionCategory.TRANSPORTABLE:
        return instrument_transportable(obs_list)

    if not obs_list:
        raise RuntimeError('No observations provided for instrumentation!')

    archstring = obs_list[0].archstring
    bytestring = obs_list[0].bytestring
    state_format = obs_list[0].state_format

    if category == InstructionCategory.NO_DATA_OUTPUTS:
        return LogicCircuit(assignments=[], architecture=archstring, instruction=bytestring, state_format=state_format)

    # Defaults to a black-box abstract dependency graph representing anything complex
    return LogicCircuit(assignments=[], architecture=archstring, instruction=bytestring, state_format=state_format)
