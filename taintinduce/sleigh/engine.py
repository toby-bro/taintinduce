import pypcode

from taintinduce.classifier.categories import InstructionCategory
from taintinduce.instrumentation.ast import (
    BinaryExpr,
    Expr,
    InstructionCellExpr,
    LogicCircuit,
    Op,
    TaintAssignment,
    TaintOperand,
    UnaryExpr,
)
from taintinduce.isa.register import Register
from taintinduce.sleigh.lifter import get_context, lift_instruction
from taintinduce.sleigh.mapper import determine_category
from taintinduce.sleigh.polarity import compute_polarity
from taintinduce.sleigh.slicer import _get_varnode_id, slice_backward
from taintinduce.types import Architecture


def _map_sleigh_to_state(ctx: pypcode.Context, arch: str, state_format: list[Register], offset: int, size: int) -> tuple[str, int, int] | None:  # noqa: E501
    # Handle X86 flags abstract offsets (512-540)
    if 'X86' in arch.upper() and 512 <= offset < 550:
        for sf_reg in state_format:
            if 'FLAGS' in sf_reg.name.upper():
                bit_idx = offset - 512
                # Flags are mapped as 1-bit internally despite Sleigh giving them size=1 (byte)
                return sf_reg.name, bit_idx, bit_idx

    for sf_reg in state_format:
        s_r = ctx.registers.get(sf_reg.name) or ctx.registers.get(sf_reg.name.lower())
        if not s_r:
            continue

        # Check if the requested register falls within this state_format register
        if s_r.offset <= offset and (offset + size) <= (s_r.offset + s_r.size):
            rel_byte = offset - s_r.offset
            bit_start = rel_byte * 8
            bit_end = bit_start + (size * 8) - 1
            return sf_reg.name, bit_start, bit_end

    return None


def generate_static_rule(arch: Architecture, bytestring: bytes, state_format: list[Register]) -> LogicCircuit:  # noqa: C901
    """
    Statically analyzes an instruction using SLEIGH and generates
    the inferred logic circuit with D-vectors.
    """
    ctx = get_context(arch)
    translation = lift_instruction(arch, bytestring)

    outputs = []
    for op in translation.ops:
        if op.output and op.output.space.name == 'register':
            outputs.append(op.output)

    unique_outputs = {_get_varnode_id(out): out for out in outputs}.values()

    assignments: list[TaintAssignment] = []

    for out_vn in unique_outputs:
        mapped_out = _map_sleigh_to_state(ctx, arch, state_format, out_vn.offset, out_vn.size)
        if not mapped_out:
            continue
        out_name, out_bit_start, out_bit_end = mapped_out

        slice_ops = slice_backward(translation.ops, out_vn)
        cat = determine_category(slice_ops)
        polarities = compute_polarity(slice_ops)

        deps: dict[tuple[str, int, int], int] = {}
        for vn_id, p in polarities.items():
            parts = vn_id.split(':')
            if len(parts) != 3:
                continue
            space, st_offset, st_size = parts
            if space == 'register':
                mapped_dep = _map_sleigh_to_state(ctx, arch, state_format, int(st_offset), int(st_size))
                if mapped_dep:
                    deps[mapped_dep] = p

        if not deps:
            continue

        target = TaintOperand(out_name, out_bit_start, out_bit_end, is_taint=True)
        dependencies = []
        cell_inputs_rep1: dict[str, Expr] = {}
        cell_inputs_rep2: dict[str, Expr] = {}

        for (dep_name, r_min, r_max), p in deps.items():
            T_in = TaintOperand(dep_name, r_min, r_max, is_taint=True)
            V_in = TaintOperand(dep_name, r_min, r_max, is_taint=False)
            dependencies.append(T_in)

            v_and_not_t = BinaryExpr(Op.AND, V_in, UnaryExpr(Op.NOT, T_in))

            if p == 1:
                rep1_expr = BinaryExpr(Op.OR, V_in, T_in)
                rep2_expr = v_and_not_t
            else:
                rep1_expr = v_and_not_t
                rep2_expr = BinaryExpr(Op.OR, V_in, T_in)

            # In Cell inputs we just use the name if it is disjoint, but here multiple pieces of same reg could be used
            # We assume disjoint parent registers mapping for cell formulas simplification
            cell_inputs_rep1[dep_name] = rep1_expr
            cell_inputs_rep2[dep_name] = rep2_expr

        if cat == InstructionCategory.MAPPED:
            expr: Expr = dependencies[0]
            for dep in dependencies[1:]:
                expr = BinaryExpr(Op.OR, expr, dep)
            assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=expr))

        elif cat == InstructionCategory.TRANSPORTABLE:
            C1_cell = InstructionCellExpr(arch, bytestring.hex(), out_name, out_bit_start, out_bit_end, cell_inputs_rep1)  # noqa: E501
            C2_cell = InstructionCellExpr(arch, bytestring.hex(), out_name, out_bit_start, out_bit_end, cell_inputs_rep2)  # noqa: E501

            expression: Expr = BinaryExpr(Op.XOR, C1_cell, C2_cell)

            transport_term: Expr = dependencies[0]
            for dep in dependencies[1:]:
                transport_term = BinaryExpr(Op.OR, transport_term, dep)

            expression = BinaryExpr(Op.OR, expression, transport_term)

            assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=expression))
        else:
            in_dict: dict[str, Expr] = {d.name: d for d in dependencies}
            C_cell = InstructionCellExpr(arch, bytestring.hex(), out_name, out_bit_start, out_bit_end, in_dict)
            assignments.append(TaintAssignment(target=target, dependencies=dependencies, expression=C_cell))

    return LogicCircuit(assignments=assignments, architecture=arch, instruction=bytestring.hex(), state_format=state_format)  # noqa: E501
