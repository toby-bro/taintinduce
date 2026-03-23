from taintinduce.sleigh.lifter import get_context, lift_instruction
from taintinduce.sleigh.mapper import determine_category
from taintinduce.sleigh.polarity import compute_polarity
from taintinduce.sleigh.slicer import _get_varnode_id, slice_backward


def generate_static_rule(arch: str, bytestring: bytes) -> dict[str, str | dict[str, dict[str, str | dict[str, int]]]]:
    """
    Statically analyzes an instruction using SLEIGH and generates
    the inferred dependencies, cell category, and D-vectors.
    """
    ctx = get_context(arch)
    translation = lift_instruction(arch, bytestring)

    # Identify outputs by looking at the written varnodes
    # In P-Code, an instruction writes to temp vars and real registers.
    # We only care about exposed CPU registers (or memory).
    outputs = []

    # Simple pass: find all operations that write to a registered CPU state
    # To keep it simple, we check any write to the 'register' space
    for op in translation.ops:
        if op.output and op.output.space.name == 'register':
            outputs.append(op.output)

    # De-duplicate outputs (some instructions might write to the same reg multiple times)
    unique_outputs = {_get_varnode_id(out): out for out in outputs}.values()

    outputs_dict: dict[str, dict[str, str | dict[str, int]]] = {}
    results: dict[str, str | dict[str, dict[str, str | dict[str, int]]]] = {
        'isa': arch,
        'bytecode': bytestring.hex(),
        'instruction': '',
        'outputs': outputs_dict,
    }

    for out_vn in unique_outputs:
        reg_lst = [n for n, r in ctx.registers.items() if r.offset == out_vn.offset and r.size == out_vn.size]
        out_name = reg_lst[0] if reg_lst else _get_varnode_id(out_vn)
        # 1. Slice backward to find all ops contributing to this output
        slice_ops = slice_backward(translation.ops, out_vn)

        # 2. Determine CellIFT Category
        cat = determine_category(slice_ops)

        # 3. Determine D-Vectors
        polarities = compute_polarity(slice_ops)

        # 4. Resolve dependencies to human-readable names
        deps = {}
        for vn_id, p in polarities.items():
            parts = vn_id.split(':')
            if len(parts) != 3:
                continue
            space, offset, size = parts

            # Map dependency input back to a register name if it is one
            if space == 'register':
                dep_reg_lst = [n for n, r in ctx.registers.items() if r.offset == int(offset) and r.size == int(size)]
                dep_name = dep_reg_lst[0] if dep_reg_lst else vn_id
                deps[dep_name] = p

        outputs_dict[out_name] = {
            'category': str(cat),
            'dependencies': deps,
        }

    return results
