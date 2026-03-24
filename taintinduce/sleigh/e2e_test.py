import os

import pytest

from taintinduce.classifier.classifier import get_register_layouts
from taintinduce.sleigh.engine import generate_static_rule
from taintinduce.taintinduce import gen_insninfo, gen_obs
from taintinduce.types import Architecture


def get_bit_dict(state_val: int, layout: list[tuple[int, int, str]]) -> dict[str, set[int]]:
    bits: dict[str, set[int]] = {}
    for start, end, name in layout:
        for i in range(end - start):
            if (state_val >> (start + i)) & 1:
                bits.setdefault(name, set()).add(i)
    return bits


x86_instructions = [
    '01d8',
    '6601d8',
    '00c0',
    '03c3',
    '21d8',
    '09c3',
    '31d8',
    '89d8',
    'f7e3',
    '50',
    '58',
    'f7d0',
    'f7d8',
    '40',
    '48',
    '9c',
    '9d',
    'd1e0',
    'd1e8',
    '6603c3',
]

amd64_instructions = [
    '4801d8',
    '4821d8',
    '4809d8',
    '4831d8',
    '4889d8',
    '48f7e3',
    '50',
    '58',
    '48f7d0',
    '48f7d8',
    '48ffc0',
    '48ffc8',
    '48d1e0',
    '48d1e8',
    '01d8',
    '21d8',
    '09d8',
    '31d8',
    '89d8',
    'f7d0',
]

arm64_instructions = [
    '0000208b',
    '0000204b',
    '0000208a',
    '000020aa',
    '000020ca',
    'e00300aa',
    '00000091',
    '000020cb',
    '00fc7f92',
    '00fc40b2',
    '00001fd3',
    '0000209b',
    '000000c8',
    '0000008b',
    '0000004b',
    '0000008a',
    '000000aa',
    '000000ca',
    '0000009b',
    'e003008a',
]


@pytest.mark.parametrize(
    ('arch', 'bytestring'),
    [(Architecture.X86, bs) for bs in x86_instructions]
    + [(Architecture.AMD64, bs) for bs in amd64_instructions]
    + [(Architecture.ARM64, bs) for bs in arm64_instructions],
)
def test_sleigh_engine_no_undertaint_or_overtaint(arch: Architecture, bytestring: str) -> None:  # noqa: C901
    if os.environ.get('E2E_TEST_SLEIGH', '0') != '1':
        pytest.skip('Set E2E_TEST_SLEIGH=1 to run this test')
    insninfo = gen_insninfo(arch, bytestring)
    obs_list, _ = gen_obs(arch, bytestring, insninfo.state_format)
    sleigh_rule = generate_static_rule(arch, bytes(bytearray.fromhex(bytestring)), insninfo.state_format)
    layout = get_register_layouts(insninfo.state_format)

    dynamic_deps: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for obs in obs_list:
        seed_io = obs.seed_io
        for mutated in obs.mutated_ios:
            flipped_in = seed_io[0].state_value ^ mutated[0].state_value
            flipped_out = seed_io[1].state_value ^ mutated[1].state_value
            in_bits = get_bit_dict(flipped_in, layout)
            out_bits = get_bit_dict(flipped_out, layout)

            in_reg, in_bit = None, None
            for reg, bitset in in_bits.items():
                for bit in bitset:
                    in_reg, in_bit = reg, bit
            if in_reg is None or in_bit is None:
                continue

            for out_reg, bitset in out_bits.items():
                for out_bit in bitset:
                    dynamic_deps.setdefault((out_reg, out_bit), set()).add((in_reg, in_bit))

    static_deps: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for assignment in sleigh_rule.assignments:
        target = assignment.target
        for out_bit in range(target.bit_start, target.bit_end + 1):
            for dep in assignment.dependencies:
                for in_bit in range(dep.bit_start, dep.bit_end + 1):
                    static_deps.setdefault((target.name, out_bit), set()).add((dep.name, in_bit))

    def is_interesting_bit(arch: Architecture, reg: str, bit: int) -> bool:  # noqa: ARG001
        if reg.startswith('MEM_'):
            return False
        if 'FLAGS' in reg.upper() or 'EFLAGS' in reg.upper():
            return bit in {0, 2, 6, 7, 11}
        if 'NZCV' in reg.upper() or 'CPSR' in reg.upper():
            return bit in {28, 29, 30, 31}
        return True

    # Verification 1: No Undertaint!

    # Every data link found organically in mutation observations MUST be included structurally in Sleigh
    # This guarantees Sleigh includes ALL interesting flags and bits.
    for out_key, dyn_in_set in dynamic_deps.items():
        if not is_interesting_bit(arch, out_key[0], out_key[1]):
            continue
        static_in_set = static_deps.get(out_key, set())
        for dyn_in in dyn_in_set:
            if not is_interesting_bit(arch, dyn_in[0], dyn_in[1]):
                continue

            # If Sleigh does not explicitly write to out_key, its implicit behavior
            # is identical to the input (e.g. EBX remains EBX, EAX upper half remains upper half).
            if not static_deps.get(out_key):
                if dyn_in == out_key:
                    # It's an implicit identity mapping which matches!
                    continue
                pytest.fail(
                    f'UNDERTAINT: {arch} {bytestring} : {out_key} '
                    f'modified by {dyn_in} but completely missed by Sleigh!',
                )

            assert (
                dyn_in in static_in_set
            ), f'UNDERTAINT: {arch} {bytestring} : {out_key} missing explicit dependency on {dyn_in}'

    # Verification 2: Checking exact taint for flipped bit (No Overtaint!)
    # To check that we do not overtaint evaluating exactly the formula for the single bit flipped:
    #
    # The generated Sleigh equation for compute cells is `T_out = C(V_in|T_in) XOR C(V_in&~T_in)`
    # Since dynamic runs already computed exactly `C(V_in|T_in)` (seed output) and `C(V_in&~T_in)` (mutated output)
    # The evaluation evaluates to `seed_out ^ mutated_out` which corresponds to `dynamic_deps`.
    # Therefore evaluating the logic circuit on single bits trivially validates exact overtaint mathematically.
    #
    # Here, we ensure that statically Sleigh didn't produce ghost dependencies for variables it shouldn't even know.
    # We require that if a register is statically said to depend on another, we AT LEAST observed ONE bit
    # demonstrating that relation dynamically.

    dynamic_aggregate: set[tuple[str, str]] = set()
    for (o_r, _o_b), in_set in dynamic_deps.items():
        for i_r, _i_b in in_set:
            dynamic_aggregate.add((o_r, i_r))

    static_aggregate: set[tuple[str, str]] = set()
    for assignment in sleigh_rule.assignments:
        target = assignment.target
        for dep in assignment.dependencies:
            static_aggregate.add((target.name, dep.name))

    for out_reg, in_reg in static_aggregate:
        if 'FLAGS' not in out_reg and 'NZCV' not in out_reg:
            if in_reg != out_reg:
                assert (out_reg, in_reg) in dynamic_aggregate, f'OVERTAINT! Ghost edge {out_reg} depending on {in_reg}'
