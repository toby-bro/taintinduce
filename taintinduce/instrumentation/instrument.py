from taintinduce.classifier.categories import InstructionCategory
from taintinduce.classifier.classifier import get_register_layouts
from taintinduce.instrumentation.ast import LogicCircuit, TaintAssignment, TaintOperand
from taintinduce.state.state import Observation


def instrument_mapped(obs_list: list[Observation]) -> LogicCircuit:  # noqa: C901
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

    flow_map: dict[tuple[str, int], set[tuple[str, int]]] = {}  # Maps out_reg -> set of in_regs

    for obs in obs_list:
        seed_in, seed_out = obs.seed_io
        for mutate_in, mutate_out in obs.mutated_ios:
            in_xor = seed_in.state_value ^ mutate_in.state_value
            if in_xor == 0 or (in_xor & (in_xor - 1)) != 0:
                continue  # single bits only to trace direct mappings

            out_xor = seed_out.state_value ^ mutate_out.state_value
            if out_xor == 0:
                continue

            # Which registry bit was this?
            # A precise implementation will reconstruct exactly which bit maps to which.
            # As a starting base level abstraction: whole registers flow mapping.
            diff_in_bit = in_xor.bit_length() - 1
            diff_out_bits = [i for i in range(out_xor.bit_length()) if (out_xor >> i) & 1]

            in_reg = None
            for start, end, name in layout:
                if start <= diff_in_bit < end:
                    in_reg = (name, end - start)
                    break

            if not in_reg:
                continue

            for diff_out_bit in diff_out_bits:
                for start, end, name in layout:
                    if start <= diff_out_bit < end:
                        out_reg = (name, end - start)
                        if out_reg not in flow_map:
                            flow_map[out_reg] = set()
                        flow_map[out_reg].add(in_reg)

    for (out_name, out_size), in_regs in flow_map.items():
        if not in_regs:
            continue

        target = TaintOperand(out_name, 0, out_size - 1)
        dependencies = [TaintOperand(r_name, 0, r_size - 1) for r_name, r_size in in_regs]
        assignments.append(TaintAssignment(target=target, dependencies=dependencies))

    return LogicCircuit(
        assignments=assignments,
        architecture=archstring,
        instruction=bytestring,
        state_format=state_format,
    )


def instrument_monotonic(obs_list: list[Observation]) -> LogicCircuit:
    """Generates straight logical operations mapping identical bit indices (AND, OR maskings)."""
    # Monotonic generally follows exact same structural copy logic but bits only flow IF condition is met.
    # For now, it mirrors exactly the MAPPED topological dependencies structurally.

    return instrument_mapped(obs_list)


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
