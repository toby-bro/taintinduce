import json

from taintinduce.classifier.categories import InstructionCategory
from taintinduce.classifier.classifier import get_register_layouts
from taintinduce.instrumentation.instrument import instrument_instruction
from taintinduce.mreplica.mrepica import MReplica
from taintinduce.serialization import TaintInduceDecoder
from taintinduce.state.state import State
from taintinduce.types import StateValue


def dict_to_state(taints: dict[str, int], layout: list[tuple[int, int, str]], num_bits: int) -> State:
    state_val = 0
    for start, end, name in layout:
        if name in taints:
            # mask out to size just in case
            val = taints[name] & ((1 << (end - start)) - 1)
            state_val |= val << start
    return State(num_bits, StateValue(state_val))


def state_to_dict(state: State, layout: list[tuple[int, int, str]]) -> dict[str, int]:
    out = {}
    state_val = state.state_value
    for start, end, name in layout:
        mask = (1 << (end - start)) - 1
        val = (state_val >> start) & mask
        if val != 0:  # only add if non-zero? or all? let's add all
            out[name] = val
    return out


def test_equivalence_21d8_and() -> None:
    with open('output/21d8_X86_obs.json', 'r') as f:
        obs_list = json.load(f, cls=TaintInduceDecoder)

    # 1. Produce the logic circuit logic
    circuit = instrument_instruction(obs_list, InstructionCategory.MONOTONIC)

    # 2. Extract context from the first observation to create an MReplica
    first_obs = obs_list[0]
    mreplica = MReplica(first_obs.bytestring, first_obs.archstring, first_obs.state_format)

    layout = get_register_layouts(first_obs.state_format)
    num_bits = first_obs.seed_io[0].num_bits

    # 3. We create a simulated input taint:
    # Say we taint bits 0 and 3 in EAX, and bit 1 in EBX
    input_taints = {
        'EAX': 0x00000009,
        'EBX': 0x00000002,
        'EFLAGS': 0x0,
    }

    # Let's craft a new seed specifically for EAX and EBX to be 0xFFFFFFFF
    # We will simply overwrite the input state value with 0xFFFFFFFF for both.
    original_seed_io = first_obs.seed_io[0]
    seed_dict = state_to_dict(original_seed_io, layout)
    seed_dict['EAX'] = 0xFFFFFFFF
    seed_dict['EBX'] = 0xFFFFFFFF
    modified_seed = dict_to_state(seed_dict, layout, num_bits)

    # 4. Evaluate logic circuit
    lc_out = circuit.evaluate(input_taints, seed_dict)

    input_state = dict_to_state(input_taints, layout, num_bits)
    mreplica.make_full_m_replica(input_state, reset=True)
    mreplica_out_state = mreplica.simulate(modified_seed)

    mreplica_out_dict = state_to_dict(mreplica_out_state, layout)

    # We really only care about data registers (EAX, EBX)
    # the instrumentation does not output EFLAGS currently.
    assert lc_out.get('EAX', 0) == mreplica_out_dict.get('EAX', 0)
    assert lc_out.get('EBX', 0) == mreplica_out_dict.get('EBX', 0)


def test_equivalence_01d8_add() -> None:
    with open('output/01d8_X86_obs.json', 'r') as f:
        obs_list = json.load(f, cls=TaintInduceDecoder)

    # Currently we might not have 'TRANSPORTABLE' category mapped in instrument_instruction,
    # let's just force MONOTONIC/MAPPED to see what it generates!
    circuit = instrument_instruction(obs_list, InstructionCategory.MONOTONIC)

    first_obs = obs_list[0]
    mreplica = MReplica(first_obs.bytestring, first_obs.archstring, first_obs.state_format)

    layout = get_register_layouts(first_obs.state_format)
    num_bits = first_obs.seed_io[0].num_bits

    input_taints = {
        'EAX': 0x00000009,
        'EBX': 0x00000002,
        'EFLAGS': 0x0,
    }

    lc_out = circuit.evaluate(input_taints)

    original_seed_io = first_obs.seed_io[0]

    # For ADD, if we want maximum propagation (to trigger dependencies), what seed to use?
    # well, actually for addition, any carry can propagate taint.
    # We will test on 0x0 + 0x0, or maybe 1+1 etc. Let's just use 0x0 and 0x0.
    original_seed_io = first_obs.seed_io[0]
    seed_dict = state_to_dict(original_seed_io, layout)
    seed_dict['EAX'] = 0x0
    seed_dict['EBX'] = 0x0
    modified_seed = dict_to_state(seed_dict, layout, num_bits)

    mreplica.make_full_m_replica(dict_to_state(input_taints, layout, num_bits), reset=True)
    mreplica_out_state = mreplica.simulate(modified_seed)

    mreplica_out_dict = state_to_dict(mreplica_out_state, layout)

    print('MREPLICA:', mreplica_out_dict)
    print('LC:', lc_out)
    assert lc_out.get('EAX', 0) == mreplica_out_dict.get('EAX', 0)
