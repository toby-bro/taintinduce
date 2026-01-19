"""Observation processing utilities for inference engine."""
import logging
from collections import defaultdict

from taintinduce.state.state import Observation, State
from taintinduce.types import (
    BitPosition,
    Dataflow,
    MutatedInputStates,
    ObservationDependency,
)

logger = logging.getLogger(__name__)


def extract_observation_dependencies(
    observations: list[Observation],
) -> list[ObservationDependency]:
    """Extracts the bit that are flipped in each response to a bit flip in the input."""
    obs_deps: list[ObservationDependency] = []
    for observation in observations:
        # single_obs_dep contains the dependency for a single observation
        obs_dep = Dataflow()
        obs_mutate_in = MutatedInputStates()
        seed_in, seed_out = observation.seed_io
        for mutate_in, mutate_out in observation.mutated_ios:
            bitflip_pos = next(iter(seed_in.diff(mutate_in)))
            if len(seed_in.diff(mutate_in)) != 1:
                raise Exception('More than one bit flipped in mutated input state!')
            bitchanges_pos = seed_out.diff(mutate_out)
            obs_dep[bitflip_pos] = bitchanges_pos
            obs_mutate_in[bitflip_pos] = mutate_in
        obs_deps.append(
            ObservationDependency(dataflow=obs_dep, mutated_inputs=obs_mutate_in, original_output=seed_in),
        )
    return obs_deps


def link_affected_outputs_to_their_input_states(
    observation_dependencies: list[ObservationDependency],
    mutated_input_bit: BitPosition,
) -> dict[frozenset[BitPosition], set[State]]:
    """Get a dictionary mapping modified output bits to their input states IF the given input bit was mutated."""
    partitions: defaultdict[frozenset[BitPosition], set[State]] = defaultdict(set)

    # for each observation, get the dep behavior, and add the seed to it
    for observation in observation_dependencies:
        dataflow = observation.dataflow
        mutated_input_states = observation.mutated_inputs
        if mutated_input_bit in dataflow.inputs() and mutated_input_bit in mutated_input_states.mutated_bits():
            partitions[dataflow.get_modified_outputs(mutated_input_bit)].add(
                mutated_input_states.get_input_state(mutated_input_bit),
            )

    return partitions
