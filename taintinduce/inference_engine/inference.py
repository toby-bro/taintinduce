# Replaced squirrel import with our own
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm

from taintinduce.rules.rules import ConditionDataflowPair, GlobalRule
from taintinduce.state.state import Observation
from taintinduce.types import (
    BitPosition,
    ObservationDependency,
)

from . import observation_processor, partition_handler, unitary_flow_processor, validation

"""Inference engine for data-dependent taint propagation rules.

This module infers taint propagation rules with conditions from observations.
It supports two types of conditions:

1. Control-flow dependent (legacy mode, use_full_state=False):
   - Conditions based only on FLAGS/NZCV register
   - Example: CMOV propagates taint only if ZF=0

2. Data-dependent (generalized mode, use_full_state=True):
   - Conditions based on any input register values
   - Example: AND eax,ebx propagates no taint if ebx=0
   - Example: SHL eax,cl propagates no taint if cl=0
   - Example: IMUL with small operands may not affect high bits

The algorithm uses ESPRESSO logic minimizer to find boolean formulas that
separate different taint propagation behaviors based on input state.
"""

logger = logging.getLogger(__name__)


def infer(
    observations: list[Observation],
) -> GlobalRule:
    """Infers the dataflow of the instruction using the obesrvations.

    Args:
        observations ([Observation]): List of observations to infer on.
        cond_reg: Condition register (EFLAGS for X86/AMD64, NZCV for ARM64/JN)
        observation_engine: Optional ObservationEngine for refinement pass
        enable_refinement: Whether to perform refinement pass with targeted observations
    Returns:
        A Rule object with inferred dataflows and conditions
    Raises:
        None
    """

    if len(observations) == 0:
        raise Exception('No observations to infer from!')

    # zl: we have the state_format in observation, assert that all observations in obs_list have the same state_format
    state_format = observations[0].state_format
    if state_format is None:
        raise Exception('State format is None!')
    assert all(obs.state_format == state_format for obs in observations)

    observation_dependencies = observation_processor.extract_observation_dependencies(observations)
    per_bit_conditions = infer_flow_conditions(
        observation_dependencies,
    )

    if len(per_bit_conditions) == 0:
        raise Exception('No conditions inferred!')

    # Build list of ConditionDataflowPair objects from unitary flow conditions
    # Each condition applies only to the specific input bits it was generated for

    rule = GlobalRule(state_format, pairs=[pair for pairs in per_bit_conditions.values() for pair in pairs])

    # Validate that the generated rule explains all observations
    explained, total = validation.validate_rule_explains_observations(rule, observation_dependencies)

    if explained < total:
        print(
            f'Rule validation incomplete: {explained}/{total} behaviors explained '
            f'({explained/total*100:.1f}%). Some observations may not be fully captured by conditions.',
        )
    else:
        print(f'Rule validation successful: all {total} observation behaviors explained.')

    return rule


def infer_flow_conditions(
    observation_dependencies: list[ObservationDependency],
) -> dict[BitPosition, list[ConditionDataflowPair]]:
    """Infer conditions for dataflows for each input bit independently.

    Returns:
        Dictionary mapping each input bit to its list of ConditionDataflowPair objects.
        Each input bit's conditions are kept separate to avoid incorrectly applying
        conditions from one bit to another.
    """

    # Group flows by OUTPUT bit to get input dependencies for each output
    output_to_inputs = unitary_flow_processor.group_unitary_flows_by_output(observation_dependencies)

    # Also track input to outputs for possible_flows (needed for subset detection)
    # possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
    # for observation in observation_dependencies:
    #     for mutated_input_bit, modified_output_bits in observation.dataflow.items():
    #         possible_flows[mutated_input_bit].add(modified_output_bits)

    # Store conditions per input bit
    per_bit_conditions: dict[BitPosition, list[ConditionDataflowPair]] = {}

    # Sort OUTPUT bits by their input dependency count (fewest dependencies first)
    sorted_output_bits = sorted(
        output_to_inputs.keys(),
        key=lambda bit: len(output_to_inputs[bit]),
    )
    logger.debug(f'Processing {len(sorted_output_bits)} output bits in order of input dependency count')

    completed_outputs: set[BitPosition] = set()
    all_conditions: list[ConditionDataflowPair] = []

    # Process OUTPUT bits in WAVES based on subset dependencies (parallel within each wave)
    logger.debug(f'Processing {len(sorted_output_bits)} output bits in dependency-aware waves')

    remaining_output_bits = set(sorted_output_bits)
    wave_number = 0

    with tqdm(total=len(sorted_output_bits), desc='Inferring flow conditions', unit='output') as pbar:
        while remaining_output_bits:
            wave_number += 1

            # Identify output bits ready for this wave (all subset dependencies satisfied)
            ready_output_bits = _identify_ready_output_bits_by_subset_dependency(
                remaining_output_bits,
                output_to_inputs,
            )

            if not ready_output_bits:
                logger.error(f'Deadlock: {len(remaining_output_bits)} output bits remain but none are ready')
                logger.error(f'Remaining output bits: {remaining_output_bits}')
                raise Exception('Circular dependency detected in output_bit_refs')

            logger.debug(f'Wave {wave_number}: processing {len(ready_output_bits)} output bits in parallel')

            # Process this wave in parallel, collect results WITHOUT modifying shared state
            wave_results = _process_output_wave_parallel(
                ready_output_bits,
                output_to_inputs,
                frozenset(completed_outputs),
                observation_dependencies,
                all_conditions,
            )

            # NOW update shared state with all results from this wave (thread-safe)
            for output_bit, conditionalFlows in wave_results.items():
                completed_outputs.add(output_bit)
                all_conditions.extend(conditionalFlows)
                for pair in conditionalFlows:
                    if pair.input_bit not in per_bit_conditions:
                        per_bit_conditions[pair.input_bit] = []
                    per_bit_conditions[pair.input_bit].append(pair)

            remaining_output_bits -= ready_output_bits
            pbar.update(len(ready_output_bits))

    logger.debug(f'Completed processing in {wave_number} waves')

    return per_bit_conditions


def _identify_ready_output_bits_by_subset_dependency(
    remaining_output_bits: set[BitPosition],
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
) -> set[BitPosition]:
    """Identify output bits ready for processing based on subset dependencies.

    An output bit is ready when all other outputs with FEWER input dependencies are complete.
    """
    ready: set[BitPosition] = set()

    for output_bit in remaining_output_bits:
        input_bits = output_to_inputs[output_bit]

        # Check if any other remaining output has fewer inputs (subset dependency)
        has_blocking_subset = False
        for other_output in remaining_output_bits:
            if other_output == output_bit:
                continue
            other_inputs = output_to_inputs[other_output]
            # If another output has inputs that are a PROPER SUBSET of ours, wait
            if other_inputs and input_bits and other_inputs < input_bits:
                has_blocking_subset = True
                break

        if not has_blocking_subset:
            ready.add(output_bit)

    # If nothing is ready, return outputs with minimal input count to bootstrap
    if not ready and remaining_output_bits:
        min_size = min(len(output_to_inputs[bit]) for bit in remaining_output_bits)
        ready = {bit for bit in remaining_output_bits if len(output_to_inputs[bit]) == min_size}

    return ready


def _process_output_wave_parallel(
    ready_output_bits: set[BitPosition],
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    completed_outputs: frozenset[BitPosition],
    observation_dependencies: list[ObservationDependency],
    all_conditions: list[ConditionDataflowPair],
) -> dict[BitPosition, list[ConditionDataflowPair]]:
    """Process a wave of output bits in parallel.

    Returns:
        Dict mapping output_bit -> [ConditionDataflowPair]
    """

    def process_single_output(
        output_bit: BitPosition,
    ) -> tuple[BitPosition, list[ConditionDataflowPair]]:
        input_bits_for_output = output_to_inputs[output_bit]
        results_for_output: list[ConditionDataflowPair] = []

        for input_bit in input_bits_for_output:
            pair = partition_handler.handle_multiple_partitions_output_centric(
                input_bit,
                output_bit,
                output_to_inputs,
                completed_outputs,
                observation_dependencies,
                all_conditions,
            )

            results_for_output.append(pair)

        return output_bit, results_for_output

    wave_results: dict[BitPosition, list[ConditionDataflowPair]] = {}
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_single_output, ob): ob for ob in ready_output_bits}
        for future in as_completed(futures):
            output_bit, results = future.result()
            wave_results[output_bit] = results

    return wave_results
