# Replaced squirrel import with our own
import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from taintinduce.observation_engine.observation import ObservationEngine

from taintinduce.isa.arm64_registers import ARM64_REG_NZCV
from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_EFLAGS
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair, Rule
from taintinduce.state.state import Observation, State
from taintinduce.types import (
    BitPosition,
    Dataflow,
    DataflowSet,
    ObservationDependency,
)

from . import condition_generator, observation_processor, partition_handler, validation

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

logging.basicConfig(format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class InferenceEngine(object):
    def __init__(self) -> None:
        self.condition_generator = condition_generator.ConditionGenerator()

    def _build_full_dataflows(
        self,
        condition_groups: list[tuple[list[ConditionDataflowPair], DataflowSet]],
    ) -> list[ConditionDataflowPair]:
        """Build list of ConditionDataflowPair objects with full dataflows."""
        condition_dataflow_pairs_full: list[ConditionDataflowPair] = []

        for ordered_pairs, use_bit_dataflows in condition_groups:
            # Use the ordered pairs that were already inferred (from a representative input bit)
            # Build full dataflows for each condition in this group
            for pair in ordered_pairs:
                dataflow = Dataflow()
                # For each input bit in this condition group, collect outputs
                for use_bit, output_sets in use_bit_dataflows.items():
                    if output_sets:
                        all_outputs: set[BitPosition] = set()
                        for output_set in output_sets:
                            all_outputs.update(output_set)
                        dataflow[use_bit] = frozenset(all_outputs)

                # Create a new pair with the full dataflow
                # Use empty condition if condition is None
                condition = pair.condition if pair.condition is not None else TaintCondition(LogicType.DNF, frozenset())

                # Log 1-to-many flows with no condition or empty condition
                is_empty_condition = pair.condition is None or (
                    pair.condition.condition_ops is not None and len(pair.condition.condition_ops) == 0
                )
                if is_empty_condition:
                    for input_bit, output_bits in dataflow.items():
                        if len(output_bits) > 1:
                            logger.warning(
                                f'No condition for input bit {input_bit} -> '
                                f'{len(output_bits)} output bits (full dataflow)',
                            )

                condition_dataflow_pairs_full.append(
                    ConditionDataflowPair(condition=condition, output_bits=dataflow),
                )

        return condition_dataflow_pairs_full

    def infer(
        self,
        observations: list[Observation],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        observation_engine: Optional['ObservationEngine'] = None,
        enable_refinement: bool = False,
    ) -> Rule:
        """Infers the dataflow of the instruction using the obesrvations.

        Args:
            observations ([Observation]): List of observations to infer on.
            cond_reg: Condition register (EFLAGS or NZCV)
            observation_engine: Optional ObservationEngine for refinement pass
            enable_refinement: Whether to perform refinement pass with targeted observations
        Returns:
            A Rule object with inferred dataflows and conditions
        Raises:
            None
        """

        if len(observations) == 0:
            raise Exception('No observations to infer from!')

        # zl: we have the state_format in observation, assert that all observations in obs_list have the same state_format  # noqa: E501
        state_format = observations[0].state_format
        if state_format is None:
            raise Exception('State format is None!')
        assert all(obs.state_format == state_format for obs in observations)

        condition_groups = self.infer_flow_conditions(
            observations,
            cond_reg,
            state_format,
            enable_refinement=enable_refinement,
            observation_engine=observation_engine,
        )

        if len(condition_groups) == 0:
            raise Exception('No conditions inferred!')

        # Build list of ConditionDataflowPair objects with full dataflows
        # Process ALL condition groups using the stored pairs
        condition_dataflow_pairs_full = self._build_full_dataflows(condition_groups)

        rule = Rule(state_format, pairs=condition_dataflow_pairs_full)

        # Validate that the generated rule explains all observations
        observation_dependencies = observation_processor.extract_observation_dependencies(observations)
        explained, total = validation.validate_rule_explains_observations(rule, observation_dependencies)

        if explained < total:
            logger.warning(
                f'Rule validation incomplete: {explained}/{total} behaviors explained '
                f'({explained/total*100:.1f}%). Some observations may not be fully captured by conditions.',
            )
        else:
            logger.info(f'Rule validation successful: all {total} observation behaviors explained.')

        return rule

    def infer_flow_conditions(
        self,
        observations: list[Observation],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        state_format: list[Register],
        enable_refinement: bool = False,
        observation_engine: Optional['ObservationEngine'] = None,
    ) -> list[tuple[list[ConditionDataflowPair], DataflowSet]]:
        """Infer conditions for dataflows and group by condition pattern.

        Returns:
            List of tuples (ordered_pairs, input_bit_dataflows).
            Each tuple represents a group of input bits with the same condition pattern.
            The ordered_pairs are from a representative input bit in that group.
            The input_bit_dataflows maps each input bit to its output sets.
        """

        observation_dependencies = observation_processor.extract_observation_dependencies(observations)

        # iterate through all the dependencies from the observations and identify what are the possible flows
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
        for observation in observation_dependencies:
            for mutated_input_bit, modified_output_bits in observation.dataflow.items():
                possible_flows[mutated_input_bit].add(modified_output_bits)

        # List of condition groups - each group contains input bits with the same condition pattern
        # Each entry: (ordered_pairs from representative input bit, dataflow_set for all input bits in group)
        condition_groups: list[tuple[list[ConditionDataflowPair], DataflowSet]] = []

        # Parallelize condition inference across input bits
        max_workers = os.cpu_count() or 1
        logger.debug(f'Using {max_workers} workers for parallel condition inference')

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_bit = {
                executor.submit(
                    self.infer_conditions_for_dataflows,
                    cond_reg,
                    state_format,
                    observation_dependencies,
                    possible_flows,
                    mutated_input_bit,
                    enable_refinement,
                    observation_engine,
                    observations,
                ): mutated_input_bit
                for mutated_input_bit in possible_flows
            }

            # Collect results as they complete
            for future in as_completed(future_to_bit):
                mutated_input_bit = future_to_bit[future]
                try:
                    condition_dataflow_pairs = future.result()

                    # Find existing group with matching condition pattern
                    condition_set = frozenset(pair.condition for pair in condition_dataflow_pairs)
                    matching_group = None
                    for ordered_pairs, dataflow_set in condition_groups:
                        existing_condition_set = frozenset(pair.condition for pair in ordered_pairs)
                        if condition_set == existing_condition_set:
                            matching_group = (ordered_pairs, dataflow_set)
                            break

                    if matching_group is None:
                        # First time seeing this condition pattern - create new group
                        matching_group = (condition_dataflow_pairs, DataflowSet())
                        condition_groups.append(matching_group)

                    # Add this input bit's dataflows to the group
                    _, dataflow_set = matching_group
                    output_sets: set[frozenset[BitPosition]] = {pair.output_bits for pair in condition_dataflow_pairs}  # type: ignore[misc]
                    old_sets: set[frozenset[BitPosition]] = dataflow_set.get(mutated_input_bit, set())
                    dataflow_set[mutated_input_bit] = old_sets.union(output_sets)
                except Exception as e:
                    logger.error(f'Failed to infer conditions for bit {mutated_input_bit}: {e}')
                    raise

        return condition_groups

    def _handle_single_partition(
        self,
        mutated_input_bit: BitPosition,
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
    ) -> list[ConditionDataflowPair]:
        """Handle case with single partition (no conditional dataflow)."""
        return partition_handler.handle_single_partition(mutated_input_bit, possible_flows)

    def _process_output_partition(
        self,
        output_set: frozenset[BitPosition],
        partitions: dict[frozenset[BitPosition], set[State]],
        state_format: list[Register],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        mutated_input_bit: BitPosition,
        enable_refinement: bool,
        observation_engine: Optional['ObservationEngine'],
        all_observations: Optional[list[Observation]],
    ) -> tuple[Optional[TaintCondition], frozenset[BitPosition]]:
        """Process a single output partition and infer its condition."""
        return partition_handler.process_output_partition(
            output_set,
            partitions,
            state_format,
            cond_reg,
            mutated_input_bit,
            enable_refinement,
            observation_engine,
            all_observations,
        )

    def _handle_multiple_partitions(
        self,
        mutated_input_bit: BitPosition,
        observation_dependencies: list[ObservationDependency],
        state_format: list[Register],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        enable_refinement: bool,
        observation_engine: Optional['ObservationEngine'],
        all_observations: Optional[list[Observation]],
    ) -> list[ConditionDataflowPair]:
        """Handle case with multiple partitions (conditional dataflow)."""
        return partition_handler.handle_multiple_partitions(
            mutated_input_bit,
            observation_dependencies,
            state_format,
            cond_reg,
            enable_refinement,
            observation_engine,
            all_observations,
        )

    def infer_conditions_for_dataflows(
        self,
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        state_format: list[Register],
        observation_dependencies: list[ObservationDependency],
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
        mutated_input_bit: BitPosition,
        enable_refinement: bool = False,
        observation_engine: Optional['ObservationEngine'] = None,
        all_observations: Optional[list[Observation]] = None,
    ) -> list[ConditionDataflowPair]:
        """Infer conditions and their associated dataflows for a mutated input bit.

        Returns:
            List of ConditionDataflowPair objects, each pairing a condition with its output bits.
            condition=None represents the default/fallthrough case.
        """
        logger.info(f'Searching flow conditions for input bit {mutated_input_bit}')

        num_partitions = len(possible_flows[mutated_input_bit])
        if num_partitions == 0:
            raise Exception(f'No possible flows for mutated input bit {mutated_input_bit}')

        # ZL: TODO: Hack for cond_reg, do a check if state_format contains the cond_reg, if no, then skip condition inference  # noqa: E501
        if num_partitions == 1:
            # no conditional dataflow - single behavior for all inputs
            return self._handle_single_partition(mutated_input_bit, possible_flows)

        return self._handle_multiple_partitions(
            mutated_input_bit,
            observation_dependencies,
            state_format,
            cond_reg,
            enable_refinement,
            observation_engine,
            all_observations,
        )
