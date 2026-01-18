# Replaced squirrel import with our own
import logging
import os

# Replaced squirrel import with our own
import pdb
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from taintinduce.observation_engine.observation import ObservationEngine

from taintinduce.isa.arm64_registers import ARM64_REG_NZCV
from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_EFLAGS
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rule_utils import espresso2cond, shift_espresso
from taintinduce.rules.rules import ConditionDataflowPair, Rule
from taintinduce.state.state import Observation, State
from taintinduce.state.state_utils import reg_pos
from taintinduce.types import (
    BitPosition,
    Dataflow,
    DataflowSet,
    MutatedInputStates,
    ObservationDependency,
    StateValue,
)

from .logic import Espresso, EspressoException, NonOrthogonalException

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
        self.espresso = Espresso()

    @staticmethod
    def extract_condition_bits(conditions: set[TaintCondition]) -> set[int]:
        """Extract all bit positions referenced in discovered conditions.

        Args:
            conditions: Set of TaintCondition objects

        Returns:
            Set of bit positions (0-based) that appear in condition masks
        """
        condition_bits: set[int] = set()
        for cond in conditions:
            if cond.condition_ops:
                for mask, value in cond.condition_ops:  # noqa: B007
                    # Extract which bits are checked by this clause
                    for bit_pos in range(64):  # Assume max 64-bit state
                        if mask & (1 << bit_pos):
                            condition_bits.add(bit_pos)
        return condition_bits

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

        return Rule(state_format, pairs=condition_dataflow_pairs_full)

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

        observation_dependencies: list[ObservationDependency] = self.extract_observation_dependencies(observations)

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
        no_cond_dataflow_set_flat: set[BitPosition] = set()
        for output_set in possible_flows[mutated_input_bit]:
            no_cond_dataflow_set_flat |= set(output_set)
        output_bits = frozenset(no_cond_dataflow_set_flat)
        if len(output_bits) > 1:
            logger.info(
                f'No condition for input bit {mutated_input_bit} -> {len(output_bits)} output bits',
            )
        return [ConditionDataflowPair(condition=None, output_bits=output_bits)]

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
        agreeing_partition: set[State] = set()
        disagreeing_partition: set[State] = set()
        for alternative_modified_output_set, input_states in partitions.items():
            if output_set != alternative_modified_output_set:
                disagreeing_partition.update(input_states)
            else:
                agreeing_partition.update(input_states)

        # use_full_state=True: generates conditions on all input registers (data-dependent)
        # This captures conditions like "if ebx=0, no taint in AND eax,ebx"
        # For arithmetic operations, this may overfit if observations are sparse
        mycond = self._gen_condition(
            agreeing_partition,
            disagreeing_partition,
            state_format,
            cond_reg,
            use_full_state=True,
        )

        # Debug: Log partition sizes to help identify overfitting
        logger.debug(
            f'  Partition sizes: agreeing={len(agreeing_partition)}, disagreeing={len(disagreeing_partition)}',
        )
        if mycond:
            logger.debug(f'  Found condition for output set {output_set}: {mycond}')

            # Refinement pass: validate this specific condition
            if enable_refinement and observation_engine is not None and all_observations is not None:
                refined_cond = self._refine_condition(
                    mycond,
                    mutated_input_bit,
                    output_set,
                    observation_engine,
                    all_observations,
                    state_format,
                    cond_reg,
                )
                if refined_cond != mycond:
                    logger.info(f'  REFINED: {mycond} -> {refined_cond}')
                    mycond = refined_cond
                else:
                    logger.info(f'  UNCHANGED: {mycond}')

        return mycond, output_set

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
        condition_dataflow_pairs: list[ConditionDataflowPair] = []
        no_cond_dataflow_set: set[frozenset[BitPosition]] = set()

        # Generate the two sets...
        # Iterate across all observations and extract the behavior for the partitions...
        partitions = self.link_affected_outputs_to_their_input_states(
            observation_dependencies,
            mutated_input_bit,
        )

        # ZL: The current heuristic is to always select the smaller partition first since
        # it lowers the chances of the DNF exploding.
        ordered_output_sets = sorted(partitions.keys(), key=lambda x: len(partitions[x]), reverse=True)

        for output_set in ordered_output_sets:
            mycond, output_bits = self._process_output_partition(
                output_set,
                partitions,
                state_format,
                cond_reg,
                mutated_input_bit,
                enable_refinement,
                observation_engine,
                all_observations,
            )

            if mycond:
                condition_dataflow_pairs.append(
                    ConditionDataflowPair(condition=mycond, output_bits=output_bits),
                )
            else:
                if len(output_set) > 1:
                    logger.info(
                        f'No condition for input bit {mutated_input_bit} -> '
                        f'{len(output_set)} output bits (partition)',
                    )
                no_cond_dataflow_set.add(output_set)

        # Default/fallthrough case: remaining behavior with no condition
        remaining_behavior: frozenset[BitPosition] = frozenset()
        if len(no_cond_dataflow_set) > 0:
            for behavior in no_cond_dataflow_set:
                remaining_behavior = remaining_behavior.union(behavior)
            logger.info(
                f'No condition for input bit {mutated_input_bit} -> '
                f'{len(remaining_behavior)} output bits (fallthrough)',
            )
            condition_dataflow_pairs.append(
                ConditionDataflowPair(condition=None, output_bits=remaining_behavior),
            )

        return condition_dataflow_pairs

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

    def link_affected_outputs_to_their_input_states(
        self,
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

    def _refine_condition(
        self,
        original_cond: TaintCondition,
        mutated_input_bit: BitPosition,
        output_set: frozenset[BitPosition],
        observation_engine: 'ObservationEngine',
        all_observations: list[Observation],
        state_format: list[Register],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
    ) -> TaintCondition:
        """Refine a specific condition by generating targeted observations.

        Args:
            original_cond: The condition to refine
            mutated_input_bit: Input bit this condition applies to
            output_set: Output bits affected by this condition
            agreeing_partition: States where condition is true
            disagreeing_partition: States where condition is false
            observation_engine: Engine to generate refinement observations
            all_observations: Original observations
            state_format: Register format
            cond_reg: Condition register

        Returns:
            Refined condition (may be same as original if refinement doesn't change it)
        """
        # Extract condition bits from this specific condition
        condition_bits = self.extract_condition_bits({original_cond})

        if not condition_bits:
            return original_cond

        logger.debug(f'    Refining condition for input bit {mutated_input_bit}, cond bits: {sorted(condition_bits)}')

        try:
            # Generate targeted observations for this condition
            # Use 64 samples - enough to cover 8-bit ranges without being too slow
            refinement_obs = observation_engine.refine_with_targeted_observations(
                condition_bits,
                num_refinement_samples=64,
            )

            if not refinement_obs:
                return original_cond

            # Combine with original observations
            combined_observations = all_observations + refinement_obs

            # Extract dependencies from combined observations
            combined_deps = self.extract_observation_dependencies(combined_observations)

            # Rebuild partitions with new observations
            combined_possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
            for obs_dep in combined_deps:
                for input_bit, output_bits in obs_dep.dataflow.items():
                    combined_possible_flows[input_bit].add(output_bits)

            # Check if this input bit still has the same output set
            if output_set not in combined_possible_flows[mutated_input_bit]:
                # Output set changed with refinement - condition may be spurious
                logger.debug('    Output set changed with refinement!')
                return original_cond

            # Rebuild partitions for this specific input bit
            refined_partitions = self.link_affected_outputs_to_their_input_states(
                combined_deps,
                mutated_input_bit,
            )

            # Find agreeing/disagreeing partitions for the same output set
            refined_agreeing: set[State] = set()
            refined_disagreeing: set[State] = set()

            for alt_output_set, input_states in refined_partitions.items():
                if alt_output_set == output_set:
                    refined_agreeing.update(input_states)
                else:
                    refined_disagreeing.update(input_states)

            # Generate new condition with refined partitions
            refined_cond = self._gen_condition(
                refined_agreeing,
                refined_disagreeing,
                state_format,
                cond_reg,
                use_full_state=True,
            )

            if refined_cond:
                return refined_cond

            return original_cond

        except Exception as e:
            logger.debug(f'    Refinement failed: {e}')
            return original_cond

    def extract_observation_dependencies(
        self,
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

    def _gen_condition(
        self,
        aggreeing_partition: set[State],
        opposing_partition: set[State],
        state_format: list[Register],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        use_full_state: bool = True,
    ) -> Optional[TaintCondition]:
        """Generate condition that separates two state partitions.

        Args:
            aggreeing_partition: Set of input States which belongs in the True partition.
            opposing_partition: Set of input States which belongs to the False partition.
            state_format: List of registers in the state.
            cond_reg: Register to use for conditions (legacy mode).
            use_full_state: If True, use all input registers for conditions (data-dependent).
                           If False, only use cond_reg (control-flow dependent).
        Returns:
            Condition object if there exists a condition.
            None if no condition can be inferred.
        Raises:
            None
        """
        partition_true: set[StateValue] = set()
        partition_false: set[StateValue] = set()

        if use_full_state:
            # Use ALL input register bits to find conditions
            # This enables data-dependent conditions like:
            # - "if ebx=0, no taint propagates in AND eax,ebx"
            # - "if shift amount=0, no changes in SHL"
            num_bits = sum([reg.bits for reg in state_format])

            for state in aggreeing_partition:
                partition_true.add(state.state_value)
            for state in opposing_partition:
                partition_false.add(state.state_value)

        else:
            # Legacy mode: Only use cond_reg bits (e.g., EFLAGS)
            # This is for control-flow dependent conditions like CMOV, SETcc
            cond_reg_start = reg_pos(cond_reg, state_format)
            cond_reg_mask = (1 << cond_reg.bits) - 1
            num_bits = cond_reg.bits

            for state in aggreeing_partition:
                cond_bits = (state.state_value >> cond_reg_start) & cond_reg_mask
                partition_true.add(StateValue(cond_bits))
            for state in opposing_partition:
                cond_bits = (state.state_value >> cond_reg_start) & cond_reg_mask
                partition_false.add(StateValue(cond_bits))

        # Debug: Uncomment to see partition values
        # print('True partition:')
        # for val in partition_true:
        #    print('{:0{}b}'.format(val, num_bits))
        # print('False partition:')
        # for val in partition_false:
        #    print('{:0{}b}'.format(val, num_bits))

        partitions = {1: partition_true, 0: partition_false}
        try:
            dnf_condition = self.espresso.minimize(num_bits, 1, 'fr', partitions)
        except NonOrthogonalException:
            return None
        except EspressoException as e:
            if 'ON-set and OFF-set are not orthogonal' in str(e):
                return None
            pdb.set_trace()
            raise e

        # dnf_condition: set of (mask, value) tuples representing DNF formula
        # Each tuple is a CNF clause: (input & mask == value)

        if not use_full_state:
            # In legacy mode, shift condition to cond_reg's position in full state
            dnf_condition = shift_espresso(dnf_condition, cond_reg, state_format)
        # In full state mode, condition bits already align with state_format

        return espresso2cond(dnf_condition)
