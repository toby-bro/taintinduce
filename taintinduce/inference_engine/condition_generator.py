"""Condition generation and refinement logic."""

import logging
import pdb
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from taintinduce.observation_engine.observation import ObservationEngine

from taintinduce.isa.register import CondRegister, Register
from taintinduce.rules.conditions import TaintCondition
from taintinduce.rules.rule_utils import espresso2cond, shift_espresso
from taintinduce.state.state import Observation, State
from taintinduce.state.state_utils import reg_pos
from taintinduce.types import (
    BitPosition,
    StateValue,
)

from . import observation_processor
from .logic import Espresso, EspressoException, NonOrthogonalException

logger = logging.getLogger(__name__)


class ConditionGenerator:
    """Handles condition generation and refinement using ESPRESSO logic minimizer."""

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
                for mask, _ in cond.condition_ops:
                    # Extract which bits are checked by this clause
                    for bit_pos in range(64):  # Assume max 64-bit state
                        if mask & (1 << bit_pos):
                            condition_bits.add(bit_pos)
        return condition_bits

    def generate_condition(
        self,
        aggreeing_partition: set[State],
        opposing_partition: set[State],
        state_format: list[Register],
        cond_reg: CondRegister,
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

    def refine_condition(
        self,
        original_cond: TaintCondition,
        mutated_input_bit: BitPosition,
        output_set: frozenset[BitPosition],
        observation_engine: 'ObservationEngine',
        all_observations: list[Observation],
        state_format: list[Register],
        cond_reg: CondRegister,
    ) -> TaintCondition:
        """Refine a specific condition by generating targeted observations.

        Args:
            original_cond: The condition to refine
            mutated_input_bit: Input bit this condition applies to
            output_set: Output bits affected by this condition
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
            combined_deps = observation_processor.extract_observation_dependencies(combined_observations)

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
            refined_partitions = observation_processor.link_affected_outputs_to_their_input_states(
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
            refined_cond = self.generate_condition(
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
