"""Condition refinement with targeted observations.

Refines conditions by generating additional observations focused on condition bits.
"""

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from taintinduce.observation_engine.observation import ObservationEngine

from taintinduce.isa.register import CondRegister, Register
from taintinduce.rules.conditions import TaintCondition
from taintinduce.state.state import Observation, State
from taintinduce.types import BitPosition

from . import observation_processor
from .condition_generator import ConditionGenerator

logger = logging.getLogger(__name__)


class ConditionRefiner:
    """Refines conditions using targeted observations."""

    def __init__(self, condition_generator: ConditionGenerator) -> None:
        self.condition_generator = condition_generator

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

            # Rebuild possible flows
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
            refined_cond = self.condition_generator.generate_condition(
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
