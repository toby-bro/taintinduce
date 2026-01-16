# Replaced squirrel import with our own
import logging

# Replaced squirrel import with our own
import pdb
from collections import defaultdict
from typing import Optional

from taintinduce.isa.arm64_registers import ARM64_REG_NZCV
from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_EFLAGS
from taintinduce.rules.conditions import TaintCondition
from taintinduce.rules.rule_utils import espresso2cond, shift_espresso
from taintinduce.rules.rules import Rule
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
logger.setLevel(logging.DEBUG)


class InferenceEngine(object):
    def __init__(self) -> None:
        self.espresso = Espresso()

    def infer(self, observations: list[Observation], cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV) -> Rule:
        """Infers the dataflow of the instruction using the obesrvations.

        Args:
            observations ([Observation]): List of observations to infer on.
            insn_info (InsnInfo): Optional argument to provide additional information about the insn.
        Returns:
            A list of Observations
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

        unique_conditions = self.infer_flow_conditions(observations, cond_reg, state_format)

        # at this point, we have all the conditions for all the bits
        # merge the condition and create the rule...
        # TODO: ZL: Have to take a look at how correct this is.
        # Don't think this is correct in general
        # The assumption here is that there will always be 2 sets, empty and the actual
        # condition list.

        dataflows: list[Dataflow] = []
        condition_array: frozenset[TaintCondition]

        merged_dataflows = Dataflow()
        _cond_array: set[TaintCondition] = set()
        for conditions, use_bit_dataflows in unique_conditions.items():
            for cond in conditions:
                _cond_array.add(cond)
            for use_bit, use_bit_dataflow in use_bit_dataflows.items():
                for dep_set in use_bit_dataflow:
                    merged_dataflows[use_bit] = merged_dataflows[use_bit].union(dep_set)
        dataflows.append(Dataflow())
        for use_bit, merged_dep_set in merged_dataflows.items():
            dataflows[-1][use_bit] = merged_dep_set
        condition_array = frozenset(_cond_array)

        rule = Rule(state_format, list(condition_array), dataflows)

        # for conditions in unique_conditions:
        #    dataflow = defaultdict(set)
        #    for use_bit, dataflows in unique_conditions[conditions]:
        #        print(use_bit)
        #        print tuple(izip_longest(conditions, dataflows, fillvalue=None))

        return rule  # noqa: RET504

    def infer_flow_conditions(
        self,
        observations: list[Observation],
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        state_format: list[Register],
    ) -> defaultdict[frozenset[TaintCondition], DataflowSet]:

        observation_dependencies: list[ObservationDependency] = self.extract_observation_dependencies(observations)

        # iterate through all the dependencies from the observations and identify what are the possible flows
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
        for observation in observation_dependencies:
            for mutated_input_bit, modified_output_bits in observation.dataflow.items():
                possible_flows[mutated_input_bit].add(modified_output_bits)

        unique_conditions: defaultdict[frozenset[TaintCondition], DataflowSet] = defaultdict(DataflowSet)

        for mutated_input_bit in possible_flows:
            bit_conditions, bit_dataflows = self.infer_conditions_for_dataflows(
                cond_reg,
                state_format,
                observation_dependencies,
                possible_flows,
                mutated_input_bit,
            )
            old_cond = unique_conditions[frozenset(bit_conditions)].get(mutated_input_bit, set())
            unique_conditions[frozenset(bit_conditions)][mutated_input_bit] = old_cond.union(bit_dataflows)
        return unique_conditions

    def infer_conditions_for_dataflows(
        self,
        cond_reg: X86_REG_EFLAGS | ARM64_REG_NZCV,
        state_format: list[Register],
        observation_dependencies: list[ObservationDependency],
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
        mutated_input_bit: BitPosition,
    ) -> tuple[set[TaintCondition], set[frozenset[BitPosition]]]:
        logger.debug(f'Searching flow conditions for input bit {mutated_input_bit}')

        bit_conditions: set[TaintCondition] = set()
        bit_dataflows: set[frozenset[BitPosition]] = set()
        num_partitions = len(possible_flows[mutated_input_bit])
        if num_partitions == 0:
            raise Exception(f'No possible flows for mutated input bit {mutated_input_bit}')
            # print(num_partitions)
            # ZL: ugly hack to collect all the possibly failed cond identification
        no_cond_dataflow_set: set[frozenset[BitPosition]] = set()

        # ZL: TODO: Hack for cond_reg, do a check if state_format contains the cond_reg, if no, then skip condition inference  # noqa: E501
        if num_partitions == 1:
            # no conditional dataflow
            no_cond_dataflow_set_flat: set[BitPosition] = set()
            for output_set in possible_flows[mutated_input_bit]:
                no_cond_dataflow_set_flat |= set(output_set)
            bit_dataflows.add(frozenset(no_cond_dataflow_set_flat))

        else:
            # generate the two sets...
            # iterate across all observations and extract the behavior for the partitions...
            partitions = self.link_affected_outputs_to_their_input_states(
                observation_dependencies,
                mutated_input_bit,
            )

            # ZL: The current heuristic is to always select the smaller partition first since
            # it lowers the chances of the DNF exploding.
            ordered_output_sets = sorted(partitions.keys(), key=lambda x: len(partitions[x]), reverse=True)

            for output_set in ordered_output_sets[:-1]:
                agreeing_partition: set[State] = set()
                disagreeing_partition: set[State] = set()
                for (
                    alternative_modified_output_set,
                    input_states,
                ) in partitions.items():  # Why not use the sorted behaviors ?
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
                    f'  Partition sizes: agreeing={len(agreeing_partition)}, '
                    f'disagreeing={len(disagreeing_partition)}',
                )
                if mycond:
                    logger.debug(f'  Found condition for output set {output_set}: {mycond}')
                    bit_conditions.add(mycond)
                    bit_dataflows.add(output_set)
                else:
                    no_cond_dataflow_set.add(output_set)

            remaining_behavior = ordered_output_sets[-1]
            if len(no_cond_dataflow_set) > 0:
                for behavior in no_cond_dataflow_set:
                    remaining_behavior = remaining_behavior.union(behavior)
            bit_dataflows.add(remaining_behavior)

        return bit_conditions, bit_dataflows

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
