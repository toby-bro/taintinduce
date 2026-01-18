"""Unit tests for the inference engine module.

This module tests the InferenceEngine class and its methods for inferring
taint propagation rules with data-dependent conditions.
"""

from collections import defaultdict
from typing import Optional
from unittest.mock import Mock, patch

import pytest

from taintinduce.inference_engine.inference import InferenceEngine
from taintinduce.inference_engine.logic import Espresso, EspressoException, NonOrthogonalException
from taintinduce.isa.register import Register
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EFLAGS
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair, Rule
from taintinduce.state.state import Observation, State
from taintinduce.types import BitPosition, Dataflow, MutatedInputStates, ObservationDependency, StateValue

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_espresso():
    """Create a mock Espresso instance."""
    espresso = Mock(spec=Espresso)
    espresso.minimize = Mock(return_value=frozenset([(0xFF, 0x01)]))
    return espresso


@pytest.fixture
def inference_engine(mock_espresso):
    """Create an InferenceEngine with mocked Espresso."""
    engine = InferenceEngine()
    engine.espresso = mock_espresso
    return engine


@pytest.fixture
def mock_register():
    """Create a mock Register."""
    reg = Mock(spec=Register)
    reg.name = 'EAX'
    reg.bits = 32
    return reg


@pytest.fixture
def mock_eflags():
    """Create a mock EFLAGS register."""
    eflags = Mock(spec=X86_REG_EFLAGS)
    eflags.name = 'EFLAGS'
    eflags.bits = 32
    return eflags


@pytest.fixture
def mock_eax():
    """Create a mock EAX register."""
    eax = Mock(spec=X86_REG_EAX)
    eax.name = 'EAX'
    eax.bits = 32
    return eax


@pytest.fixture
def state_format(mock_eflags, mock_eax):
    """Create a standard state format with EFLAGS and EAX."""
    return [mock_eflags, mock_eax]


@pytest.fixture
def simple_observation(state_format):
    """Create a simple observation for testing."""
    seed_in = State(num_bits=64, state_value=StateValue(0x0000000012345678))
    seed_out = State(num_bits=64, state_value=StateValue(0x0000000012345678))

    mutate_in = State(num_bits=64, state_value=StateValue(0x0000000012345679))  # bit 32 flipped
    mutate_out = State(num_bits=64, state_value=StateValue(0x0000000012345679))

    return Observation(
        iopair=(seed_in, seed_out),
        mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
        bytestring='test',
        archstring='X86',
        state_format=state_format,
    )


@pytest.fixture
def conditional_observation(state_format):
    """Create an observation with conditional behavior."""
    # When EFLAGS bit 0 is set, different output behavior
    seed_in = State(num_bits=64, state_value=StateValue(0x0000000100000000))
    seed_out = State(num_bits=64, state_value=StateValue(0x0000000100000000))

    mutate_in = State(num_bits=64, state_value=StateValue(0x0000000100000001))  # bit 32 flipped
    mutate_out = State(num_bits=64, state_value=StateValue(0x0000000100000005))  # bits 32, 34 changed

    return Observation(
        iopair=(seed_in, seed_out),
        mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
        bytestring='test',
        archstring='X86',
        state_format=state_format,
    )


# ============================================================================
# Tests for InferenceEngine.__init__
# ============================================================================


class TestInferenceEngineInit:
    """Tests for InferenceEngine initialization."""

    def test_init_creates_espresso(self):
        """Test that __init__ creates an Espresso instance."""
        engine = InferenceEngine()
        assert hasattr(engine, 'espresso')
        assert isinstance(engine.espresso, Espresso)


# ============================================================================
# Tests for InferenceEngine.infer
# ============================================================================


class TestInfer:
    """Tests for the main infer method."""

    def test_infer_with_empty_observations_raises_exception(self, inference_engine, mock_eflags):
        """Test that infer raises exception with empty observations."""
        with pytest.raises(Exception, match='No observations to infer from'):
            inference_engine.infer([], mock_eflags)

    def test_infer_with_none_state_format_raises_exception(self, inference_engine, mock_eflags):
        """Test that infer raises exception when state_format is None."""
        obs = Mock(spec=Observation)
        obs.state_format = None

        with pytest.raises(Exception, match='State format is None'):
            inference_engine.infer([obs], mock_eflags)

    def test_infer_returns_rule(self, inference_engine, simple_observation, mock_eflags):
        """Test that infer returns a Rule object."""
        with patch.object(inference_engine, 'infer_flow_conditions') as mock_infer_flow:
            # Return dict with: condition_set -> (ordered_pairs, dataflow_set)
            mock_cond = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))
            mock_pair = ConditionDataflowPair(
                condition=mock_cond,
                output_bits=frozenset([BitPosition(0)]),
            )
            dataflow_set: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
            dataflow_set[BitPosition(0)] = {frozenset([BitPosition(0)])}

            mock_dict: dict[
                frozenset[Optional[TaintCondition]],
                tuple[list[ConditionDataflowPair], defaultdict[BitPosition, set[frozenset[BitPosition]]]],
            ] = {}
            mock_dict[frozenset([mock_cond])] = ([mock_pair], dataflow_set)
            mock_infer_flow.return_value = mock_dict

            result = inference_engine.infer([simple_observation], mock_eflags)

            assert isinstance(result, Rule)
            assert result.state_format == simple_observation.state_format

    def test_infer_calls_infer_flow_conditions(self, inference_engine, simple_observation, mock_eflags):
        """Test that infer calls infer_flow_conditions with correct arguments."""
        with patch.object(inference_engine, 'infer_flow_conditions') as mock_infer_flow:
            # Return dict with: condition_set -> (ordered_pairs, dataflow_set)
            mock_cond = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))
            mock_pair = ConditionDataflowPair(
                condition=mock_cond,
                output_bits=frozenset([BitPosition(0)]),
            )
            dataflow_set: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
            dataflow_set[BitPosition(0)] = {frozenset([BitPosition(0)])}

            mock_dict: dict[
                frozenset[Optional[TaintCondition]],
                tuple[list[ConditionDataflowPair], defaultdict[BitPosition, set[frozenset[BitPosition]]]],
            ] = {}
            mock_dict[frozenset([mock_cond])] = ([mock_pair], dataflow_set)
            mock_infer_flow.return_value = mock_dict

            inference_engine.infer([simple_observation], mock_eflags)

            mock_infer_flow.assert_called_once_with(
                [simple_observation],
                mock_eflags,
                simple_observation.state_format,
                enable_refinement=False,
                observation_engine=None,
            )

    def test_infer_merges_conditions_and_dataflows(self, inference_engine, simple_observation, mock_eflags):
        """Test that infer properly creates condition-dataflow pairs."""
        # Integration-style test to verify pairs are created correctly
        result = inference_engine.infer([simple_observation], mock_eflags)

        # Verify we have at least one condition-dataflow pair
        assert len(result.pairs) >= 1


# ============================================================================
# Tests for InferenceEngine.extract_observation_dependencies
# ============================================================================


class TestExtractObservationDependencies:
    """Tests for extract_observation_dependencies method."""

    def test_extract_single_observation(self, inference_engine, simple_observation):
        """Test extracting dependencies from a single observation."""
        result = inference_engine.extract_observation_dependencies([simple_observation])

        assert len(result) == 1
        assert isinstance(result[0], ObservationDependency)
        assert BitPosition(0) in result[0].dataflow

    def test_extract_raises_on_multiple_bit_flips(self, inference_engine, state_format):
        """Test that method raises exception when multiple bits are flipped."""
        seed_in = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        seed_out = State(num_bits=64, state_value=StateValue(0x0000000012345678))

        # Flip two bits instead of one
        mutate_in = State(num_bits=64, state_value=StateValue(0x000000001234567B))  # bits 32 and 33
        mutate_out = State(num_bits=64, state_value=StateValue(0x000000001234567B))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )

        with pytest.raises(Exception, match='More than one bit flipped'):
            inference_engine.extract_observation_dependencies([obs])

    def test_extract_multiple_observations(self, inference_engine, simple_observation, conditional_observation):
        """Test extracting dependencies from multiple observations."""
        result = inference_engine.extract_observation_dependencies([simple_observation, conditional_observation])

        assert len(result) == 2
        assert all(isinstance(dep, ObservationDependency) for dep in result)


# ============================================================================
# Tests for InferenceEngine.link_affected_outputs_to_their_input_states
# ============================================================================


class TestLinkAffectedOutputsToTheirInputStates:
    """Tests for link_affected_outputs_to_their_input_states method."""

    def test_link_creates_partitions(self, inference_engine):
        """Test that method creates correct partitions."""
        # Create mock observation dependencies
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000087654321))

        dataflow1 = Dataflow()
        dataflow1[BitPosition(32)] = frozenset([BitPosition(32), BitPosition(33)])

        dataflow2 = Dataflow()
        dataflow2[BitPosition(32)] = frozenset([BitPosition(32), BitPosition(34)])

        mutated_inputs1 = MutatedInputStates()
        mutated_inputs1[BitPosition(32)] = state1

        mutated_inputs2 = MutatedInputStates()
        mutated_inputs2[BitPosition(32)] = state2

        obs_dep1 = ObservationDependency(dataflow=dataflow1, mutated_inputs=mutated_inputs1, original_output=state1)
        obs_dep2 = ObservationDependency(dataflow=dataflow2, mutated_inputs=mutated_inputs2, original_output=state2)

        result = inference_engine.link_affected_outputs_to_their_input_states(
            [obs_dep1, obs_dep2],
            BitPosition(32),
        )

        assert len(result) == 2
        assert frozenset([BitPosition(32), BitPosition(33)]) in result
        assert frozenset([BitPosition(32), BitPosition(34)]) in result
        assert state1 in result[frozenset([BitPosition(32), BitPosition(33)])]
        assert state2 in result[frozenset([BitPosition(32), BitPosition(34)])]

    def test_link_filters_by_mutated_bit(self, inference_engine):
        """Test that method only includes observations for the specified mutated bit."""
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))

        dataflow1 = Dataflow()
        dataflow1[BitPosition(32)] = frozenset([BitPosition(32)])
        dataflow1[BitPosition(33)] = frozenset([BitPosition(33)])

        mutated_inputs1 = MutatedInputStates()
        mutated_inputs1[BitPosition(32)] = state1

        obs_dep1 = ObservationDependency(dataflow=dataflow1, mutated_inputs=mutated_inputs1, original_output=state1)

        # Only get results for bit 32
        result = inference_engine.link_affected_outputs_to_their_input_states([obs_dep1], BitPosition(32))

        assert len(result) == 1
        assert frozenset([BitPosition(32)]) in result


# ============================================================================
# Tests for InferenceEngine._gen_condition
# ============================================================================


class TestGenCondition:
    """Tests for _gen_condition method."""

    def test_gen_condition_with_full_state(self, inference_engine, state_format, mock_eflags):
        """Test condition generation with use_full_state=True."""
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000087654321))

        agreeing = {state1}
        opposing = {state2}

        result = inference_engine._gen_condition(
            agreeing,
            opposing,
            state_format,
            mock_eflags,
            use_full_state=True,
        )

        assert result is not None
        assert isinstance(result, TaintCondition)
        inference_engine.espresso.minimize.assert_called_once()
        # Check that it used 64 bits (full state)
        assert inference_engine.espresso.minimize.call_args[0][0] == 64

    def test_gen_condition_with_cond_reg_only(self, inference_engine, state_format, mock_eflags):
        """Test condition generation with use_full_state=False."""
        state1 = State(num_bits=64, state_value=StateValue(0x0000000112345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000287654321))

        agreeing = {state1}
        opposing = {state2}

        with patch('taintinduce.inference_engine.inference.reg_pos', return_value=0):
            with patch('taintinduce.inference_engine.inference.shift_espresso') as mock_shift:
                mock_shift.return_value = frozenset([(0xFF, 0x01)])

                result = inference_engine._gen_condition(
                    agreeing,
                    opposing,
                    state_format,
                    mock_eflags,
                    use_full_state=False,
                )

                assert result is not None
                # Check that it used 32 bits (cond_reg only)
                assert inference_engine.espresso.minimize.call_args[0][0] == 32
                # Check that shift_espresso was called (legacy mode)
                mock_shift.assert_called_once()

    def test_gen_condition_returns_none_on_non_orthogonal(self, inference_engine, state_format, mock_eflags):
        """Test that method returns None when partitions are not orthogonal."""
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000012345678))  # Same state

        agreeing = {state1}
        opposing = {state2}

        inference_engine.espresso.minimize.side_effect = NonOrthogonalException('Not orthogonal')

        result = inference_engine._gen_condition(
            agreeing,
            opposing,
            state_format,
            mock_eflags,
            use_full_state=True,
        )

        assert result is None

    def test_gen_condition_returns_none_on_espresso_error(self, inference_engine, state_format, mock_eflags):
        """Test that method returns None on specific Espresso errors."""
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000087654321))

        agreeing = {state1}
        opposing = {state2}

        inference_engine.espresso.minimize.side_effect = EspressoException(
            'ON-set and OFF-set are not orthogonal',
        )

        result = inference_engine._gen_condition(
            agreeing,
            opposing,
            state_format,
            mock_eflags,
            use_full_state=True,
        )

        assert result is None

    @patch('taintinduce.inference_engine.inference.espresso2cond')
    def test_gen_condition_calls_espresso2cond(self, mock_espresso2cond, inference_engine, state_format, mock_eflags):
        """Test that method calls espresso2cond to convert result."""
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000087654321))

        agreeing = {state1}
        opposing = {state2}

        mock_espresso2cond.return_value = TaintCondition(LogicType.DNF, frozenset())

        inference_engine._gen_condition(
            agreeing,
            opposing,
            state_format,
            mock_eflags,
            use_full_state=True,
        )

        mock_espresso2cond.assert_called_once()


# ============================================================================
# Tests for InferenceEngine.infer_conditions_for_dataflows
# ============================================================================


class TestInferConditionsForDataflows:
    """Tests for infer_conditions_for_dataflows method."""

    def test_single_partition_no_conditions(self, inference_engine, state_format, mock_eflags):
        """Test that single partition results in no conditions (returns default/None)."""
        obs_deps: list[ObservationDependency] = []
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
        possible_flows[BitPosition(32)] = {frozenset([BitPosition(32)])}

        pairs = inference_engine.infer_conditions_for_dataflows(
            mock_eflags,
            state_format,
            obs_deps,
            possible_flows,
            BitPosition(32),
        )

        # With single partition, should return one pair with condition=None
        assert len(pairs) == 1
        pair = pairs[0]
        assert pair.condition is None  # No condition needed for single partition
        assert BitPosition(32) in pair.output_bits

    def test_multiple_partitions_generates_conditions(self, inference_engine, state_format, mock_eflags):
        """Test that multiple partitions generate conditions."""
        # Create observation dependencies with different behaviors
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        state2 = State(num_bits=64, state_value=StateValue(0x0000000087654321))

        dataflow1 = Dataflow()
        dataflow1[BitPosition(32)] = frozenset([BitPosition(32), BitPosition(33)])

        dataflow2 = Dataflow()
        dataflow2[BitPosition(32)] = frozenset([BitPosition(32)])

        mutated_inputs1 = MutatedInputStates()
        mutated_inputs1[BitPosition(32)] = state1

        mutated_inputs2 = MutatedInputStates()
        mutated_inputs2[BitPosition(32)] = state2

        obs_dep1 = ObservationDependency(dataflow=dataflow1, mutated_inputs=mutated_inputs1, original_output=state1)
        obs_dep2 = ObservationDependency(dataflow=dataflow2, mutated_inputs=mutated_inputs2, original_output=state2)

        possible_flows = defaultdict(set)
        possible_flows[BitPosition(32)] = {
            frozenset([BitPosition(32), BitPosition(33)]),
            frozenset([BitPosition(32)]),
        }

        with patch.object(inference_engine, '_gen_condition') as mock_gen_cond:
            mock_gen_cond.return_value = TaintCondition(LogicType.DNF, frozenset([(0xFF, 0x01)]))

            pairs = inference_engine.infer_conditions_for_dataflows(
                mock_eflags,
                state_format,
                [obs_dep1, obs_dep2],
                possible_flows,
                BitPosition(32),
            )

            assert len(pairs) >= 1  # Should have at least one pair

    def test_raises_on_zero_partitions(self, inference_engine, state_format, mock_eflags):
        """Test that method raises exception when no possible flows exist."""
        obs_deps: list[ObservationDependency] = []
        possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
        possible_flows[BitPosition(32)] = set()  # Empty

        with pytest.raises(Exception, match='No possible flows'):
            inference_engine.infer_conditions_for_dataflows(
                mock_eflags,
                state_format,
                obs_deps,
                possible_flows,
                BitPosition(32),
            )


# ============================================================================
# Tests for InferenceEngine.infer_flow_conditions
# ============================================================================


class TestInferFlowConditions:
    """Tests for infer_flow_conditions method."""

    def test_infer_flow_conditions_calls_extract_dependencies(
        self,
        inference_engine,
        simple_observation,
        state_format,
        mock_eflags,
    ):
        """Test that method calls extract_observation_dependencies."""
        with patch.object(inference_engine, 'extract_observation_dependencies') as mock_extract:
            mock_extract.return_value = []

            with patch.object(inference_engine, 'infer_conditions_for_dataflows') as mock_infer_cond:
                mock_infer_cond.return_value = (set(), set())

                inference_engine.infer_flow_conditions([simple_observation], mock_eflags, state_format)

                mock_extract.assert_called_once_with([simple_observation])

    def test_infer_flow_conditions_processes_all_input_bits(self, inference_engine, state_format, mock_eflags):
        """Test that method processes all mutated input bits."""
        # Create observation dependencies with multiple input bits
        state1 = State(num_bits=64, state_value=StateValue(0x0000000012345678))

        dataflow1 = Dataflow()
        dataflow1[BitPosition(32)] = frozenset([BitPosition(32)])
        dataflow1[BitPosition(33)] = frozenset([BitPosition(33)])

        mutated_inputs1 = MutatedInputStates()
        mutated_inputs1[BitPosition(32)] = state1
        mutated_inputs1[BitPosition(33)] = state1

        obs_dep1 = ObservationDependency(dataflow=dataflow1, mutated_inputs=mutated_inputs1, original_output=state1)

        with patch.object(inference_engine, 'extract_observation_dependencies', return_value=[obs_dep1]):
            with patch.object(inference_engine, 'infer_conditions_for_dataflows') as mock_infer_cond:
                # Return list of ConditionDataflowPair objects
                mock_infer_cond.return_value = [
                    ConditionDataflowPair(condition=None, output_bits=frozenset([BitPosition(32)])),
                ]

                inference_engine.infer_flow_conditions([Mock()], mock_eflags, state_format)

                # Should be called for both bits 32 and 33
                assert mock_infer_cond.call_count == 2


# ============================================================================
# Integration Tests
# ============================================================================


class TestInferenceEngineIntegration:
    """Integration tests for the complete inference pipeline."""

    def test_end_to_end_simple_instruction(self, state_format):
        """Test complete inference for a simple instruction."""
        engine = InferenceEngine()

        # Create observation for simple instruction (e.g., mov)
        seed_in = State(num_bits=64, state_value=StateValue(0x0000000012345678))
        seed_out = State(num_bits=64, state_value=StateValue(0x0000000012345678))

        mutate_in = State(num_bits=64, state_value=StateValue(0x0000000012345679))
        mutate_out = State(num_bits=64, state_value=StateValue(0x0000000012345679))

        obs = Observation(
            iopair=(seed_in, seed_out),
            mutated_iopairs=frozenset([(mutate_in, mutate_out)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )

        mock_eflags = state_format[0]

        # This should work without exceptions
        result = engine.infer([obs], mock_eflags)

        assert isinstance(result, Rule)
        assert result.state_format == state_format
        assert len(result.pairs) > 0

    @patch('taintinduce.inference_engine.inference.Espresso')
    def test_data_dependent_condition_and_instruction(self, mock_espresso_class, state_format):
        """Test inference for data-dependent instruction like AND."""
        mock_espresso_instance = Mock()
        mock_espresso_instance.minimize = Mock(return_value=frozenset([(0xFFFFFFFF00000000, 0x0000000000000000)]))
        mock_espresso_class.return_value = mock_espresso_instance

        engine = InferenceEngine()

        # Observation 1: EFLAGS=0, EAX bit 0 flipped, output bit 0 changes
        seed_in1 = State(num_bits=64, state_value=StateValue(0x0000000000000000))  # EFLAGS=0, EAX=0
        seed_out1 = State(num_bits=64, state_value=StateValue(0x0000000000000000))

        mutate_in1 = State(num_bits=64, state_value=StateValue(0x0000000100000000))  # EAX bit 0 (pos 32) flipped
        mutate_out1 = State(num_bits=64, state_value=StateValue(0x0000000100000000))  # output bit 0 changes

        # Observation 2: EFLAGS=0xFF, EAX bit 0 flipped, output bit 0 and 2 change (conditional)
        seed_in2 = State(num_bits=64, state_value=StateValue(0x00000000000000FF))  # EFLAGS=0xFF, EAX=0
        seed_out2 = State(num_bits=64, state_value=StateValue(0x0000000000000000))

        mutate_in2 = State(num_bits=64, state_value=StateValue(0x00000001000000FF))  # EAX bit 0 (pos 32) flipped
        mutate_out2 = State(num_bits=64, state_value=StateValue(0x0000000100000005))  # output bits 0 and 2 change

        obs1 = Observation(
            iopair=(seed_in1, seed_out1),
            mutated_iopairs=frozenset([(mutate_in1, mutate_out1)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )

        obs2 = Observation(
            iopair=(seed_in2, seed_out2),
            mutated_iopairs=frozenset([(mutate_in2, mutate_out2)]),
            bytestring='test',
            archstring='X86',
            state_format=state_format,
        )

        mock_eflags = state_format[0]

        result = engine.infer([obs1, obs2], mock_eflags)

        assert isinstance(result, Rule)
        # Should find conditional behavior
        assert len(result.pairs) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
