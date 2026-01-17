"""Unit tests for observation generation to debug AMD64 vs X86 differences."""

import pytest

from taintinduce.disassembler.insn_info import Disassembler
from taintinduce.isa.arm64_registers import ARM64_REG_NZCV, ARM64_REG_X0
from taintinduce.isa.x86_registers import (
    X86_REG_EAX,
    X86_REG_EFLAGS,
    X86_REG_RAX,
)
from taintinduce.observation_engine.observation import ObservationEngine
from taintinduce.state.state import Observation
from taintinduce.unicorn_cpu.unicorn_cpu import UnicornCPU


class TestObservationGenerationMocked:
    """Fast mocked tests for observation generation."""

    def test_x86_observe_insn_called(self, mocker):
        """Test that X86 observe_insn is called with correct strategy."""
        bytestring = '25FF00FFaa'
        dis = Disassembler('X86', bytestring)

        # Create a mock observation with state transitions
        mock_obs = mocker.MagicMock(spec=Observation)
        mock_obs.mutated_ios = frozenset([('state1', 'state2')])  # Non-empty

        # Mock observe_insn to return immediately
        mock_observe = mocker.patch.object(
            ObservationEngine,
            'observe_insn',
            return_value=[mock_obs],
        )

        obs_engine = ObservationEngine(bytestring, 'X86', dis.insn_info.state_format)
        observations = obs_engine.observe_insn()

        # Verify it was called once
        mock_observe.assert_called_once()
        assert len(observations) == 1
        assert len(observations[0].mutated_ios) > 0

    def test_amd64_observe_insn_called(self, mocker):
        """Test that AMD64 observe_insn is called with correct strategy."""
        bytestring = '25FF00FFaa'
        dis = Disassembler('AMD64', bytestring)

        # Create a mock observation with state transitions
        mock_obs = mocker.MagicMock(spec=Observation)
        mock_obs.mutated_ios = frozenset([('state1', 'state2')])

        # Mock observe_insn to return immediately
        mock_observe = mocker.patch.object(
            ObservationEngine,
            'observe_insn',
            return_value=[mock_obs],
        )

        obs_engine = ObservationEngine(bytestring, 'AMD64', dis.insn_info.state_format)
        observations = obs_engine.observe_insn()

        # Verify it was called once
        mock_observe.assert_called_once()
        assert len(observations) == 1
        assert len(observations[0].mutated_ios) > 0

    def test_gen_seeds_called_with_strategy(self, mocker):
        """Test that _gen_seeds is called with correct parameters."""
        bytestring = '25FF00FFaa'
        dis = Disassembler('X86', bytestring)
        state_format = dis.insn_info.state_format

        # Mock _gen_seeds to return immediately
        mock_seed_in = mocker.MagicMock()
        mock_seed_out = mocker.MagicMock()
        mock_gen_seeds = mocker.patch.object(
            ObservationEngine,
            '_gen_seeds',
            return_value=[(mock_seed_in, mock_seed_out)],
        )

        obs_engine = ObservationEngine(bytestring, 'X86', state_format)
        seeds = obs_engine._gen_seeds(bytestring, 'X86', state_format)

        # Verify it was called once with correct args
        mock_gen_seeds.assert_called_once_with(bytestring, 'X86', state_format)
        assert len(seeds) == 1

    def test_gen_observation_called_with_seed(self, mocker):
        """Test that _gen_observation is called with seed."""
        bytestring = '25FF00FFaa'
        dis = Disassembler('AMD64', bytestring)
        state_format = dis.insn_info.state_format

        # Mock _gen_observation to return immediately
        mock_obs = mocker.MagicMock(spec=Observation)
        mock_obs.mutated_ios = frozenset([('state1', 'state2')])
        mock_gen_obs = mocker.patch.object(
            ObservationEngine,
            '_gen_observation',
            return_value=mock_obs,
        )

        obs_engine = ObservationEngine(bytestring, 'AMD64', state_format)
        mock_seed = (mocker.MagicMock(), mocker.MagicMock())
        obs = obs_engine._gen_observation(bytestring, 'AMD64', state_format, mock_seed)

        # Verify it was called once
        mock_gen_obs.assert_called_once_with(bytestring, 'AMD64', state_format, mock_seed)
        assert len(obs.mutated_ios) > 0


class TestActualExecution:
    """Tests that verify actual CPU execution with real inputs/outputs."""

    def test_x86_and_instruction_execution(self):
        """Test that X86 AND instruction produces correct output."""
        bytecode = bytes.fromhex('25FF00FFaa')  # AND EAX, 0xaaff00ff
        cpu = UnicornCPU('X86')

        eax_reg = X86_REG_EAX()
        eflags_reg = X86_REG_EFLAGS()

        # Test: 0xFFFFFFFF AND 0xaaff00ff = 0xaaff00ff
        state_in = {eax_reg: 0xFFFFFFFF, eflags_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out = cpu.execute(bytecode)

        assert state_out[eax_reg] == 0xAAFF00FF, f'Expected 0xaaff00ff, got {state_out[eax_reg]:#x}'

    def test_amd64_and_instruction_execution(self):
        """Test that AMD64 AND instruction produces correct output."""
        bytecode = bytes.fromhex('25FF00FFaa')  # AND EAX, 0xaaff00ff
        cpu = UnicornCPU('AMD64')

        rax_reg = X86_REG_RAX()
        eflags_reg = X86_REG_EFLAGS()

        # Test: 0xFFFFFFFFFFFFFFFF AND 0xaaff00ff = 0x00000000aaff00ff (upper 32 zeroed)
        state_in = {rax_reg: 0xFFFFFFFFFFFFFFFF, eflags_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out = cpu.execute(bytecode)

        assert state_out[rax_reg] == 0x00000000AAFF00FF, f'Expected 0x00000000aaff00ff, got {state_out[rax_reg]:#018x}'

    def test_x86_bit_flip_changes_output(self):
        """Test that flipping input bit changes output for X86."""
        bytecode = bytes.fromhex('25FF00FFaa')
        cpu = UnicornCPU('X86')

        eax_reg = X86_REG_EAX()
        eflags_reg = X86_REG_EFLAGS()

        # Original state
        state_in = {eax_reg: 0xFFFFFFFF, eflags_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out1 = cpu.execute(bytecode)

        # Flipped bit 0
        state_in_flipped = {eax_reg: 0xFFFFFFFF ^ 1, eflags_reg: 0}
        cpu.set_cpu_state(state_in_flipped)  # type: ignore[arg-type]
        _, state_out2 = cpu.execute(bytecode)

        assert state_out1[eax_reg] != state_out2[eax_reg], 'Bit flip should change output'

    def test_amd64_bit_flip_changes_output(self):
        """Test that flipping input bit changes output for AMD64."""
        bytecode = bytes.fromhex('25FF00FFaa')
        cpu = UnicornCPU('AMD64')

        rax_reg = X86_REG_RAX()
        eflags_reg = X86_REG_EFLAGS()

        # Original state
        state_in = {rax_reg: 0xFFFFFFFFFFFFFFFF, eflags_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out1 = cpu.execute(bytecode)

        # Flipped bit 0
        state_in_flipped = {rax_reg: 0xFFFFFFFFFFFFFFFF ^ 1, eflags_reg: 0}
        cpu.set_cpu_state(state_in_flipped)  # type: ignore[arg-type]
        _, state_out2 = cpu.execute(bytecode)

        assert state_out1[rax_reg] != state_out2[rax_reg], 'Bit flip should change output'

    def test_arm64_add_instruction_execution(self):
        """Test that ARM64 ADD instruction produces correct output."""
        bytecode = bytes.fromhex('00080091')  # add x0, x0, #0x02
        cpu = UnicornCPU('ARM64')

        x0_reg = ARM64_REG_X0()
        nzcv_reg = ARM64_REG_NZCV()

        # Test: 0x0000000000000005 + 0x02 = 0x0000000000000007
        state_in = {x0_reg: 0x0000000000000005, nzcv_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out = cpu.execute(bytecode)

        assert state_out[x0_reg] == 0x0000000000000007, f'Expected 0x0000000000000007, got {state_out[x0_reg]:#018x}'

    def test_arm64_and_instruction_execution(self):
        """Test that ARM64 AND instruction produces correct output."""
        bytecode = bytes.fromhex('000c1c12')  # and w0, w0, #0xf0
        cpu = UnicornCPU('ARM64')

        x0_reg = ARM64_REG_X0()
        nzcv_reg = ARM64_REG_NZCV()

        # Test: 0x00000000000000FF AND 0xF0 = 0x00000000000000F0
        state_in = {x0_reg: 0x00000000000000FF, nzcv_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out = cpu.execute(bytecode)

        assert state_out[x0_reg] == 0x00000000000000F0, f'Expected 0x00000000000000F0, got {state_out[x0_reg]:#018x}'

    def test_arm64_bit_flip_changes_output(self):
        """Test that flipping input bit changes output for ARM64."""
        bytecode = bytes.fromhex('00080091')  # add x0, x0, #0x02
        cpu = UnicornCPU('ARM64')

        x0_reg = ARM64_REG_X0()
        nzcv_reg = ARM64_REG_NZCV()

        # Original state
        state_in = {x0_reg: 0x0000000000000005, nzcv_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        _, state_out1 = cpu.execute(bytecode)

        # Flipped bit 0
        state_in_flipped = {x0_reg: 0x0000000000000005 ^ 1, nzcv_reg: 0}
        cpu.set_cpu_state(state_in_flipped)  # type: ignore[arg-type]
        _, state_out2 = cpu.execute(bytecode)

        assert state_out1[x0_reg] != state_out2[x0_reg], 'Bit flip should change output'

    def test_arm64_instruction_state_changes(self):
        """Test that ARM64 instructions produce actual state changes (not no-ops)."""
        bytecode = bytes.fromhex('00080091')  # add x0, x0, #0x02
        cpu = UnicornCPU('ARM64')

        x0_reg = ARM64_REG_X0()
        nzcv_reg = ARM64_REG_NZCV()

        # Execute with initial value
        state_in = {x0_reg: 0x0000000000000010, nzcv_reg: 0}
        cpu.set_cpu_state(state_in)  # type: ignore[arg-type]
        state_before, state_after = cpu.execute(bytecode)

        # Verify state actually changed
        assert state_before[x0_reg] == 0x0000000000000010, 'State before should match input'
        assert state_after[x0_reg] == 0x0000000000000012, 'State after should be input + 2'
        assert (
            state_before[x0_reg] != state_after[x0_reg]
        ), 'ARM64 instruction must produce state change (not silently fail)'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
