from typing import Optional

from tqdm import tqdm
from unicorn.unicorn import UcError

from taintinduce.cpu.cpu import CPU, CPUFactory
from taintinduce.cpu.unicorn_cpu import OutOfRangeException
from taintinduce.isa.amd64 import AMD64
from taintinduce.isa.arm64 import ARM64
from taintinduce.isa.isa import ISA
from taintinduce.isa.jn import JN
from taintinduce.isa.register import Register
from taintinduce.isa.x86 import X86
from taintinduce.observation_engine.strategy import (
    BitFill,
    Bitwalk,
    IEEE754Extended,
    RandomNumber,
    SystematicRange,
    ZeroWalk,
)
from taintinduce.state.state import Observation, State
from taintinduce.state.state_utils import regs2bits
from taintinduce.types import CpuRegisterMap

from .strategy import SeedVariation, Strategy


def decode_instruction_bytes(bytestring: str, archstring: str) -> bytes:
    """Decode instruction bytestring to bytes based on architecture.

    Args:
        bytestring: Hex string representation of instruction
        archstring: Architecture name (X86, AMD64, ARM64, JN, etc.)

    Returns:
        Decoded bytes for the instruction
    """
    # For JN ISA, each hex char is a nibble (4 bits) - convert directly to bytes
    if archstring == 'JN':
        return bytes([int(c, 16) for c in bytestring])
    # For other architectures, pairs of hex chars form bytes
    return bytes.fromhex(bytestring)


def encode_instruction_bytes(bytecode: bytes, archstring: str) -> str:
    """Encode instruction bytes to hex string based on architecture.

    Args:
        bytecode: Instruction bytes
        archstring: Architecture name (X86, AMD64, ARM64, JN, etc.)

    Returns:
        Hex string representation of the instruction
    """
    # For JN ISA, each byte holds a nibble value (0-15), convert to single hex chars
    if archstring == 'JN':
        return ''.join(f'{b:X}' for b in bytecode)
    # For other architectures, use standard hex encoding
    return bytecode.hex()


class ConditionTargetedStrategy(Strategy):
    """Strategy that generates systematic values to validate condition bits.

    Instead of random values, this generates ALL possible values for small
    registers (<=8 bits) or systematic sampling for larger registers that
    contain condition bits. This exposes the true pattern rather than adding noise.
    """

    def __init__(self, condition_bits: set[int], state_format: list[Register]):
        self.condition_bits = condition_bits
        self.state_format = state_format

    def _generate_small_bit_range_inputs(self, reg: Register, local_bits: list[int]) -> list[SeedVariation]:
        """Generate inputs for registers with small bit ranges (≤8 bits)."""
        inputs = []
        min_bit = min(local_bits)
        max_bit = max(local_bits)
        bit_span = max_bit - min_bit + 1

        # Test all combinations in the bit range [min_bit, max_bit]
        for i in range(2**bit_span):
            value = i << min_bit
            inputs.append(SeedVariation(registers=[reg], values=[value]))

        return inputs

    def _generate_medium_bit_range_inputs(self, reg: Register, local_bits: list[int]) -> list[SeedVariation]:
        """Generate inputs for 16-bit registers."""
        inputs = []

        # Test every Nth value plus edge cases
        step = max(1, (2**reg.bits) // 256)  # Sample 256 values
        for value in range(0, 2**reg.bits, step):
            inputs.append(SeedVariation(registers=[reg], values=[value]))

        # Add edge cases near boundaries
        for bit_idx in local_bits:
            # Values around bit transitions
            for offset in [-1, 0, 1]:
                val = (1 << bit_idx) + offset
                if 0 <= val < 2**reg.bits:
                    inputs.append(SeedVariation(registers=[reg], values=[val]))

        return inputs

    def _generate_large_bit_range_inputs(self, reg: Register, local_bits: list[int]) -> list[SeedVariation]:
        """Generate inputs for 32/64-bit registers."""
        inputs = []
        num_cond_bits = len(local_bits)

        if num_cond_bits <= 10:  # Manageable number of combinations
            # Test all 2^N combinations of condition bits
            for combo in range(2**num_cond_bits):
                value = 0
                for i, bit_idx in enumerate(sorted(local_bits)):
                    if combo & (1 << i):
                        value |= 1 << bit_idx
                inputs.append(SeedVariation(registers=[reg], values=[value]))
        else:
            # Too many bits (>10), sample systematically
            # Test all combinations of the most significant condition bits
            top_bits = sorted(local_bits, reverse=True)[:8]  # Top 8 bits
            for combo in range(2 ** len(top_bits)):
                value = 0
                for i, bit_idx in enumerate(top_bits):
                    if combo & (1 << i):
                        value |= 1 << bit_idx
                inputs.append(SeedVariation(registers=[reg], values=[value]))

        return inputs

    def generator(self, regs: list[Register]) -> list[SeedVariation]:
        inputs = []

        # Map condition bits to their registers
        bit_offset = 0
        reg_bit_map: dict[Register, list[int]] = {}
        for reg in self.state_format:
            reg_bits = []
            for bit_pos in range(bit_offset, bit_offset + reg.bits):
                if bit_pos in self.condition_bits:
                    reg_bits.append(bit_pos - bit_offset)  # Local bit position
            if reg_bits:
                reg_bit_map[reg] = reg_bits
            bit_offset += reg.bits

        # For each register involved in conditions
        for reg, local_bits in reg_bit_map.items():
            if reg not in regs:
                continue

            # Calculate the span of condition bits within THIS REGISTER
            min_bit = min(local_bits)
            max_bit = max(local_bits)
            bit_span = max_bit - min_bit + 1

            # SYSTEMATIC COVERAGE: Test ALL values for small bit ranges
            # Key insight: If condition bits span ≤8 bits within THIS register,
            # treat it as an 8-bit problem and test all 2^N combinations
            # This works even for sub-registers like AL (bits 0-7 of EAX)
            if bit_span <= 8:
                inputs.extend(self._generate_small_bit_range_inputs(reg, local_bits))
            elif reg.bits <= 16:
                inputs.extend(self._generate_medium_bit_range_inputs(reg, local_bits))
            else:
                # For 32/64-bit registers, focus on condition bit patterns
                inputs.extend(self._generate_large_bit_range_inputs(reg, local_bits))

        return inputs


class ObservationEngine(object):
    """Engine to observe instruction behavior under various input states.
    Attributes:
    bytestring (str): Hex string representing the instruction bytes.
    archstring (str): Architecture string (e.g., X86, AMD64, ARM64).
    state_format (list[Register]): List of registers defining the CPU state format.
    Methods:
    observe_insn(): Generates observations for the instruction.
    """

    arch: ISA
    bytestring: str
    cpu: CPU
    archstring: str
    state_format: list[Register]
    DEBUG_LOG: bool

    def __init__(self, bytestring: str, archstring: str, state_format: list[Register]) -> None:
        match archstring:
            case 'X86':
                self.arch = X86()
            case 'AMD64':
                self.arch = AMD64()
            case 'ARM64':
                self.arch = ARM64()
            case 'JN':
                self.arch = JN()
            case _:
                raise Exception('Unsupported architecture: {}'.format(archstring))

        self.cpu = CPUFactory.create_cpu(archstring)
        mem_regs = {x for x in state_format if 'MEM' in x.name}
        self.cpu.set_memregs(mem_regs)

        state_string = ' '.join(['({},{})'.format(x.name, x.bits) for x in state_format])
        print('')
        print('state_format: {}'.format(state_string))
        print('')

        self.bytestring = bytestring
        self.archstring = archstring
        self.state_format = state_format
        self.DEBUG_LOG = False

    def observe_insn(self) -> list[Observation]:  # (, bytestring, archstring, state_format):
        """Produces the observations for a particular instruction.

        The planned signature of the method is as follows.
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64, JN)
            state_format (list(Register)): A list of registers which defines the order of the State object

        But due to the extremely badly written UnicornCPU (the crazy memory stuff),
        we'll have to create the ObservationEngine in such a way that it instantiate the CPU once
        for the entire observation routine, or the performance will be extremely bad.

        Args:
            None
        Returns:
            A list of Observations
        Raises:
            None
        """

        bytestring = self.bytestring
        archstring = self.archstring
        state_format = self.state_format

        observations: list[Observation] = []
        seed_ios = self._gen_seeds(bytestring, archstring, state_format)
        for seed_io in tqdm(seed_ios):
            observations.append(self._gen_observation(bytestring, archstring, state_format, seed_io))
        return observations

    def _gen_observation(
        self,
        bytestring: str,
        archstring: str,
        state_format: list[Register],
        seed_io: tuple[CpuRegisterMap, CpuRegisterMap],
    ) -> Observation:
        """Generates the Observation object for the provided seed state by performing a one-bit bitflip.

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            state_format (list(Register)): A list of registers which defines the order of the State object
        Returns:
            A single Observation object for the provided seed.
        Raises:
            None
        """

        cpu = self.cpu
        bytecode = decode_instruction_bytes(bytestring, archstring)
        seed_in, seed_out = seed_io
        seed_state = regs2bits(seed_in, state_format)
        result_state = regs2bits(seed_out, state_format)
        state_list: list[tuple[State, State]] = []

        # for reg in self.potential_use_regs:
        for reg in self.state_format:
            if 'WRITE' in reg.name or 'ADDR' in reg.name:
                continue
            # for x in tqdm(range(reg.bits)):
            for x in range(reg.bits):
                cpu.set_cpu_state(seed_in)
                pos_val = 1 << x
                mutate_val = seed_in[reg] ^ pos_val
                cpu.write_reg(reg, mutate_val)
                try:
                    sb, sa = cpu.execute(bytecode)
                except UcError:
                    continue
                except OutOfRangeException:
                    continue
                state_before = regs2bits(sb, state_format)
                state_after = regs2bits(sa, state_format)
                if not seed_state.diff(state_before):
                    continue
                state_list.append((state_before, state_after))
        return Observation((seed_state, result_state), frozenset(state_list), bytestring, archstring, state_format)

    def _gen_seeds(
        self,
        bytestring: str,
        archstring: str,
        state_format: list[Register],
        strategies: Optional[list[Strategy]] = None,
    ) -> list[tuple[CpuRegisterMap, CpuRegisterMap]]:
        """Generates a set of seed states based on the state_format using the strategies defined.

        If the state space is small (< 2^14 states), exhaustively tests all possible states.
        Otherwise, uses sampling strategies.

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64, JN)
            state_format (list(Register)): A list of registers which defines the order of the State object
            strategies (list(Strategy)): A list of Strategy objects to use for seed generation
        Returns:
            A list of seed state IO tuples
        Raises:
            None
        """
        # Calculate total state space size
        total_bits = sum(reg.bits for reg in state_format)
        total_states = 2**total_bits

        # If state space is small enough, exhaustively test all states
        if total_states < 2**14:  # 16384 states
            return self._gen_exhaustive_seeds(bytestring, archstring, state_format)

        # Otherwise, use sampling strategies
        if not strategies:
            strategies = [
                SystematicRange(),
                RandomNumber(100),
                Bitwalk(),
                ZeroWalk(),
                BitFill(),
                IEEE754Extended(10),
            ]

        seed_states: list[tuple[CpuRegisterMap, CpuRegisterMap]] = []

        # TODO: HACK to speed up, we'll ignore write and addr
        temp_state_format = [x for x in state_format if ('WRITE' not in x.name and 'ADDR' not in x.name)]
        for strategy in strategies:
            for seed_variation in tqdm(strategy.generator(temp_state_format)):
                seed_io = self._gen_random_seed_io(bytestring, archstring, seed_variation)
                # check if its successful or not, if not debug print
                if seed_io:
                    seed_states.append(seed_io)
                else:
                    if self.DEBUG_LOG:
                        print('MAX_TRIES-{}-{}-{}-{}'.format(bytestring, archstring, state_format, seed_variation))
                    continue

        return seed_states

    def _gen_exhaustive_seeds(
        self,
        bytestring: str,
        archstring: str,
        state_format: list[Register],
    ) -> list[tuple[CpuRegisterMap, CpuRegisterMap]]:
        """Generate all possible seed states exhaustively for small state spaces.

        Args:
            bytestring: Hex string of instruction
            archstring: Architecture string
            state_format: List of registers defining state

        Returns:
            List of all possible (input_state, output_state) tuples
        """
        total_bits = sum(reg.bits for reg in state_format)
        total_states = 2**total_bits

        seed_states: list[tuple[CpuRegisterMap, CpuRegisterMap]] = []
        bytecode = decode_instruction_bytes(bytestring, archstring)
        cpu = CPUFactory.create_cpu(archstring)

        desc = f'Generating exhaustive seeds ({total_states} states)'
        for state_val in tqdm(range(total_states), desc=desc):
            # Convert state value to register values
            input_state = CpuRegisterMap()
            bit_offset = 0

            for reg in state_format:
                reg_value = (state_val >> bit_offset) & ((1 << reg.bits) - 1)
                input_state[reg] = reg_value
                bit_offset += reg.bits

            # Execute instruction to get output state
            cpu.set_cpu_state(input_state)
            try:
                _, output_state = cpu.execute(bytecode)
                seed_states.append((input_state, output_state))
            except (UcError, OutOfRangeException):
                continue

        return seed_states

    def _gen_seed_io(
        self,
        bytestring: str,
        archstring: str,
        seed_in: CpuRegisterMap,
        num_tries: int = 255,
    ) -> tuple[CpuRegisterMap, CpuRegisterMap] | None:
        """Generates a pair of in / out CPUState, seed_in, seed_out,
        by executing the instruction using a the provided CPUState

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            seed_in ( dict{Register:Integer } ): The input seed state
        Returns:
            Returns the seed input / output states as tuple(CPUState, CPUState) if successful.
            Otherwise returns None if it fails to find within num_tries
        Raises:
            Exception
        """

        cpu = self.cpu
        bytecode = decode_instruction_bytes(bytestring, archstring)

        for x in range(num_tries):
            try:
                cpu.set_cpu_state(seed_in)
                sb, sa = cpu.execute(bytecode)
                break
            except OutOfRangeException:
                if x == num_tries - 1:
                    return None
                continue
            except UcError:
                if x == num_tries - 1:
                    return None
                continue
        return sb, sa

    def _gen_random_seed_io(
        self,
        bytestring: str,
        archstring: str,
        seed_variation: SeedVariation,
        num_tries: int = 255,
    ) -> tuple[CpuRegisterMap, CpuRegisterMap] | None:
        """Generates a pair of in / out CPUState, seed_in, seed_out, by executing the instruction using a randomly
        generated CPUState with the seed_variation applied.

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            seed_variation (SeedVariation): The seed variation with registers and values to set
        Returns:
            Returns the seed input / output states as tuple(CPUState, CPUState) if successful.
            Otherwise returns None if it fails to find within num_tries
        Raises:
            Exception
        """

        cpu = self.cpu
        bytecode = decode_instruction_bytes(bytestring, archstring)
        regs2mod, vals2mod = seed_variation.registers, seed_variation.values

        for x in range(num_tries):
            try:
                cpu.randomize_regs()
                cpu.write_regs(regs2mod, vals2mod)
                sb, sa = cpu.execute(bytecode)
                break
            except UcError:
                if x == num_tries - 1:
                    return None
                continue
            except OutOfRangeException:
                if x == num_tries - 1:
                    return None
                continue
        return sb, sa

    def refine_with_targeted_observations(
        self,
        condition_bits: set[int],
        num_refinement_samples: int = 100,
    ) -> list[Observation]:
        """Generate targeted observations to validate/refute discovered conditions.

        After initial condition discovery, this method generates adversarial test cases
        that specifically target the condition bits to verify if they truly determine
        the taint propagation behavior.

        Args:
            condition_bits: Set of bit positions that appear in discovered conditions
            num_refinement_samples: Number of additional targeted samples to generate

        Returns:
            List of new observations targeting condition bits
        """
        # Generate targeted observations using the condition-aware strategy
        targeted_strategy = ConditionTargetedStrategy(condition_bits, self.state_format)

        # Filter state_format to exclude memory-related registers
        temp_state_format = [x for x in self.state_format if 'WRITE' not in x.name and 'ADDR' not in x.name]

        seed_ios = []
        for seed_variation in tqdm(
            targeted_strategy.generator(temp_state_format),
            desc='Generating refinement seeds',
        ):
            seed_io = self._gen_random_seed_io(
                self.bytestring,
                self.archstring,
                seed_variation,
            )
            if seed_io:
                seed_ios.append(seed_io)
                if len(seed_ios) >= num_refinement_samples:
                    break

        # Generate observations from these targeted seeds
        refinement_observations = []
        for seed_io in tqdm(seed_ios, desc='Generating refinement observations'):
            obs = self._gen_observation(self.bytestring, self.archstring, self.state_format, seed_io)
            refinement_observations.append(obs)

        return refinement_observations

    def _gen_refinement_observations_helper(
        self,
        seed_ios: list[tuple[CpuRegisterMap, CpuRegisterMap]],
        num_refinement_samples: int,
    ) -> list[Observation]:
        """Helper to complete refinement observation generation."""
        # Check if we have enough samples
        if len(seed_ios) >= num_refinement_samples:
            seed_ios = seed_ios[:num_refinement_samples]

        # Generate observations from these targeted seeds
        refinement_observations = []
        for seed_io in tqdm(seed_ios, desc='Generating refinement observations'):
            obs = self._gen_observation(self.bytestring, self.archstring, self.state_format, seed_io)
            refinement_observations.append(obs)

        return refinement_observations
