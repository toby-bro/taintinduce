"""JN (Just Nibbles) ISA Instruction Set.

A simplified 4-bit ISA with 8 instructions for testing taint inference.

Instruction encoding:
- Opcode: 1 hex char (4 bits)
- Immediate (if needed): 1 hex char (4 bits)

Instructions:
0x0: ADD R1, R2     - R1 = R1 + R2 (mod 16)
0x1: ADD R1, imm4   - R1 = R1 + imm4 (mod 16)
0x2: OR  R1, R2     - R1 = R1 | R2
0x3: OR  R1, imm4   - R1 = R1 | imm4
0x4: AND R1, R2     - R1 = R1 & R2
0x5: AND R1, imm4   - R1 = R1 & imm4
0x6: XOR R1, R2     - R1 = R1 ^ R2
0x7: XOR R1, imm4   - R1 = R1 ^ imm4

State layout (12 bits total = 3 nibbles):
  bits 0-3:   R1 (4 bits)
  bits 4-7:   R2 (4 bits)
  bits 8-11:  NZVC (4 bits) - Condition flags (not yet updated by instructions)
"""

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


class JNOpcode(IntEnum):
    """JN instruction opcodes."""

    ADD_R1_R2 = 0x0
    ADD_R1_IMM = 0x1
    OR_R1_R2 = 0x2
    OR_R1_IMM = 0x3
    AND_R1_R2 = 0x4
    AND_R1_IMM = 0x5
    XOR_R1_R2 = 0x6
    XOR_R1_IMM = 0x7


@dataclass
class JNInstruction:
    """Represents a JN instruction."""

    opcode: JNOpcode
    immediate: Optional[int] = None  # Only for immediate instructions

    @property
    def has_immediate(self) -> bool:
        """Check if this instruction has an immediate operand."""
        return self.opcode in [
            JNOpcode.ADD_R1_IMM,
            JNOpcode.OR_R1_IMM,
            JNOpcode.AND_R1_IMM,
            JNOpcode.XOR_R1_IMM,
        ]

    @property
    def mnemonic(self) -> str:
        """Get the instruction mnemonic."""
        mnemonics = {
            JNOpcode.ADD_R1_R2: 'ADD R1, R2',
            JNOpcode.ADD_R1_IMM: f'ADD R1, 0x{self.immediate:X}' if self.immediate is not None else 'ADD R1, imm4',
            JNOpcode.OR_R1_R2: 'OR R1, R2',
            JNOpcode.OR_R1_IMM: f'OR R1, 0x{self.immediate:X}' if self.immediate is not None else 'OR R1, imm4',
            JNOpcode.AND_R1_R2: 'AND R1, R2',
            JNOpcode.AND_R1_IMM: f'AND R1, 0x{self.immediate:X}' if self.immediate is not None else 'AND R1, imm4',
            JNOpcode.XOR_R1_R2: 'XOR R1, R2',
            JNOpcode.XOR_R1_IMM: f'XOR R1, 0x{self.immediate:X}' if self.immediate is not None else 'XOR R1, imm4',
        }
        return mnemonics[self.opcode]

    def to_bytes(self) -> bytes:
        """Encode instruction to bytes."""
        if self.has_immediate:
            if self.immediate is None:
                raise ValueError(f'Instruction {self.mnemonic} requires immediate value')
            # Encode as two separate nibbles/bytes: opcode, immediate
            return bytes([self.opcode & 0xF, self.immediate & 0xF])
        return bytes([self.opcode & 0xF])

    @classmethod
    def from_bytes(cls, data: bytes) -> 'JNInstruction':
        """Decode instruction from bytes."""
        if len(data) == 0:
            raise ValueError('Empty instruction data')

        opcode = JNOpcode(data[0])
        immediate = None

        # Check if this opcode requires an immediate
        if opcode in [JNOpcode.ADD_R1_IMM, JNOpcode.OR_R1_IMM, JNOpcode.AND_R1_IMM, JNOpcode.XOR_R1_IMM]:
            if len(data) < 2:
                raise ValueError(f'Instruction {opcode.name} requires immediate value')
            immediate = data[1] & 0xF

        return cls(opcode, immediate)

    @staticmethod
    def compute_flags(result: int, operand1: int, operand2: int, is_add: bool) -> int:
        """Compute NZCV flags for a 4-bit result.

        Args:
            result: 4-bit result value (may have carry bit in bit 4)
            operand1: First operand (4 bits)
            operand2: Second operand (4 bits)
            is_add: True if operation is ADD (for C and V flags)

        Returns:
            4-bit NZCV flags: N=bit3, Z=bit2, C=bit1, V=bit0
        """
        result_4bit = result & 0xF

        # N (Negative): bit 3 of result (sign bit in 4-bit 2's complement)
        n = 1 if (result_4bit & 0x8) != 0 else 0

        # Z (Zero): result is zero
        z = 1 if result_4bit == 0 else 0

        # C (Carry): for ADD, carry out from bit 3
        if is_add:
            c = 1 if (result & 0x10) != 0 else 0  # Carry from bit 3 to bit 4
        else:
            c = 0  # Non-add operations don't set carry

        # V (Overflow): for ADD, signed overflow in 4-bit 2's complement
        # Overflow occurs when:
        # - Adding two positive numbers gives negative result
        # - Adding two negative numbers gives positive result
        if is_add:
            sign_op1 = (operand1 & 0x8) != 0
            sign_op2 = (operand2 & 0x8) != 0
            sign_result = (result_4bit & 0x8) != 0
            v = 1 if (sign_op1 == sign_op2) and (sign_op1 != sign_result) else 0
        else:
            v = 0  # Non-add operations don't set overflow

        # Pack NZCV into 4 bits: NZCV from bit 3 to bit 0
        return (n << 3) | (z << 2) | (c << 1) | v

    def execute(self, r1: int, r2: int) -> tuple[int, int]:
        """Execute the instruction and return new register values.

        Args:
            r1: Current R1 value (4 bits)
            r2: Current R2 value (4 bits)

        Returns:
            Tuple of (new_r1, new_r2)
        """
        # Ensure inputs are 4-bit values
        r1 = r1 & 0xF
        r2 = r2 & 0xF

        if self.opcode == JNOpcode.ADD_R1_R2:
            return (r1 + r2) & 0xF, r2
        if self.opcode == JNOpcode.ADD_R1_IMM:
            assert self.immediate is not None
            return (r1 + (self.immediate & 0xF)) & 0xF, r2
        if self.opcode == JNOpcode.OR_R1_R2:
            return r1 | r2, r2
        if self.opcode == JNOpcode.OR_R1_IMM:
            assert self.immediate is not None
            return r1 | (self.immediate & 0xF), r2
        if self.opcode == JNOpcode.AND_R1_R2:
            return r1 & r2, r2
        if self.opcode == JNOpcode.AND_R1_IMM:
            assert self.immediate is not None
            return r1 & (self.immediate & 0xF), r2
        if self.opcode == JNOpcode.XOR_R1_R2:
            return r1 ^ r2, r2
        if self.opcode == JNOpcode.XOR_R1_IMM:
            assert self.immediate is not None
            return r1 ^ (self.immediate & 0xF), r2
        raise ValueError(f'Unknown opcode: {self.opcode}')


def decode_hex_string(hex_str: str) -> JNInstruction:
    """Decode a hex string to a JN instruction.

    Args:
        hex_str: Hex string where each character is a nibble (4 bits).
                '6' = XOR R1, R2 (single nibble opcode)
                '7A' = XOR R1, #0xA (opcode=7, immediate=A)
                No padding - length determines if immediate or register variant.

    Returns:
        Decoded JNInstruction
    """
    # Remove any spaces or 0x/0X prefix (case insensitive)
    hex_str = hex_str.replace(' ', '')
    # Handle both 0x and 0X prefixes
    if hex_str.lower().startswith('0x'):
        hex_str = hex_str[2:]

    # Each hex char is a nibble - convert to bytes where each byte holds one nibble value
    data = bytes([int(c, 16) for c in hex_str])
    return JNInstruction.from_bytes(data)


def encode_instruction(opcode: JNOpcode, immediate: Optional[int] = None) -> str:
    """Encode an instruction to hex string.

    Args:
        opcode: The instruction opcode
        immediate: Optional immediate value (for imm instructions)

    Returns:
        Hex string representation where each hex char is a nibble
    """
    instr = JNInstruction(opcode, immediate)
    bytecode = instr.to_bytes()
    # Each byte holds a nibble value (0-15), output as single hex char
    return ''.join(f'{b:X}' for b in bytecode)
