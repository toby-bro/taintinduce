"""Tests for JN (Just Nibbles) ISA.

Test the simplified 4-bit ISA implementation.
"""

from taintinduce.isa.jn_isa import JNInstruction, JNOpcode, decode_hex_string, encode_instruction
from taintinduce.isa.jn_registers import JN_REG_R1, JN_REG_R2, get_jn_state_format


class TestJNRegisters:
    """Test JN register definitions."""

    def test_r1_properties(self):
        """Test R1 register properties."""
        r1 = JN_REG_R1()
        assert r1.name == 'R1'
        assert r1.bits == 4
        assert r1.structure == [4]

    def test_r2_properties(self):
        """Test R2 register properties."""
        r2 = JN_REG_R2()
        assert r2.name == 'R2'
        assert r2.bits == 4
        assert r2.structure == [4]

    def test_state_format(self):
        """Test standard state format."""
        state_format = get_jn_state_format()
        assert len(state_format) == 3
        assert state_format[0].name == 'R1'
        assert state_format[1].name == 'R2'
        assert state_format[2].name == 'NZVC'
        assert sum(reg.bits for reg in state_format) == 12


class TestJNInstructionEncoding:
    """Test JN instruction encoding and decoding."""

    def test_add_r1_r2_encoding(self):
        """Test ADD R1, R2 encoding."""
        instr = JNInstruction(JNOpcode.ADD_R1_R2)
        assert instr.to_bytes() == b'\x00'
        assert not instr.has_immediate

    def test_add_r1_imm_encoding(self):
        """Test ADD R1, imm4 encoding."""
        instr = JNInstruction(JNOpcode.ADD_R1_IMM, 0xA)
        assert instr.to_bytes() == b'\x01\x0a'
        assert instr.has_immediate

    def test_decode_add_r1_r2(self):
        """Test decoding ADD R1, R2."""
        instr = JNInstruction.from_bytes(b'\x00')
        assert instr.opcode == JNOpcode.ADD_R1_R2
        assert instr.immediate is None

    def test_decode_add_r1_imm(self):
        """Test decoding ADD R1, imm4."""
        instr = JNInstruction.from_bytes(b'\x01\x0a')
        assert instr.opcode == JNOpcode.ADD_R1_IMM
        assert instr.immediate == 0xA

    def test_hex_string_decode(self):
        """Test decoding from hex string."""
        instr = decode_hex_string('1A')
        assert instr.opcode == JNOpcode.ADD_R1_IMM
        assert instr.immediate == 0xA

    def test_encode_instruction_helper(self):
        """Test instruction encoding helper."""
        hex_str = encode_instruction(JNOpcode.ADD_R1_IMM, 0xB)
        assert hex_str == '010B'

    def test_all_opcodes_encode_decode(self):
        """Test all opcodes can be encoded and decoded."""
        opcodes = [
            (JNOpcode.ADD_R1_R2, None),
            (JNOpcode.ADD_R1_IMM, 0x5),
            (JNOpcode.OR_R1_R2, None),
            (JNOpcode.OR_R1_IMM, 0x7),
            (JNOpcode.AND_R1_R2, None),
            (JNOpcode.AND_R1_IMM, 0x3),
            (JNOpcode.XOR_R1_R2, None),
            (JNOpcode.XOR_R1_IMM, 0xF),
        ]

        for opcode, imm in opcodes:
            instr = JNInstruction(opcode, imm)
            encoded = instr.to_bytes()
            decoded = JNInstruction.from_bytes(encoded)
            assert decoded.opcode == opcode
            assert decoded.immediate == imm


class TestJNInstructionExecution:
    """Test JN instruction execution semantics."""

    def test_add_r1_r2_no_overflow(self):
        """Test ADD R1, R2 without overflow."""
        instr = JNInstruction(JNOpcode.ADD_R1_R2)
        new_r1, new_r2 = instr.execute(r1=3, r2=5)
        assert new_r1 == 8  # 3 + 5 = 8
        assert new_r2 == 5  # R2 unchanged

    def test_add_r1_r2_with_overflow(self):
        """Test ADD R1, R2 with overflow (wraps at 16)."""
        instr = JNInstruction(JNOpcode.ADD_R1_R2)
        new_r1, new_r2 = instr.execute(r1=12, r2=7)
        assert new_r1 == 3  # (12 + 7) mod 16 = 3
        assert new_r2 == 7  # R2 unchanged

    def test_add_r1_imm(self):
        """Test ADD R1, imm4."""
        instr = JNInstruction(JNOpcode.ADD_R1_IMM, 0x2)
        new_r1, new_r2 = instr.execute(r1=5, r2=9)
        assert new_r1 == 7  # 5 + 2 = 7
        assert new_r2 == 9  # R2 unchanged

    def test_or_r1_r2(self):
        """Test OR R1, R2."""
        instr = JNInstruction(JNOpcode.OR_R1_R2)
        new_r1, new_r2 = instr.execute(r1=0b1010, r2=0b0101)
        assert new_r1 == 0b1111  # 0xA | 0x5 = 0xF
        assert new_r2 == 0b0101

    def test_or_r1_imm(self):
        """Test OR R1, imm4."""
        instr = JNInstruction(JNOpcode.OR_R1_IMM, 0b0011)
        new_r1, new_r2 = instr.execute(r1=0b1000, r2=0b0000)
        assert new_r1 == 0b1011  # 0x8 | 0x3 = 0xB
        assert new_r2 == 0b0000

    def test_and_r1_r2(self):
        """Test AND R1, R2."""
        instr = JNInstruction(JNOpcode.AND_R1_R2)
        new_r1, new_r2 = instr.execute(r1=0b1111, r2=0b0101)
        assert new_r1 == 0b0101  # 0xF & 0x5 = 0x5
        assert new_r2 == 0b0101

    def test_and_r1_imm(self):
        """Test AND R1, imm4."""
        instr = JNInstruction(JNOpcode.AND_R1_IMM, 0b1100)
        new_r1, new_r2 = instr.execute(r1=0b1010, r2=0b0000)
        assert new_r1 == 0b1000  # 0xA & 0xC = 0x8
        assert new_r2 == 0b0000

    def test_xor_r1_r2(self):
        """Test XOR R1, R2."""
        instr = JNInstruction(JNOpcode.XOR_R1_R2)
        new_r1, new_r2 = instr.execute(r1=0b1010, r2=0b0101)
        assert new_r1 == 0b1111  # 0xA ^ 0x5 = 0xF
        assert new_r2 == 0b0101

    def test_xor_r1_imm(self):
        """Test XOR R1, imm4."""
        instr = JNInstruction(JNOpcode.XOR_R1_IMM, 0b1111)
        new_r1, new_r2 = instr.execute(r1=0b1010, r2=0b0000)
        assert new_r1 == 0b0101  # 0xA ^ 0xF = 0x5
        assert new_r2 == 0b0000


class TestJNInstructionMnemonics:
    """Test instruction mnemonic generation."""

    def test_add_r1_r2_mnemonic(self):
        """Test ADD R1, R2 mnemonic."""
        instr = JNInstruction(JNOpcode.ADD_R1_R2)
        assert instr.mnemonic == 'ADD R1, R2'

    def test_add_r1_imm_mnemonic(self):
        """Test ADD R1, imm4 mnemonic."""
        instr = JNInstruction(JNOpcode.ADD_R1_IMM, 0xA)
        assert instr.mnemonic == 'ADD R1, 0xA'

    def test_xor_r1_imm_mnemonic(self):
        """Test XOR R1, imm4 mnemonic."""
        instr = JNInstruction(JNOpcode.XOR_R1_IMM, 0xF)
        assert instr.mnemonic == 'XOR R1, 0xF'
