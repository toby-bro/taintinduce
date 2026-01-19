"""Unit tests for the disassembler insn_info module."""

import pytest

from taintinduce.disassembler.exceptions import (
    ParseInsnException,
    UnsupportedArchException,
)
from taintinduce.disassembler.insn_info import Disassembler, InsnInfo
from taintinduce.isa.jn_registers import JN_REG_NZCV
from taintinduce.isa.x86_registers import X86_REG_EAX, X86_REG_EFLAGS


class TestDisassemblerX86:
    """Test cases for X86 (32-bit) disassembly."""

    def test_simple_mov_eax_ebx(self):
        """Test MOV EAX, EBX (89 d8)."""
        dis = Disassembler('X86', '89d8')
        assert dis.insn_info.archstring == 'X86'
        assert dis.insn_info.bytestring == '89d8'
        assert isinstance(dis.insn_info.cond_reg, X86_REG_EFLAGS)
        # Should track EAX and EBX
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EBX' in reg_names

    def test_add_eax_immediate(self):
        """Test ADD EAX, imm32 (05 XX XX XX XX)."""
        dis = Disassembler('X86', '05010000FF')
        assert dis.insn_info.archstring == 'X86'
        # Should track EAX and EFLAGS
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EFLAGS' in reg_names

    def test_and_eax_immediate_complete(self):
        """Test AND EAX, imm32 (25 XX XX XX XX) - complete 5 bytes."""
        dis = Disassembler('X86', '25FFFFFF7F')
        assert dis.insn_info.archstring == 'X86'
        assert dis.insn_info.bytestring == '25FFFFFF7F'
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EFLAGS' in reg_names

    def test_and_eax_immediate_incomplete_fails(self):
        """Test that incomplete AND EAX instruction (25 FF FF - only 3 bytes) fails."""
        with pytest.raises(ParseInsnException, match='capstone disassemble cannot translate'):
            Disassembler('X86', '25FFFF')

    def test_push_eax(self):
        """Test PUSH EAX (50)."""
        dis = Disassembler('X86', '50')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'ESP' in reg_names  # Stack pointer is implicitly modified

    def test_pop_eax(self):
        """Test POP EAX (58)."""
        dis = Disassembler('X86', '58')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'ESP' in reg_names

    def test_xor_eax_eax(self):
        """Test XOR EAX, EAX (31 c0) - common zeroing idiom."""
        dis = Disassembler('X86', '31c0')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EFLAGS' in reg_names

    def test_inc_eax(self):
        """Test INC EAX (40)."""
        dis = Disassembler('X86', '40')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EFLAGS' in reg_names

    def test_conditional_jump(self):
        """Test JZ (74 XX) - conditional jump."""
        dis = Disassembler('X86', '7402')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EFLAGS' in reg_names

    def test_test_eax_eax(self):
        """Test TEST EAX, EAX (85 c0)."""
        dis = Disassembler('X86', '85c0')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EFLAGS' in reg_names

    def test_empty_bytecode_fails(self):
        """Test that empty bytecode fails."""
        with pytest.raises(ParseInsnException):
            Disassembler('X86', '')

    def test_invalid_bytecode_fails(self):
        """Test that invalid bytecode fails."""
        with pytest.raises(ValueError, match=r'non-hexadecimal|invalid literal'):
            Disassembler('X86', 'GGGG')  # Invalid hex


class TestDisassemblerAMD64:
    """Test cases for AMD64 (64-bit) disassembly."""

    def test_mov_rax_rbx(self):
        """Test MOV RAX, RBX (48 89 d8)."""
        dis = Disassembler('AMD64', '4889d8')
        assert dis.insn_info.archstring == 'AMD64'
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'RAX' in reg_names
        assert 'RBX' in reg_names

    def test_add_rax_immediate(self):
        """Test ADD RAX, imm32 (48 05 XX XX XX XX)."""
        dis = Disassembler('AMD64', '480501000000')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'RAX' in reg_names
        assert 'EFLAGS' in reg_names

    def test_push_rax(self):
        """Test PUSH RAX (50)."""
        dis = Disassembler('AMD64', '50')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'RAX' in reg_names
        assert 'RSP' in reg_names

    def test_xor_rax_rax(self):
        """Test XOR RAX, RAX (48 31 c0)."""
        dis = Disassembler('AMD64', '4831c0')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'RAX' in reg_names
        assert 'EFLAGS' in reg_names


class TestDisassemblerARM64:
    """Test cases for ARM64 disassembly."""

    def test_mov_x0_x1(self):
        """Test MOV X0, X1 (e0 03 01 aa)."""
        dis = Disassembler('ARM64', 'e00301aa')
        assert dis.insn_info.archstring == 'ARM64'
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'X0' in reg_names
        assert 'X1' in reg_names

    def test_add_x0_x1_x2(self):
        """Test ADD X0, X1, X2 (20 00 02 8b)."""
        dis = Disassembler('ARM64', '2000028b')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'X0' in reg_names
        assert 'X1' in reg_names
        assert 'X2' in reg_names


class TestDisassemblerArchitecture:
    """Test architecture handling."""

    def test_unsupported_arch_fails(self):
        """Test that unsupported architecture raises exception."""
        with pytest.raises(UnsupportedArchException):
            Disassembler('MIPS', '00000000')

    def test_supported_architectures(self):
        """Test all supported architectures can be instantiated."""
        supported = ['X86', 'AMD64', 'ARM64']
        for arch in supported:
            # Use NOP-like instructions that should work
            if arch in ('X86', 'AMD64'):
                dis = Disassembler(arch, '90')  # NOP
            else:  # ARM64
                dis = Disassembler(arch, 'd503201f')  # NOP
            assert dis.insn_info.archstring == arch


class TestInsnInfo:
    """Test InsnInfo class."""

    def test_construction_with_valid_args(self):
        """Test InsnInfo construction with valid arguments."""
        info = InsnInfo(
            archstring='X86',
            bytestring='90',
            state_format=[X86_REG_EAX()],
            cond_reg=X86_REG_EFLAGS(),
        )
        assert info.archstring == 'X86'
        assert info.bytestring == '90'
        assert len(info.state_format) == 1
        assert isinstance(info.cond_reg, X86_REG_EFLAGS)

    def test_construction_without_required_args_fails(self):
        """Test that InsnInfo construction fails without required args."""
        with pytest.raises(Exception, match='Invalid arguments'):
            InsnInfo()


class TestRealWorldInstructions:
    """Test real-world instruction examples."""

    def test_complex_x86_instruction(self):
        """Test a complex X86 instruction with memory operand."""
        # MOV EAX, [EBX+4]
        dis = Disassembler('X86', '8b4304')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        # Note: Memory operands might not always track base registers implicitly

    def test_amd64_with_rex_prefix(self):
        """Test AMD64 instruction with REX prefix."""
        # MOV RAX, [RBX]
        dis = Disassembler('AMD64', '488b03')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'RAX' in reg_names
        # Note: Memory operands might not always track base registers implicitly

    def test_instruction_with_multiple_operands(self):
        """Test instruction affecting multiple registers."""
        # IMUL EAX, EBX, 5
        dis = Disassembler('X86', '6bc305')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'EAX' in reg_names
        assert 'EBX' in reg_names

    def test_string_operation(self):
        """Test string operation that uses implicit registers."""
        # MOVSB (moves byte from DS:ESI to ES:EDI)
        dis = Disassembler('X86', 'a4')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        # Should include ESI, EDI
        assert 'ESI' in reg_names or 'SI' in reg_names
        assert 'EDI' in reg_names or 'DI' in reg_names


class TestDisassemblerJN:
    """Test cases for JN (Just Nibbles) ISA."""

    def test_add_register_instruction(self):
        """Test ADD R1, R2 (opcode 0 - register variant).

        Register instructions should include R1, R2, and NZCV in state_format.
        """
        dis = Disassembler('JN', '0')
        assert dis.insn_info.archstring == 'JN'
        assert dis.insn_info.bytestring in ('0', '00')

        # Should track R1, R2, and NZCV
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names, 'R1 should be in state_format for register instruction'
        assert 'R2' in reg_names, 'R2 should be in state_format for register instruction'
        assert 'NZCV' in reg_names, 'NZCV should be in state_format'
        assert len(dis.insn_info.state_format) == 3

    def test_add_immediate_instruction(self):
        """Test ADD R1, #0xA (opcode 1A - immediate variant).

        Immediate instructions should ONLY include R1 and NZCV (R2 excluded).
        """
        dis = Disassembler('JN', '1A')
        assert dis.insn_info.archstring == 'JN'
        assert dis.insn_info.bytestring == '1A'

        # Should track R1 and NZCV, but NOT R2
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names, 'R1 should be in state_format for immediate instruction'
        assert 'R2' not in reg_names, 'R2 should NOT be in state_format for immediate instruction'
        assert 'NZCV' in reg_names, 'NZCV should be in state_format'
        assert len(dis.insn_info.state_format) == 2

    def test_or_register_instruction(self):
        """Test OR R1, R2 (opcode 2 - register variant)."""
        dis = Disassembler('JN', '2')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names
        assert 'R2' in reg_names
        assert 'NZCV' in reg_names
        assert len(dis.insn_info.state_format) == 3

    def test_or_immediate_instruction(self):
        """Test OR R1, #0xF (opcode 3F - immediate variant)."""
        dis = Disassembler('JN', '3F')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names
        assert 'R2' not in reg_names
        assert 'NZCV' in reg_names
        assert len(dis.insn_info.state_format) == 2

    def test_and_register_instruction(self):
        """Test AND R1, R2 (opcode 4 - register variant)."""
        dis = Disassembler('JN', '4')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names
        assert 'R2' in reg_names
        assert 'NZCV' in reg_names

    def test_and_immediate_instruction(self):
        """Test AND R1, #0x5 (opcode 55 - immediate variant)."""
        dis = Disassembler('JN', '55')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names
        assert 'R2' not in reg_names
        assert 'NZCV' in reg_names

    def test_xor_register_instruction(self):
        """Test XOR R1, R2 (opcode 6 - register variant)."""
        dis = Disassembler('JN', '6')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names
        assert 'R2' in reg_names
        assert 'NZCV' in reg_names

    def test_xor_immediate_instruction(self):
        """Test XOR R1, #0x9 (opcode 79 - immediate variant)."""
        dis = Disassembler('JN', '79')
        reg_names = {reg.name for reg in dis.insn_info.state_format}
        assert 'R1' in reg_names
        assert 'R2' not in reg_names
        assert 'NZCV' in reg_names

    def test_all_register_instructions_include_r2(self):
        """Verify all register-variant instructions include R2."""
        register_opcodes = ['0', '2', '4', '6']  # Even opcodes = register
        for opcode in register_opcodes:
            dis = Disassembler('JN', opcode)
            reg_names = {reg.name for reg in dis.insn_info.state_format}
            assert 'R2' in reg_names, f'Opcode {opcode} should include R2 (register variant)'

    def test_all_immediate_instructions_exclude_r2(self):
        """Verify all immediate-variant instructions exclude R2."""
        immediate_opcodes = ['1A', '3F', '55', '79']  # Odd opcodes with immediate
        for opcode in immediate_opcodes:
            dis = Disassembler('JN', opcode)
            reg_names = {reg.name for reg in dis.insn_info.state_format}
            assert 'R2' not in reg_names, f'Opcode {opcode} should NOT include R2 (immediate variant)'

    def test_jn_cond_reg_is_nzvc(self):
        """Verify JN uses NZCV as condition register."""
        dis = Disassembler('JN', '1A')
        assert isinstance(dis.insn_info.cond_reg, JN_REG_NZCV)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
