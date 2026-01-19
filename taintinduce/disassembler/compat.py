"""
Disassembler wrapper to replace squirrel.squirrel_disassembler.
Uses Capstone directly without the squirrel wrapper.
"""

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    Cs,
    CsInsn,
)

from taintinduce.disassembler.exceptions import ParseInsnException
from taintinduce.isa.jn_isa import decode_hex_string as decode_jn_hex_string


class JNInsnWrapper:
    """Wrapper to make JN instructions compatible with Capstone's CsInsn interface."""

    def __init__(self, jn_insn):
        self._jn_insn = jn_insn
        # Use the JNInstruction's mnemonic property for proper formatting
        # The mnemonic includes both the operation and operands
        full_insn = jn_insn.mnemonic
        # Split into mnemonic and operands (e.g., "ADD R1, 0xA" -> "ADD" and "R1, 0xA")
        parts = full_insn.split(maxsplit=1)
        self.mnemonic = parts[0] if parts else ''
        self.op_str = parts[1] if len(parts) > 1 else ''


class SquirrelDisassemblerJN:
    """JN ISA disassembler compatible with Capstone interface."""

    def __init__(self, arch_str: str) -> None:
        self.arch_str = arch_str

    def disassemble(self, bytecode: bytes | str, address: int = 0x1000) -> JNInsnWrapper:  # noqa: ARG002
        """Disassemble JN bytecode and return wrapped instruction object."""
        # Convert bytes to hex string if needed
        if isinstance(bytecode, bytes):
            bytecode = bytecode.hex()

        try:
            jn_insn = decode_jn_hex_string(str(bytecode))
            return JNInsnWrapper(jn_insn)
        except Exception as e:
            raise ParseInsnException(f'Failed to disassemble JN instruction: {e}') from e


class SquirrelDisassemblerCapstone:
    """Capstone-based disassembler compatible with old squirrel interface."""

    md: Cs
    arch_str: str

    def __init__(self, arch_str: str) -> None:
        self.arch_mapping: dict[str, tuple[int, int]] = {
            'X86': (CS_ARCH_X86, CS_MODE_32),
            'AMD64': (CS_ARCH_X86, CS_MODE_64),
            'ARM64': (CS_ARCH_ARM64, CS_MODE_ARM),
            'ARM32': (CS_ARCH_ARM, CS_MODE_ARM),
        }
        self.arch_str = arch_str
        arch, mode = self.arch_mapping[self.arch_str]
        self.md = Cs(arch, mode)
        self.md.detail = True

    def disassemble(self, bytecode: bytes | str, address: int = 0x1000) -> CsInsn:
        """Disassemble bytecode and return wrapped Capstone instruction object."""
        if not self.md:
            raise RuntimeError('Capstone not initialized')

        # Convert hex string to bytes if needed
        if isinstance(bytecode, str):
            bytecode = bytes.fromhex(bytecode)

        insns = list(self.md.disasm(bytecode, address))
        if not insns:
            raise ParseInsnException(f'Failed to disassemble bytecode at address {hex(address)}')
        if len(insns) != 1:
            raise ParseInsnException('Multiple instructions disassembled; expected a single instruction.')
        if not isinstance(insns[0], CsInsn):
            raise ParseInsnException('Disassembled object is not a CsInsn instance.')
        return insns[0]


class SquirrelDisassemblerZydis(SquirrelDisassemblerCapstone):
    """
    Zydis disassembler stub - falls back to Capstone for x86/x64, uses JN decoder for JN.
    Original squirrel used Zydis for x86/x64, but Capstone works fine.
    """

    def __new__(cls, arch_str: str):  # type: ignore[no-untyped-def]
        """Create appropriate disassembler based on architecture."""
        if arch_str == 'JN':
            return SquirrelDisassemblerJN(arch_str)
        return super().__new__(cls)
