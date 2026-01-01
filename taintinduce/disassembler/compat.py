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
    Zydis disassembler stub - falls back to Capstone.
    Original squirrel used Zydis for x86/x64, but Capstone works fine.
    """
