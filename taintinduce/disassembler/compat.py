"""
Disassembler wrapper to replace squirrel.squirrel_disassembler.
Uses Capstone directly without the squirrel wrapper.
"""

from typing import Any, Optional

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    Cs,
)

from taintinduce.disassembler.exceptions import ParseInsnException


class InstructionWrapper:
    """Wrapper around Capstone instruction to provide squirrel-compatible interface."""

    def __init__(self, insn: Any) -> None:
        self._insn = insn

    def reg_reads(self) -> list[int]:
        """Get list of registers read by this instruction."""
        return list(self._insn.regs_read)

    def reg_writes(self) -> list[int]:
        """Get list of registers written by this instruction."""
        return list(self._insn.regs_write)

    def __getattr__(self, name: str) -> Any:
        """Forward all other attributes to the wrapped instruction."""
        return getattr(self._insn, name)


class DisassemblerBase:
    """Base class for disassemblers."""

    def __init__(self, arch_str: str) -> None:
        self.arch_str: str = arch_str
        self.md: Optional[Cs] = None
        self._setup_capstone()

    def _setup_capstone(self) -> None:
        """Setup Capstone disassembler. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement _setup_capstone")

    def disassemble(self, bytecode: bytes | str, address: int = 0x1000) -> InstructionWrapper:
        """Disassemble bytecode and return wrapped Capstone instruction object."""
        if not self.md:
            raise RuntimeError("Capstone not initialized")

        # Convert hex string to bytes if needed
        if isinstance(bytecode, str):
            bytecode = bytes.fromhex(bytecode)

        insns = list(self.md.disasm(bytecode, address))
        if not insns:
            raise ParseInsnException(f"Failed to disassemble bytecode at address {hex(address)}")
        return InstructionWrapper(insns[0])


class SquirrelDisassemblerCapstone(DisassemblerBase):
    """Capstone-based disassembler compatible with old squirrel interface."""

    def __init__(self, arch_str: str) -> None:
        self.arch_mapping: dict[str, tuple[int, int]] = {
            'X86': (CS_ARCH_X86, CS_MODE_32),
            'AMD64': (CS_ARCH_X86, CS_MODE_64),
            'ARM64': (CS_ARCH_ARM64, CS_MODE_ARM),
            'ARM32': (CS_ARCH_ARM, CS_MODE_ARM),
        }
        super().__init__(arch_str)

    def _setup_capstone(self) -> None:
        """Initialize Capstone for the specified architecture."""
        if self.arch_str not in self.arch_mapping:
            raise ValueError(f"Unsupported architecture: {self.arch_str}")

        arch, mode = self.arch_mapping[self.arch_str]
        self.md = Cs(arch, mode)
        self.md.detail = True


class SquirrelDisassemblerZydis(SquirrelDisassemblerCapstone):
    """
    Zydis disassembler stub - falls back to Capstone.
    Original squirrel used Zydis for x86/x64, but Capstone works fine.
    """

    pass
