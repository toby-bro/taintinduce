"""JN (Just Nibbles) ISA Register definitions.

A simplified 4-bit ISA with two registers for testing taint inference algorithms.
"""

from taintinduce.isa.register import CondRegister, Register


class JN_REG_R1(Register):
    """R1: First 4-bit register."""

    def __init__(self):
        self.name = 'R1'
        self.uc_const = 0x1000  # Dummy constant for JN
        self.bits = 4
        self.structure = [4]
        self.value = None
        self.address = None


class JN_REG_R2(Register):
    """R2: Second 4-bit register."""

    def __init__(self):
        self.name = 'R2'
        self.uc_const = 0x1001  # Dummy constant for JN
        self.bits = 4
        self.structure = [4]
        self.value = None
        self.address = None


class JN_REG_NZCV(CondRegister):
    """NZCV: Condition flags register (Negative, Zero, Carry, oVerflow).

    4-bit register containing condition flags:
    - bit 0: V (oVerflow)
    - bit 1: C (Carry)
    - bit 2: Z (Zero)
    - bit 3: N (Negative)
    """

    def __init__(self):
        self.name = 'NZCV'
        self.uc_const = 0x1002  # Dummy constant for JN
        self.bits = 4
        self.structure = [4]
        self.value = None
        self.address = None


# Standard state format: [R1, R2, NZCV]
# Bit layout in state (12 bits = 3 nibbles):
#   bits 0-3:   R1 (4 bits)
#   bits 4-7:   R2 (4 bits)
#   bits 8-11:  NZCV (4 bits)
def get_jn_state_format():
    """Get the standard JN state format."""
    return [JN_REG_R1(), JN_REG_R2(), JN_REG_NZCV()]
