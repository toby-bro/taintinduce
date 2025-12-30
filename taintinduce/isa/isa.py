from typing import Optional

from taintinduce.serialization import SerializableMixin


class Register(SerializableMixin):
    structure: Optional[list] = []

    def __init__(self, repr_str=None):
        self.name = None
        self.uc_const = None
        self.bits = None
        self.structure = None
        self.value = None
        self.address = None

    def __hash__(self):
        return hash(self.uc_const)

    def __eq__(self, other):
        return self.uc_const == other.uc_const

    def __ne__(self, other):
        return not (self == other)


class ISA(SerializableMixin):
    name = None
    cpu_regs = None

    def __init__(self):
        pass

    def name2reg(self, name):
        pass

    def create_full_reg(self, name, bits=0, structure=[]):
        pass
