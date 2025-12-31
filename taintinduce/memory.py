"""Memory slot representation for taint tracking."""


class MemorySlot:
    """Memory access slot for tracking memory reads/writes in taint rules."""

    READ: str = 'READ'
    WRITE: str = 'WRITE'
    ADDR: str = 'ADDR'
    VALUE: str = 'VALUE'

    def __init__(self, slot_id: int, access_type: str, size: int, mem_type: str) -> None:
        self.slot_id: int = slot_id
        self.access_type: str = access_type
        self.size: int = size
        self.mem_type: str = mem_type

    @staticmethod
    def get_mem(slot_id: int, access_type: str, size: int, mem_type: str) -> 'MemorySlot':
        return MemorySlot(slot_id, access_type, size, mem_type)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, MemorySlot):
            return False
        return (
            self.slot_id == value.slot_id
            and self.access_type == value.access_type
            and self.size == value.size
            and self.mem_type == value.mem_type
        )

    def __hash__(self) -> int:
        return hash((self.slot_id, self.access_type, self.size, self.mem_type))
