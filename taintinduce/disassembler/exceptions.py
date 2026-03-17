class ParseInsnException(Exception):
    def __str__(self) -> str:
        return '[ERROR] capstone disassemble cannot translate this instruction!'


class UnsupportedArchException(Exception):
    def __str__(self) -> str:
        return '[ERROR] TaintInduce doesnt support this arch now!'


class InsnInfoException(Exception):
    def __str__(self) -> str:
        return '[ERROR] insninfo cannot parse capstone information!'


class UnsupportedSizeException(Exception):
    def __str__(self) -> str:
        return '[ERROR] size unsupport error!'
