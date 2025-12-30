class ParseInsnException(Exception):
    def __str__(self):
        return '[ERROR] capstone disassemble cannot translate this instruction!'


class UnsupportedArchException(Exception):
    def __str__(self):
        return '[ERROR] TaintInduce doesnt support this arch now!'


class InsnInfoException(Exception):
    def __str__(self):
        return '[ERROR] insninfo cannot parse capstone information!'


class UnsupportedSizeException(Exception):
    def __str__(self):
        return '[ERROR] size unsupport error!'
