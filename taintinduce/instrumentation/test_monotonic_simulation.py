import random


# Let's say C is a known monotonic function, e.g. bitwise AND
def C_and(A, B):
    return A & B

def C_or(A, B):
    return A | B

def m_replica(A, B, T_A, T_B, C_func, width=8):
    """
    Computes precise taint using full m-replica methodology.
    For every bit in output, it is tainted if there exists an input combining
    the original input and toggling ANY tainted bits that changes the output bit.
    """
    # Generating all 2^(number of tainted bits) inputs is slow for 64 bits.
    # We will do it bit-by-bit since it's a bitwise function anyway.
    out_taint = 0
    for bit in range(width):
        # bit is tainted if toggling A[bit] (if T_A[bit]=1) or B[bit] (if T_B[bit]=1)
        # changes the output of C_func for this bit.

        orig_A_bit = (A >> bit) & 1
        orig_B_bit = (B >> bit) & 1
        ta_bit = (T_A >> bit) & 1
        tb_bit = (T_B >> bit) & 1

        # Possible values for A_bit and B_bit
        A_vals = [orig_A_bit ^ 1, orig_A_bit] if ta_bit else [orig_A_bit]
        B_vals = [orig_B_bit ^ 1, orig_B_bit] if tb_bit else [orig_B_bit]

        orig_out = C_func(orig_A_bit, orig_B_bit)

        is_tainted = False
        for av in A_vals:
            for bv in B_vals:
                if C_func(av, bv) != orig_out:
                    is_tainted = True
                    break
            if is_tainted:
                break

        if is_tainted:
            out_taint |= (1 << bit)

    return out_taint


def test_monotonic_property_and():
    # Test formula: C(I & ~T_I) ^ C(I | T_I)
    for _ in range(100):
        A = random.randint(0, 255)
        B = random.randint(0, 255)
        T_A = random.randint(0, 255)
        T_B = random.randint(0, 255)

        # M-replica truth
        expected = m_replica(A, B, T_A, T_B, C_and)

        # Polarization formula
        # I & ~T_I
        A0 = A & ~T_A
        B0 = B & ~T_B

        # I | T_I
        A1 = A | T_A
        B1 = B | T_B

        actual = C_and(A0, B0) ^ C_and(A1, B1)

        assert expected == actual

def test_monotonic_property_or():
    for _ in range(100):
        A = random.randint(0, 255)
        B = random.randint(0, 255)
        T_A = random.randint(0, 255)
        T_B = random.randint(0, 255)

        expected = m_replica(A, B, T_A, T_B, C_or)

        A0 = A & ~T_A
        B0 = B & ~T_B
        A1 = A | T_A
        B1 = B | T_B

        actual = C_or(A0, B0) ^ C_or(A1, B1)
        assert expected == actual

