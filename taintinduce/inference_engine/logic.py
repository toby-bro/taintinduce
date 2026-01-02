import os
import pickle
import subprocess
from importlib.resources import files

from taintinduce.types import StateValue

command_template = """
.i {}
.o {}
.type {}
{}
.e

"""


class EspressoException(Exception):
    pass


class NonOrthogonalException(Exception):
    pass


class Espresso(object):
    def __init__(self) -> None:
        # Use importlib.resources instead of deprecated pkg_resources
        try:
            espresso_file = files('taintinduce.inference_engine').joinpath('espresso')
            path = str(espresso_file)
        except Exception:
            # Fallback to relative path if package resources not available
            path = os.path.join(os.path.dirname(__file__), 'espresso')

        if 'ESPRESSO_PATH' in os.environ:
            path = os.environ['ESPRESSO_PATH']
        self.path = path

    def parse_output(self, output_b: bytes) -> set[tuple[int, int]]:
        """Takes the output of Espresso and returns the conditions.

        Args:
            output (str): A string containing the output of berkeley's ESPRESSO tool

        Returns:
            bool_cond (set(int, int)): Boolean formula of the condition in DNF form represented as a
                set of tuples (mask, value). Each tuple represents a condition in CNF.

        Raises:
            Exception: Illegal character in output string.
            Exception: Length of logic != number of phases.
        """
        result = {}
        output = output_b.decode('utf-8')
        lines = output.split('\n')
        num_phase = None
        logic = []
        for line in lines:
            if line[0] == '#':
                continue
            tokens = line.split()
            if '.i' == tokens[0]:
                result['input_size'] = int(tokens[1], 10)
            elif '.o' == tokens[0]:
                result['output_size'] = int(tokens[1], 10)
            elif '.p' == tokens[0]:
                num_phase = int(tokens[1], 10)
            elif '.e' == tokens[0]:
                break
            else:
                logic.append(tokens)

        if num_phase is None or num_phase != len(logic):
            print(num_phase)
            print(logic)
            raise Exception('Length of logic != number of phases')

        # extract boolean condition from logic
        bool_cond: set[tuple[int, int]] = set()
        self.extract_conditions(num_phase, logic, bool_cond)
        return bool_cond

    def extract_conditions(self, num_phase: int, logic: list[list[str]], bool_cond: set[tuple[int, int]]) -> None:
        for x in range(num_phase):
            condition_bitstring, _ = logic[x]
            # condition is a bitstring, so index 0 is the msb
            # we always treat values as little-endian so index 0 is lsb
            # we will want to inverse it to make logic clearer
            condition_bitstring = condition_bitstring[::-1]

            condition_bitmask = 0
            condition_value = 0
            for pos, var in enumerate(condition_bitstring):
                if var == '1':
                    condition_bitmask |= 1 << pos
                    condition_value |= 1 << pos
                elif var == '0':
                    condition_bitmask |= 1 << pos
                elif var == '-':
                    continue
                else:
                    raise Exception('Illegal character found in boolean logic!')
            bool_cond.add((condition_bitmask, condition_value))

    def minimize_raw(
        self,
        in_size: int,
        out_size: int,
        pla_type: str,
        observations: dict[int, set[StateValue]],
    ) -> bytes:
        """Obtain a minimal formula using the ESPRESSO heuristic, returning raw output.

        Args:
            in_size (int): Size of the input formula in terms of bits.
            out_size (int): Size of the output formula in terms of bits.
            pla_type (str): String to determine the optimization strategy, check espresso options
                for more information
            observations ({int: set(int)}): A dictionary with key being 1/0 representing the true and
                false class. Value of the key is a set of ints being the input states for that class.
        Returns:
            result (bytes): Raw output from espresso minimization.
        Raises:
            Exception: Output found on stderr!
        """
        return self._minimize(in_size, out_size, pla_type, observations, raw=True)  # type: ignore[return-value]

    def minimize(
        self,
        in_size: int,
        out_size: int,
        pla_type: str,
        observations: dict[int, set[StateValue]],
    ) -> set[tuple[int, int]]:
        """Obtain a minimal formula using the ESPRESSO heuristic.

        Args:
            in_size (int): Size of the input formula in terms of bits.
            out_size (int): Size of the output formula in terms of bits.
            pla_type (str): String to determine the optimization strategy, check espresso options
                for more information
            observations ({int: set(int)}): A dictionary with key being 1/0 representing the true and
                false class. Value of the key is a set of ints being the input states for that class.
        Returns:
            result (set): see parse_out function output
        Raises:
            Exception: Output found on stderr!
        """
        return self._minimize(in_size, out_size, pla_type, observations, raw=False)  # type: ignore[return-value]

    def _minimize(
        self,
        in_size: int,
        out_size: int,
        pla_type: str,
        observations: dict[int, set[StateValue]],
        raw: bool = False,
    ) -> set[tuple[int, int]] | bytes:
        """Obtain a minimal formula using the ESPRESSO heuristic.

        Args:
            in_size (int): Size of the input formula in terms of bits.
            out_size (int): Size of the output formula in terms of bits.
            pla_type (str): String to determine the optimization strategy, check espresso options
                for more information
            observations ({int: set(int)}): A dictionary with key being 1/0 representing the true and
                false class. Value of the key is a set of ints being the input states for that class.
            raw (bool): Boolean value to return raw output instead of (mask, value) pairs. Defaults
                to False.

        Returns:
            result (set/None): see parse_out function output

        Raises:
            Exception: Output found on stderr!
        """
        input_size = '.i {}'.format(in_size)  # noqa: F841
        output_size = '.o {}'.format(out_size)  # noqa: F841
        in_format = '{{:0{}b}}'.format(in_size)
        out_format = '{{:0{}b}}'.format(out_size)

        # get number of outputs

        obs = ['{} {}'.format(in_format.format(y), out_format.format(x)) for x in observations for y in observations[x]]
        obs_string = '\n'.join(obs)

        command = command_template.format(in_size, out_size, pla_type, obs_string)
        espresso = subprocess.Popen(  # noqa: S603
            [self.path, '-t'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = espresso.communicate(command.encode())
        if stderr:
            raise EspressoException(stderr)

        result: set[tuple[int, int]] | bytes
        if raw:
            result = stdout
        else:
            result = self.parse_output(stdout)

        return result


def main() -> None:
    espresso = Espresso()
    obs = pickle.load(open('/tmp/test', 'rb'))  # noqa: S108, S301
    espresso.minimize(32, 1, 'fr', obs)
    return


if __name__ == '__main__':
    main()
