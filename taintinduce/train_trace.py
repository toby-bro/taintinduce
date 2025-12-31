"""Train taint rules from a Peekaboo trace.

This module processes Peekaboo execution traces and generates taint rules
for unique instructions found in the trace.
"""

import argparse
import json
from pathlib import Path

from .pypeekaboo import PyPeekaboo
from .serialization import TaintInduceEncoder
from .taintinduce import taintinduce_infer


class RuleDatabase:
    """Simple JSON-based rule storage system (replaces SquirrelFlowDB)."""

    def __init__(self, rules_dir: str) -> None:
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    def get_rule_path(self, arch: str, bytestring: str) -> Path:
        """Get the path for a rule file."""
        return self.rules_dir / f'{bytestring}_{arch}_rule.json'

    def has_rule(self, arch: str, bytestring: str) -> bool:
        """Check if a rule already exists."""
        return self.get_rule_path(arch, bytestring).exists()

    def save_rule(self, arch: str, bytestring: str, rule_data: dict) -> None:
        """Save a taint rule to disk."""
        rule_path = self.get_rule_path(arch, bytestring)
        with open(rule_path, 'w') as f:
            json.dump(rule_data, f, cls=TaintInduceEncoder, indent=2)
        print(f'Saved rule: {rule_path}')

    def check_and_generate_rules(self, arch: str, insn_set: set[str]) -> None:
        """Check which instructions need rules and generate them."""
        missing_rules: list[str] = []
        for bytestring in insn_set:
            if not self.has_rule(arch, bytestring):
                missing_rules.append(bytestring)
            else:
                print(f'Rule exists: {bytestring}')

        if missing_rules:
            print(f'\nGenerating {len(missing_rules)} missing rules...')
            for i, bytestring in enumerate(missing_rules, 1):
                try:
                    print(f'\n[{i}/{len(missing_rules)}] Processing {bytestring}...')
                    insninfo, obs_list, taintrule = taintinduce_infer(arch, bytestring)

                    # Save the rule
                    rule_data = {
                        'bytestring': bytestring,
                        'arch': arch,
                        'insninfo': insninfo,
                        'observations': obs_list,
                        'taintrule': taintrule,
                    }
                    self.save_rule(arch, bytestring, rule_data)
                except Exception as e:
                    print(f'ERROR: Failed to generate rule for {bytestring}: {e}')
        else:
            print('\nAll rules already exist!')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Generate taint rules from a Peekaboo execution trace.',
    )
    parser.add_argument('trace_path', type=str, help='Path to a peekaboo trace directory.')
    parser.add_argument('--output-dir', type=str, default='rules', help='Rules output directory.')

    args = parser.parse_args()

    # Load the trace
    print(f'Loading trace from: {args.trace_path}')
    peekaboo = PyPeekaboo(args.trace_path)

    # Extract unique instructions from the trace
    insn_set = set()
    for addr in peekaboo.bytesmap:
        bytestring = ''.join(['{:02x}'.format(x) for x in peekaboo.bytesmap[addr]])
        insn_set.add(bytestring)

    print(f'\nFound {len(insn_set)} unique instructions in trace')
    print(f'Architecture: {peekaboo.arch_str}')

    # Check and generate rules
    rule_db = RuleDatabase(args.output_dir)
    rule_db.check_and_generate_rules(peekaboo.arch_str, insn_set)

    print(f'\nDone! Rules stored in: {args.output_dir}')


if __name__ == '__main__':
    main()
