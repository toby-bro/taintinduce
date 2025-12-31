"""Train taint rules from a Peekaboo trace.

This module processes Peekaboo execution traces and generates taint rules
for unique instructions found in the trace.
"""

import argparse
import json
import signal
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from io import StringIO
from pathlib import Path
from typing import Any

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

    def save_rule(self, arch: str, bytestring: str, rule_data: dict[str, Any]) -> None:
        """Save a taint rule to disk."""
        rule_path = self.get_rule_path(arch, bytestring)
        with open(rule_path, 'w') as f:
            json.dump(rule_data, f, cls=TaintInduceEncoder, indent=2)
        print(f'Saved rule: {rule_path}')

    def check_and_generate_rules(self, arch: str, insn_set: set[str], num_threads: int = 1) -> None:
        """Check which instructions need rules and generate them."""
        missing_rules: list[str] = []
        for bytestring in insn_set:
            if not self.has_rule(arch, bytestring):
                missing_rules.append(bytestring)
            else:
                print(f'Rule exists: {bytestring}')

        if not missing_rules:
            print('\nAll rules already exist!')
            return

        print(f'\nGenerating {len(missing_rules)} missing rules using {num_threads} process(es)...')

        if num_threads == 1:
            self._generate_rules_single_process(arch, missing_rules)
        else:
            self._generate_rules_multiprocess(arch, missing_rules, num_threads)

    def _generate_rules_single_process(self, arch: str, missing_rules: list[str]) -> None:
        """Generate rules using a single process."""
        for i, bytestring in enumerate(missing_rules, 1):
            self._generate_rule(arch, bytestring, i, len(missing_rules))

    def _generate_rules_multiprocess(self, arch: str, missing_rules: list[str], num_threads: int) -> None:
        """Generate rules using multiple processes."""
        executor = ProcessPoolExecutor(
            max_workers=num_threads,
            initializer=_worker_init,
        )
        try:
            # Submit all tasks
            future_to_bytestring = {
                executor.submit(
                    _generate_rule_worker,
                    arch,
                    bytestring,
                    i,
                    len(missing_rules),
                    str(self.rules_dir),
                ): bytestring
                for i, bytestring in enumerate(missing_rules, 1)
            }

            # Process completed tasks
            for future in as_completed(future_to_bytestring):
                bytestring = future_to_bytestring[future]
                try:
                    future.result()
                except Exception as e:
                    print(f'ERROR: Process failed for {bytestring}: {e}')

            # Normal completion
            executor.shutdown(wait=True)
        except KeyboardInterrupt:
            print('\n\nInterrupted! Killing worker processes...')
            # Cancel all pending futures
            for future in future_to_bytestring.keys():
                future.cancel()
            # Shutdown immediately without waiting
            executor.shutdown(wait=False)
            # Give workers a moment to exit, then force kill

            time.sleep(0.1)
            # Terminate any remaining workers
            for _, process in executor._processes.items():
                try:
                    process.terminate()
                except Exception as e:
                    print(f'Warning: Failed to terminate worker process: {e}')
            sys.exit(1)

    def _generate_rule(self, arch: str, bytestring: str, index: int, total: int) -> None:
        """Generate a single rule (thread-safe)."""
        try:
            print(f'\n[{index}/{total}] Processing {bytestring}...')
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


def _worker_init():
    """Initialize worker process with signal handlers."""
    # Workers should ignore SIGINT and let the main process handle it
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _generate_rule_worker(arch: str, bytestring: str, index: int, total: int, rules_dir: str) -> None:
    """Worker function for multiprocessing (must be at module level)."""
    # Suppress verbose output from worker processes to avoid stdout/stderr conflicts
    # tqdm writes to stderr when stdout is redirected, so we must suppress both

    # Save original stdout and stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    try:
        # Suppress all stdout and stderr in worker processes
        sys.stdout = StringIO()
        sys.stderr = StringIO()

        insninfo, obs_list, taintrule = taintinduce_infer(arch, bytestring)

        # Restore stdout/stderr for final status message
        sys.stdout = original_stdout
        sys.stderr = original_stderr

        # Save the rule
        rule_data = {
            'bytestring': bytestring,
            'arch': arch,
            'insninfo': insninfo,
            'observations': obs_list,
            'taintrule': taintrule,
        }

        # Save directly to file
        rule_path = Path(rules_dir) / f'{bytestring}_{arch}_rule.json'
        with open(rule_path, 'w') as f:
            json.dump(rule_data, f, cls=TaintInduceEncoder, indent=2)
        print(f'[{index}/{total}] ✓ {bytestring}')
    except Exception as e:
        # Restore stdout/stderr for error message
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        print(f'[{index}/{total}] ✗ {bytestring}: {e}')
    finally:
        # Ensure stdout and stderr are restored
        sys.stdout = original_stdout
        sys.stderr = original_stderr


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Generate taint rules from a Peekaboo execution trace.',
    )
    parser.add_argument('trace_path', type=str, help='Path to a peekaboo trace directory.')
    parser.add_argument('--output-dir', type=str, default='rules', help='Rules output directory.')
    parser.add_argument(
        '--threads',
        '-j',
        type=int,
        default=1,
        help='Number of processes to use for rule generation (default: 1)',
    )

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
    rule_db.check_and_generate_rules(peekaboo.arch_str, insn_set, args.threads)

    print(f'\nDone! Rules stored in: {args.output_dir}')


if __name__ == '__main__':
    main()
