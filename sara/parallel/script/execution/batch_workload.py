"""Fixed original-14 input/output contracts, independent of either predictor.

The pure original14 input/output literals have no dependencies on historical
method-admission wrappers, retained experiment results or per-origin replay.
"""
from copy import deepcopy
from pathlib import Path
import re

from script.execution.workload_contracts import BASE, MINIMAL, INPUTS

DEFAULT_CASE = 'spmm-empty-and-tail'


def contract(case=DEFAULT_CASE):
    if case not in MINIMAL:
        raise ValueError('one fixed original14 case required; LM is outside this phase')
    row = deepcopy(BASE[case])
    if (row['app'], row['arguments']) != MINIMAL[case]:
        raise ValueError('input registry and whole-output contract disagree')
    row['case'] = case
    row['env_files'] = deepcopy(INPUTS.get(case, {}))
    return row


def fixture_assets(case):
    return {Path(relative).name: relative for relative in contract(case)['env_files'].values()}


def environment(case):
    return {'SARA_VALIDATE_CPU': '0', **{key: './'+Path(relative).name
            for key, relative in contract(case)['env_files'].items()}}


def output_regions(log, case):
    from script.execution.method_input_context import read_text
    found = [dict(base=int(base, 16), bytes=int(count), name=name, space='global')
        for base, count, name in re.findall(
            r'GPUFI_OUTPUT base=(0x[0-9a-fA-F]+) bytes=(\d+) name=(\S+)', read_text(log))]
    expected = {row['name']: row['bytes'] for row in contract(case)['outputs']}
    if len(found) != len(expected) or {row['name']:row['bytes'] for row in found} != expected:
        raise ValueError('complete named output allocations differ from the fixed workload')
    if any(a['base'] < b['base']+b['bytes'] and b['base'] < a['base']+a['bytes']
           for index, a in enumerate(found) for b in found[index+1:]):
        raise ValueError('terminal output allocations unexpectedly overlap')
    return found
