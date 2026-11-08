"""Actual host-memory boundaries bound to SARA's already validated input image."""
from pathlib import Path
import time
from script.execution.memory_effect_records import Validator,read_ledger_rows

def read_boundaries(capture,image,event_count,native_fingerprint):
    start=time.perf_counter()
    if not image or not image.get('host_ledger_sha256'):
        return None,dict(status='missing_bound_ledger_global_frontiers_retained')
    path=Path(capture)/'memory.jsonl'
    rows,facts=read_ledger_rows(path)
    if facts['ledger_sha256']!=image['host_ledger_sha256']:
        raise ValueError('host boundary ledger differs from validated initial image')
    checker=Validator()
    for row in rows:checker.consume(row)
    report=checker.report()
    if report['source_fingerprint']!=native_fingerprint:
        raise ValueError('host boundary native identity')
    close=facts['close'];checkpoint=close['checkpoint']
    if (checkpoint['prefix_bytes'],checkpoint['prefix_sha256'])!=(facts['prefix_bytes'],facts['prefix_sha256']):
        raise ValueError('host boundary prefix identity')
    result=[]
    for copy in report['copy_effects']:
        cursor=copy['instruction_cursor']
        if not 0<=cursor<=event_count or cursor!=copy['instruction_cursor_after']:
            raise ValueError('host copy outside complete actual event order')
        result.append(dict(cursor=cursor,sequence=copy['sequence'],kind=copy['copy_kind'],
            source=copy['source'],destination=copy['destination'],count=copy['count']))
    # Allocation/free metadata never kills a value dependency. Only actual
    # recorded full overwrites do so; a later unequal golden load is a frontier.
    result.sort(key=lambda r:(r['cursor'],r['sequence']))
    return result,dict(status='actual_closed_host_ledger',ledger_sha256=facts['ledger_sha256'],
        copies=len(report['copy_effects']),construction_seconds=time.perf_counter()-start,
        trace_binding='same immutable image and descriptor validated by method input preparation')
