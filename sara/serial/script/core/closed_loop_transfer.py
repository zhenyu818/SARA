"""RF interval effects and projection used by the current generic rules."""
from collections import defaultdict
from dataclasses import dataclass
import time

@dataclass(frozen=True)
class RFLoopEffect:
    kernel: int
    thread: int
    uid: int
    start: int
    stop: int
    due: int = 0
    masked: int = 0
    value_only: int = 0
    rule: str = ''



def project(regions, effects, statistics=None):
    """Overlay proved masks on complete RF histories, independent of queries."""
    from script.core.batch_backward import Region
    index = defaultdict(list)
    for e in effects:
        if e.due or e.masked:
            index[e.kernel, e.thread, e.uid].append(e)
    for region in regions:
        begin = time.perf_counter()
        target = region.target
        candidates = index.get((target['kernel'], target['thread'], target['register_uid']), ())
        overlaps = [e for e in candidates if e.start < region.stop and region.start < e.stop]
        cuts = sorted({region.start, region.stop} | {max(region.start, e.start) for e in overlaps}
                      | {min(region.stop, e.stop) for e in overlaps})
        pieces=[]
        for start, stop in zip(cuts, cuts[1:]):
            classes = dict(region.classes)
            for e in overlaps:
                if e.start <= start and stop <= e.stop:
                    for k in classes:
                        classes[k] &= ~(e.due | e.masked)
                    classes['DUE'] |= e.due
                    classes['Masked'] |= e.masked
            pieces.append(Region(region.component, target, start, stop, region.bit_start,
                                 region.width, classes, region.unknown_reason))
        if statistics is not None:
            statistics['projection_work_seconds']=statistics.get('projection_work_seconds',0.0)+time.perf_counter()-begin
        yield from pieces



def construct(events,image):
    """Use the same structural certificates as the grouped public entry."""
    from script.core.generic_counter_loops import construct as counters
    from script.core.generic_bound_loops import construct as bounds
    from script.core.closed_control import construct as control
    results=[counters(events,image),bounds(events,image),control(events)]
    effects=[effect for values,_ in results for effect in values]
    return effects,dict(policy='generic-integer-loop-and-closed-control-v1',
        effects=len(effects),construction_seconds=sum(s['construction_seconds'] for _,s in results),
        counter=results[0][1],bound=results[1][1],closed_control=results[2][1])
