"""One performance boundary for independently acquired aggregate method tasks.

The window ends after the aggregate file and its directory have been fsynced.
Performance receipts and validation-only capsules are written afterwards. The
same boundary is usable by FI, GEREM and SARA; this module never changes a
prediction, creates a fault origin, or recursively scans the output tree.
"""
from contextlib import contextmanager
from pathlib import Path
import resource
import time

from script.execution.campaign import atomic_json


SCHEMA = 'sara-method-performance-window-v1'


def _read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def _key_values(text):
    if text is None:
        return None
    try:
        return {key: int(value) for key, value in
                (line.split() for line in text.splitlines())}
    except (ValueError, TypeError):
        return None


def _io_values(text):
    if text is None:
        return None
    result = {}
    try:
        for line in text.splitlines():
            device, *fields = line.split()
            result[device] = {key: int(value) for key, value in
                              (field.split('=', 1) for field in fields)}
    except (ValueError, TypeError):
        return None
    return result


def snapshot():
    own, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    peak = _read('/sys/fs/cgroup/memory.peak')
    current = _read('/sys/fs/cgroup/memory.current')
    return dict(monotonic_seconds=time.perf_counter(),
        cpu_user_seconds=own.ru_utime + children.ru_utime,
        cpu_system_seconds=own.ru_stime + children.ru_stime,
        self_max_rss_bytes=int(own.ru_maxrss) * 1024,
        waited_children_max_rss_bytes=int(children.ru_maxrss) * 1024,
        cgroup_cpu=_key_values(_read('/sys/fs/cgroup/cpu.stat')),
        cgroup_io=_io_values(_read('/sys/fs/cgroup/io.stat')),
        process_io=_key_values(_read('/proc/self/io')),
        cgroup_memory_peak_bytes=int(peak) if peak is not None and peak.isdecimal() else None,
        cgroup_memory_current_bytes=int(current) if current is not None and current.isdecimal() else None)


def _difference(before, after):
    if before is None or after is None:
        return None
    return {key: after.get(key, 0) - before.get(key, 0)
            for key in sorted(set(before) | set(after))}


def elapsed(before, after):
    io = None
    if before['cgroup_io'] is not None and after['cgroup_io'] is not None:
        io = {device: _difference(before['cgroup_io'].get(device, {}),
                                  after['cgroup_io'].get(device, {}))
              for device in sorted(set(before['cgroup_io']) | set(after['cgroup_io']))}
    return dict(wall_seconds=after['monotonic_seconds'] - before['monotonic_seconds'],
        cpu_user_seconds=after['cpu_user_seconds'] - before['cpu_user_seconds'],
        cpu_system_seconds=after['cpu_system_seconds'] - before['cpu_system_seconds'],
        cgroup_cpu_delta=_difference(before['cgroup_cpu'], after['cgroup_cpu']),
        cgroup_io_delta=io,
        process_io_delta=_difference(before['process_io'], after['process_io']),
        memory_peak_bytes=after['cgroup_memory_peak_bytes'],
        memory_current_bytes=after['cgroup_memory_current_bytes'],
        self_max_rss_bytes=after['self_max_rss_bytes'],
        waited_children_max_rss_bytes=after['waited_children_max_rss_bytes'],
        memory_scope='cgroup/process high-water counters since worker start; not a phase-reset peak',
        io_scope='kernel accounting, including filesystem/cache behavior; no recursive directory sampling')


def _subtract_tree(total, deductions):
    if total is None:
        return None
    if isinstance(total, dict):
        return {key: _subtract_tree(value, [item.get(key, {} if isinstance(value, dict) else 0) if item is not None else None
                                           for item in deductions])
                for key, value in total.items()}
    if any(item is None for item in deductions):
        return None
    return total - sum(deductions)


def active_elapsed(total, gaps):
    """Subtract only explicitly bracketed, quiescent validation checkpoints."""
    result = dict(total)
    for key in ('wall_seconds', 'cpu_user_seconds', 'cpu_system_seconds',
                'cgroup_cpu_delta', 'cgroup_io_delta', 'process_io_delta'):
        result[key] = _subtract_tree(total[key], [gap[key] for gap in gaps])
    result['memory_scope'] = (total['memory_scope'] +
        '; inclusive of validation checkpoints: a high-water counter cannot be subtracted')
    return result


class PerformanceWindow:
    """Own acquisition -> preparation -> analysis -> one durable aggregate.

    Phases are sequential so their costs cannot be accidentally double-counted.
    Callers must finish this window before exporting optional point records,
    classified-region capsules, provenance inventories or validation receipts.
    """
    def __init__(self, method, output, *, component=None, task=None):
        if method not in ('FI', 'GEREM', 'SARA-rates'):
            raise ValueError('one declared aggregate method required')
        self.method, self.output = method, Path(output)
        self.component, self.task = component, task
        self.started = snapshot()
        self.phases, self.active, self.finished = {}, None, False
        self.validation_checkpoints, self.in_checkpoint = [], False

    @contextmanager
    def phase(self, name):
        if self.finished or self.active is not None or self.in_checkpoint or name in self.phases:
            raise ValueError('performance phases must be unique, sequential and unfinished')
        self.active = name
        before = snapshot()
        first_gap = len(self.validation_checkpoints)
        successful = False
        try:
            yield
            successful = True
        finally:
            total = elapsed(before, snapshot())
            gaps = self.validation_checkpoints[first_gap:]
            self.phases[name] = dict(active_elapsed(total, gaps), successful=successful,
                elapsed_including_validation=total, excluded_validation_checkpoints=len(gaps))
            self.active = None

    @contextmanager
    def validation_checkpoint(self, *, workers_idle, purpose='durable validation resume evidence'):
        """Bracket evidence I/O after all method workers have joined.

        Acquisition, analysis, required model preparation and aggregate I/O may
        never use this context. The caller asserts quiescence; no background
        method worker may overlap the excluded interval.
        """
        if self.finished or self.in_checkpoint or workers_idle is not True:
            raise ValueError('validation checkpoint requires unfinished window and joined workers')
        if not isinstance(purpose, str) or not purpose:
            raise ValueError('validation checkpoint purpose is required')
        self.in_checkpoint = True
        before = snapshot()
        successful = False
        try:
            yield
            successful = True
        finally:
            self.validation_checkpoints.append(dict(elapsed(before, snapshot()),
                purpose=purpose, phase=self.active, workers_idle=True, successful=successful))
            self.in_checkpoint = False

    def complete(self, aggregate, *, aggregate_name='aggregate.json'):
        if self.finished or self.active is not None or self.in_checkpoint:
            raise ValueError('aggregate performance window is already finished or active')
        name = Path(aggregate_name)
        if name.name != str(name) or name.name in ('', '.', '..'):
            raise ValueError('aggregate result filename must be local to its fresh output')
        target = self.output / name
        if target.exists():
            raise FileExistsError('never replace an aggregate performance result')
        with self.phase('aggregate_persistence'):
            atomic_json(target, aggregate)
        self.finished = True
        after = snapshot()
        total = elapsed(self.started, after)
        receipt = dict(schema=SCHEMA, method=self.method, component=self.component,
            task=self.task, performance_measurement=True, complete=True, partial=False,
            **active_elapsed(total, self.validation_checkpoints), phases=self.phases,
            elapsed_including_validation=total,
            excluded_validation_checkpoints=self.validation_checkpoints,
            interrupted_for_validation=bool(self.validation_checkpoints),
            aggregate_file=name.name, aggregate_fsynced=True,
            boundary=('own acquisition through durable aggregate; explicitly bracketed joined-worker '
                'validation checkpoints, receipt and post-window validation export excluded'),
            validation_export_included=False, paired_query_included=False,
            external_queue_build_Docker_startup_included=False,
            recursive_storage_sampler_enabled=False)
        atomic_json(self.output / 'performance-window.json', receipt)
        return receipt

    finish = complete

    def save_partial(self, reason, *, receipt_name='performance-partial.json'):
        """Preserve active costs of a failed/interrupted dispatch, never completion."""
        if self.finished or self.active is not None or self.in_checkpoint:
            raise ValueError('partial receipt requires an unfinished, quiescent window')
        name = Path(receipt_name)
        if name.name != str(name) or name.name in ('', '.', '..'):
            raise ValueError('partial receipt filename must be local')
        target = self.output / name
        if target.exists():
            raise FileExistsError('never replace a partial performance receipt')
        total = elapsed(self.started, snapshot())
        self.finished = True
        receipt = dict(schema=SCHEMA, method=self.method, component=self.component,
            task=self.task, performance_measurement=True, complete=False, partial=True,
            reason=str(reason), **active_elapsed(total, self.validation_checkpoints),
            elapsed_including_validation=total, phases=self.phases,
            excluded_validation_checkpoints=self.validation_checkpoints,
            interrupted_for_validation=bool(self.validation_checkpoints),
            aggregate_file=None, aggregate_fsynced=False,
            boundary='partial active method work; failed/interrupted dispatch, no completed aggregate',
            validation_export_included=False, paired_query_included=False,
            external_queue_build_Docker_startup_included=False,
            recursive_storage_sampler_enabled=False)
        atomic_json(target, receipt)
        return receipt
