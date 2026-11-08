"""Lossless classified intervals for post-performance paired queries only.

Only the rates pass creates these intervals. Reading a capsule never imports a
simulator, runs propagation, creates a full-population query index, or changes
the batch priority/support policy. Hex masks avoid decimal integer size limits.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile

from script.execution.campaign import atomic_json, canonical_bytes, fingerprint

SCHEMA = 'sara-classified-region-capsule-v1'
MAX_LINE = 16 * 1024 * 1024


def _digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def write_capsule(output, regions, *, identity, aggregate):
    """Call only after PerformanceWindow.finish; no timing/resource fields."""
    from script.core.batch_backward import CLASSES
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'classified-regions.jsonl.gz'
    fd, temporary = tempfile.mkstemp(prefix='.regions-', dir=str(output))
    count = 0
    try:
        with os.fdopen(fd, 'wb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as stream:
                stream.write(canonical_bytes(dict(schema=SCHEMA, kind='header', identity=identity,
                    identity_fingerprint=fingerprint(identity), aggregate=aggregate)) + b'\n')
                for region in regions:
                    row = dict(kind='region', component=region.component, target=region.target,
                        start=region.start, stop=region.stop, bit_start=region.bit_start,
                        width=region.width, classes={name: hex(region.classes[name]) for name in CLASSES},
                        unknown_reason=region.unknown_reason)
                    encoded = canonical_bytes(row) + b'\n'
                    if len(encoded) > MAX_LINE:
                        raise ValueError('classified interval exceeds explicit transport record bound')
                    stream.write(encoded); count += 1
                stream.write(canonical_bytes(dict(kind='close', regions=count)) + b'\n')
            raw.flush(); os.fsync(raw.fileno())
        os.replace(temporary, target)
        directory = os.open(str(output), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    receipt = dict(schema=SCHEMA, path=target.name, sha256=_digest(target), regions=count,
        identity=identity, identity_fingerprint=fingerprint(identity), aggregate=aggregate,
        validation_only=True, performance_measurement=False, performance_costs_or_resources=None,
        same_rates_core_result=True, new_collection=False, new_propagation=False,
        per_origin_replay=False)
    atomic_json(output / 'capsule.json', receipt)
    return receipt


def read_capsule(receipt_path, *, expected_identity=None):
    """Return receipt and a checked stream; consuming the stream validates close."""
    from script.core.batch_backward import CLASSES, Region
    receipt_path = Path(receipt_path)
    receipt = json.loads(receipt_path.read_text())
    if (receipt.get('schema') != SCHEMA or receipt.get('path') != 'classified-regions.jsonl.gz'
            or receipt.get('performance_measurement') is not False
            or receipt.get('identity_fingerprint') != fingerprint(receipt.get('identity'))
            or (expected_identity is not None and receipt['identity'] != expected_identity)):
        raise ValueError('bound post-performance classified capsule required')
    path = receipt_path.parent / receipt['path']
    if path.is_symlink() or _digest(path) != receipt['sha256']:
        raise ValueError('classified capsule bytes changed')

    def regions():
        count = 0
        with gzip.open(path, 'rb') as stream:
            line = stream.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE:
                raise ValueError('capsule header bound exceeded')
            header = json.loads(line)
            if header != dict(schema=SCHEMA, kind='header', identity=receipt['identity'],
                    identity_fingerprint=receipt['identity_fingerprint'], aggregate=receipt['aggregate']):
                raise ValueError('capsule header identity changed')
            while True:
                line = stream.readline(MAX_LINE + 1)
                if not line or len(line) > MAX_LINE or not line.endswith(b'\n'):
                    raise ValueError('classified capsule truncated or record bound exceeded')
                row = json.loads(line)
                if row.get('kind') == 'close':
                    if row != dict(kind='close', regions=count) or count != receipt['regions'] or stream.read(1):
                        raise ValueError('classified capsule close/count/trailing bytes changed')
                    break
                if row.pop('kind', None) != 'region' or set(row['classes']) != set(CLASSES):
                    raise ValueError('typed classified interval required')
                row['classes'] = {name: int(row['classes'][name], 16) for name in CLASSES}
                yield Region(**row)
                count += 1
    return receipt, regions()
