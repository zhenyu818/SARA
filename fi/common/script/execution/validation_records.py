"""Post-performance point records in bounded durable chunks, never one fsync/draw."""
import hashlib
import json
from pathlib import Path

from script.execution.campaign import atomic_json, fingerprint

SCHEMA = 'sara-validation-point-chunks-v1'
CHUNK_SIZE = 64


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def write_chunks(output, records, *, method, identity):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    chunks, pending, ids, count = [], [], set(), 0

    def flush():
        if not pending:
            return
        name = 'points-%06d.json' % len(chunks)
        atomic_json(output / name, dict(schema=SCHEMA, method=method,
            identity_fingerprint=fingerprint(identity), records=list(pending)))
        chunks.append(dict(path=name, sha256=digest(output / name), records=len(pending)))
        pending.clear()

    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get('trial_id'), str):
            raise ValueError('typed per-draw validation record required')
        if record['trial_id'] in ids:
            raise ValueError('duplicate draw ID; repeated site IDs remain valid')
        ids.add(record['trial_id'])
        pending.append(record)
        count += 1
        if len(pending) == CHUNK_SIZE:
            flush()
    flush()
    if not count:
        raise ValueError('empty point validation export refused')
    summary = dict(schema=SCHEMA, method=method, identity=identity,
        identity_fingerprint=fingerprint(identity), records=count, chunk_size=CHUNK_SIZE,
        chunks=chunks, validation_only=True, performance_measurement=False,
        performance_costs_or_resources=None, per_record_fsync=False,
        legal_repeated_sites_preserved=True, per_origin_replay=False)
    atomic_json(output / 'index.json', summary)
    return summary


def read_chunks(index):
    index = Path(index)
    summary = json.loads(index.read_text())
    if (summary.get('schema') != SCHEMA or summary.get('chunk_size') != CHUNK_SIZE
            or summary.get('identity_fingerprint') != fingerprint(summary.get('identity'))
            or summary.get('performance_measurement') is not False):
        raise ValueError('complete post-performance validation index required')
    ids, count = set(), 0
    for number, item in enumerate(summary['chunks']):
        if item['path'] != 'points-%06d.json' % number:
            raise ValueError('ordered local point chunk names required')
        path = index.parent / item['path']
        if path.is_symlink() or digest(path) != item['sha256']:
            raise ValueError('validation chunk bytes changed')
        chunk = json.loads(path.read_text())
        if (chunk.get('schema') != SCHEMA or chunk.get('method') != summary['method']
                or chunk.get('identity_fingerprint') != summary['identity_fingerprint']
                or len(chunk.get('records', [])) != item['records']
                or not 0 < item['records'] <= CHUNK_SIZE):
            raise ValueError('validation chunk identity/count changed')
        for record in chunk['records']:
            if record['trial_id'] in ids:
                raise ValueError('duplicate validation draw ID')
            ids.add(record['trial_id']); count += 1
            yield record
    if count != summary['records']:
        raise ValueError('validation chunks lost draws')
