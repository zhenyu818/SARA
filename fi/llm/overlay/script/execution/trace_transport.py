"""Lossless closed trace transport; no sampler, event filtering or authority.

The simulator's decoded byte hash continues to bind the host ledger. A gzip
capture additionally binds its physical bytes and requires a complete single
member/CRC. This reader never repairs a partial stream or accepts a prefix.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import zlib

SCHEMA='sara-exact-trace-storage-v1'
PHYSICAL_BYTES=512*1024**2
DECODED_BYTES=1024**3
BLOCK=1024**2


def _require(value,reason):
    if not value:raise ValueError(reason)


def _json(payload):
    def object_pairs(pairs):
        row={}
        for key,value in pairs:
            _require(key not in row,'duplicate_trace_storage_JSON_key');row[key]=value
        return row
    return json.loads(payload,object_pairs_hook=object_pairs,
        parse_constant=lambda value:(_ for _ in ()).throw(ValueError('nonfinite_trace_storage_JSON')))


def read_trace_payload(path,*,max_physical_bytes=PHYSICAL_BYTES,max_decoded_bytes=DECODED_BYTES):
    from script.execution.method_input_context import current_context
    context = current_context(path)
    if context is None:
        return _read_trace_payload(path, max_physical_bytes=max_physical_bytes,
                                   max_decoded_bytes=max_decoded_bytes)
    for value in (max_physical_bytes, max_decoded_bytes):
        _require(type(value) is int and value > 0, 'positive_trace_transport_budget_required')
    context.check_size(path, max_physical_bytes)
    # The sidecar is a separate immutable dependency even when this payload is
    # cached. Re-stat it on every call, rather than accepting a stale receipt.
    sidecar = Path(str(path) + '.completeness.json')
    if sidecar.exists():
        context.check_size(sidecar, 16 * 1024**2)
    dependency = context.key(sidecar) if sidecar.exists() else None
    expected_dependency = context.cached(path, 'trace-sidecar-dependency-v1', lambda: dependency)
    _require(dependency == expected_dependency, 'trace_sidecar_presence_or_identity_changed')
    def load():
        context.count(path, 'trace_transport_decodes')
        result = _read_trace_payload(path, max_physical_bytes=max_physical_bytes,
                                     max_decoded_bytes=max_decoded_bytes, context=context)
        context.count(path, 'trace_decoded_bytes', len(result[0]))
        return result
    payload, transport = context.cached(path, 'trace-payload-v1', load)
    _require(transport['physical_bytes'] <= max_physical_bytes
        and transport['decoded_bytes'] <= max_decoded_bytes, 'trace_transport_reuse_budget_exceeded')
    return payload, transport


def _read_trace_payload(path,*,max_physical_bytes=PHYSICAL_BYTES,max_decoded_bytes=DECODED_BYTES,context=None):
    """Return exact decoded bytes + complete physical/decoded identity.

    Plain legacy captures retain their original bytes/identity. An explicit
    gzip storage declaration is mandatory in the actual completeness sidecar;
    renaming a compressed file never upgrades an old capture certificate.
    Decoded byte budgets bound transport output, not parsed Python list memory.
    """
    for value in (max_physical_bytes,max_decoded_bytes):
        _require(type(value) is int and value>0,'positive_trace_transport_budget_required')
    path=Path(path)
    _require(path.absolute()==path.resolve(strict=True),'trace_transport_symlink_ancestor')
    before=path.lstat()
    _require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=max_physical_bytes,'trace_transport_physical_budget_or_type')
    identity=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
    physical=hashlib.sha256() if context is None else None
    decoded=hashlib.sha256();parts=[];total=0;count=0;codec=None;inflater=None
    if context is None:
        fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        source=os.fdopen(fd,'rb')
    else:
        source=io.BytesIO(context.read_bytes(path))
    with source as stream:
        if context is None:
            _require(identity(os.fstat(stream.fileno()))==identity(before),'trace_transport_changed_at_open')
        while True:
            block=stream.read(BLOCK)
            if not block:break
            count+=len(block)
            if physical is not None:physical.update(block)
            _require(count<=max_physical_bytes,'trace_transport_physical_budget_exceeded')
            if codec is None:
                codec='gzip' if block[:2]==b'\x1f\x8b' else 'plain'
                if codec=='gzip':inflater=zlib.decompressobj(16+zlib.MAX_WBITS)
            if codec=='gzip':
                _require(not inflater.eof,'trace_transport_trailing_or_multiple_members')
                try:chunk=inflater.decompress(block,max_decoded_bytes-total+1)
                except zlib.error as error:raise ValueError('trace_transport_gzip_CRC_or_format_failure') from error
                _require(not inflater.unconsumed_tail,'trace_transport_decoded_budget_exceeded')
                _require(not inflater.unused_data,'trace_transport_trailing_or_multiple_members')
            else:chunk=block
            total+=len(chunk);_require(total<=max_decoded_bytes,'trace_transport_decoded_budget_exceeded')
            decoded.update(chunk);parts.append(chunk)
        if codec=='gzip':_require(inflater.eof and not inflater.unused_data,'trace_transport_truncated_gzip')
        _require((context is not None or identity(os.fstat(stream.fileno()))==identity(before))
            and identity(path.lstat())==identity(before),'trace_transport_changed_during_read')
    descriptor=dict(schema=SCHEMA,codec=codec,physical_bytes=count,
        physical_sha256=physical.hexdigest() if physical is not None else context.digest(path),
        decoded_bytes=total,decoded_sha256=decoded.hexdigest(),close_succeeded=True)
    sidecar=Path(str(path)+'.completeness.json')
    declaration=None
    if sidecar.exists():
        _require(sidecar.absolute()==sidecar.resolve(strict=True) and sidecar.is_file()
            and not sidecar.is_symlink() and sidecar.stat().st_size<=16*1024**2,'trace_completeness_sidecar_type_or_budget')
        before_sidecar=sidecar.stat()
        encoded=sidecar.read_bytes() if context is None else context.read_bytes(sidecar)
        _require(identity(sidecar.stat())==identity(before_sidecar),'trace_sidecar_changed_during_read')
        actual=_json(encoded) if context is None else context.read_json(sidecar)
        declaration=actual.get('storage')
    else:actual={}
    if codec=='gzip' or declaration is not None:
        _require(actual.get('trace_close_succeeded') is True and declaration==descriptor
            and actual.get('trace_bytes')==total and actual.get('trace_sha256')==decoded.hexdigest(),
            'gzip_trace_actual_close_or_physical_decoded_binding_mismatch')
    transport=dict(descriptor,producer_close_verified=declaration is not None,gzip_CRC_checked=codec=='gzip')
    if declaration is None:transport['close_succeeded']=None
    return b''.join(parts),transport


def read_trace_document(path,**budgets):
    payload,transport=read_trace_payload(path,**budgets)
    from script.execution.method_input_context import current_context
    context = current_context(path)
    if context is None:
        return _json(payload),transport
    def load():
        context.count(path, 'json_decodes')
        context.count(path, 'trace_json_decodes')
        value = _json(payload)
        # Only an already imported closed private scope can opt into publication
        # reuse. Public/default paths retain the original cached freeze.
        import sys
        helper = sys.modules.get('script.verified_inputs.purefreeze_reuse')
        return value if helper is None else helper.reuse_trace_document(path, payload, value)
    return context.cached(path, 'trace-document-v1', load),transport
