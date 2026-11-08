"""Bounded plain/gzip population JSONL transport, with no membership filtering."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat

PHYSICAL_BYTES = 512 * 1024**2
DECODED_BYTES = 1024**3
ROW_BYTES = 1024**2
MAX_RECORDS = 1250010


def iter_population_rows(path, transport, *, codec="auto", max_physical_bytes=PHYSICAL_BYTES,
                         max_decoded_bytes=DECODED_BYTES, max_row_bytes=ROW_BYTES, max_records=MAX_RECORDS):
    """Consume fully or raise. CRC/footer are separate and both mandatory.

    This bounds source/decode bytes and row count, not Python dict-list memory.
    The legacy read_stream API still materializes spans; its peak must be measured.
    """
    path=Path(path)
    if codec not in ("auto","plain","gzip"):raise ValueError("unsupported population codec")
    for budget in (max_physical_bytes,max_decoded_bytes,max_row_bytes,max_records):
        if type(budget) is not int or budget<=0:raise ValueError("explicit positive population decode budgets required")
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size>max_physical_bytes:
        raise ValueError("population physical file budget/type invalid")
    descriptor=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    transport.update(stream_complete=False)
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    try:
        with os.fdopen(descriptor,"rb") as raw:
            descriptor=None
            if identity(os.fstat(raw.fileno()))!=identity(before):raise ValueError("population file changed at open")
            actual="gzip" if raw.peek(2)[:2]==b"\x1f\x8b" else "plain"
            if codec!="auto" and actual!=codec:raise ValueError("population codec/magic mismatch")
            decoded=gzip.GzipFile(fileobj=raw,mode="rb") if actual=="gzip" else raw
            digest=hashlib.sha256();total=0;records=0;spans=0
            try:
                while True:
                    row=decoded.readline(max_row_bytes+1)
                    if not row:break
                    total+=len(row);records+=1;digest.update(row)
                    if len(row)>max_row_bytes or total>max_decoded_bytes or records>max_records:
                        raise ValueError("complete population decode budget exceeded; no prefix")
                    if not row.endswith(b"\n"):raise ValueError("unterminated population record")
                    value=json.loads(row.decode("utf-8"))
                    if not isinstance(value,dict):raise ValueError("population records must be objects")
                    spans+=value.get("kind")=="span"
                    yield value
            finally:
                if actual=="gzip":decoded.close()
            physical=hashlib.sha256();physical_bytes=0;raw.seek(0)
            while True:
                block=raw.read(1024**2)
                if not block:break
                physical.update(block);physical_bytes+=len(block)
                if physical_bytes>max_physical_bytes:raise ValueError("physical population byte budget exceeded")
            if identity(os.fstat(raw.fileno()))!=identity(before) or identity(path.lstat())!=identity(before):
                raise ValueError("population file changed during full decode/hash")
            storage=None
            if actual=="gzip":
                receipt=Path(str(path)+".storage.json")
                if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size>4096:
                    raise ValueError("gzip population producer close receipt missing/invalid")
                storage=json.loads(receipt.read_text())
                if (set(storage)!={"schema","codec","uncompressed_bytes","spans","collection_closed","close_succeeded"}
                        or storage.get("schema")!="sara-population-storage-v1" or storage.get("codec")!="gzip"
                        or type(storage.get("uncompressed_bytes")) is not int or storage["uncompressed_bytes"]!=total
                        or type(storage.get("spans")) is not int or storage["spans"]!=spans
                        or storage.get("collection_closed") is not True or storage.get("close_succeeded") is not True):
                    raise ValueError("gzip producer close/count/decoded-byte receipt mismatch")
            transport.update(codec=actual,stream_complete=True,physical_bytes=physical_bytes,decoded_bytes=total,
                physical_sha256=physical.hexdigest(),decoded_sha256=digest.hexdigest(),records=records,spans=spans,
                gzip_CRC_checked=actual=="gzip",producer_storage_receipt=storage,
                budgets={"physical_bytes":max_physical_bytes,"decoded_bytes":max_decoded_bytes,
                         "row_bytes":max_row_bytes,"records":max_records},span_list_memory_bounded_by_this_decoder=False)
    finally:
        if descriptor is not None:os.close(descriptor)
