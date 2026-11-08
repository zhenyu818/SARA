"""Lossless, bounded transport for a closed native plain population stream.

The native plain and gzip emitters produce identical JSON bytes. This adapter
uses the unchanged plain emitter when a complete workload exceeds the native
gzip emitter's fixed 1-GiB decoded limit. It never filters or merges spans.
"""
import gzip
import hashlib
import json
from pathlib import Path

from script.execution.campaign import atomic_json


def pack_closed_population(source, destination, *, max_decoded_bytes,
                           max_physical_bytes):
    source, destination = Path(source), Path(destination)
    if (source.is_symlink() or not source.is_file() or destination.exists()
            or source.stat().st_size > max_decoded_bytes):
        raise ValueError("closed population repack source/destination/budget invalid")
    partial = Path(str(destination) + ".partial")
    digest = hashlib.sha256()
    total, tail = 0, b""
    with source.open("rb") as raw, partial.open("xb") as physical:
        with gzip.GzipFile(filename="", fileobj=physical, mode="wb",
                           compresslevel=1, mtime=0) as packed:
            while True:
                block = raw.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > max_decoded_bytes:
                    raise ValueError("complete population repack decoded budget exceeded")
                digest.update(block)
                tail = (tail + block)[-16384:]
                packed.write(block)
                if physical.tell() > max_physical_bytes:
                    raise ValueError("complete population repack physical budget exceeded")
    if not tail.endswith(b"\n"):
        raise ValueError("closed native population has no terminal newline")
    footer = json.loads(tail.rstrip(b"\n").rsplit(b"\n", 1)[-1])
    if (footer.get("kind") != "footer" or footer.get("collection_closed") is not True
            or type(footer.get("spans")) is not int or footer["spans"] < 0):
        raise ValueError("closed native population footer required before repack")
    if partial.stat().st_size > max_physical_bytes:
        raise ValueError("complete population repack physical budget exceeded")
    decoded, count = hashlib.sha256(), 0
    with gzip.open(partial, "rb") as check:
        while True:
            block = check.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            if count > max_decoded_bytes:
                raise ValueError("repacked population decode budget exceeded")
            decoded.update(block)
    if count != total or decoded.digest() != digest.digest():
        raise ValueError("repack changed native population bytes")
    partial.rename(destination)
    atomic_json(str(destination) + ".storage.json", {
        "schema": "sara-population-storage-v1", "codec": "gzip",
        "uncompressed_bytes": total, "spans": footer["spans"],
        "collection_closed": True, "close_succeeded": True})
    return {"schema": "sara-population-lossless-repack-v1",
            "native_codec": "plain", "stored_codec": "gzip",
            "decoded_bytes": total, "physical_bytes": destination.stat().st_size,
            "decoded_sha256": digest.hexdigest(), "full_gzip_CRC_and_byte_hash_checked": True,
            "logical_population_modified": False,
            "max_decoded_bytes": max_decoded_bytes,
            "max_physical_bytes": max_physical_bytes}
