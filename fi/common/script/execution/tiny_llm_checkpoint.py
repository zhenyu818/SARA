"""Pinned official trained Stories260K checkpoint, explicit HTTP or cache input.

Never generates expected logits. It checks published SHA/length, actual header,
the official v0 layout, and finite FP32 checkpoint words before model admission.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import struct
import urllib.request
from urllib.parse import urlparse

URL = "https://huggingface.co/karpathy/tinyllamas/resolve/0bd21da7698eaf29a0d7de3992de8a46ef624add/stories260K/stories260K.bin"
SHA = "b0a507e7ad0f626624f17112325e66691f9076d622e1d3274d103d00299f2696"
SIZE = 1056540
HEADER = (64, 172, 5, 8, 4, 512, 512)
CPU_SHA = "9c4f2d5c6ae01b71726d1cc37530d71e60bff0ec7cc012565f16a43c1ca658bd"


def audit_bytes(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError("official complete checkpoint SHA/length mismatch")
    header = struct.unpack("<7i", data[:28])
    if header != HEADER: raise ValueError("actual checkpoint configuration differs from pinned workload")
    # Official memory_map_weights layout: shared classifier/embedding; legacy
    # stored RoPE table is skipped by both unmodified CPU and adapted CUDA.
    dim, hidden, layers, heads, kv_heads, vocab, seq = header
    kv_dim, head_size = dim * kv_heads // heads, dim // heads
    trainable = vocab * dim + 2 * layers * dim + layers * dim * dim * 2
    trainable += 2 * layers * dim * kv_dim + 3 * layers * dim * hidden + dim
    legacy_rope = seq * head_size
    words = list(struct.iter_unpack("<f", data[28:]))
    if trainable != 260032 or len(words) != trainable + legacy_rope or not all(math.isfinite(x[0]) for x in words):
        raise ValueError("actual complete weight layout/finite values differ")
    return {"bytes": len(data), "sha256": SHA, "actual_header": list(header),
            "trainable_parameters": trainable, "legacy_rope_words": legacy_rope,
            "complete_payload_words": len(words), "all_payload_words_finite": True,
            "shared_classifier_embedding": True, "trained_checkpoint": True,
            "configuration_previously_inferred_now_observed": True}


def cached_bytes(source_file):
    """Read only a bounded regular file; an exact SHA remains mandatory."""
    path = Path(source_file).absolute()
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != SIZE:
            raise ValueError("cached checkpoint must be a complete pinned-size regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(SIZE + 1)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(path.stat()):
            raise ValueError("cached checkpoint changed while being read")
    finally:
        os.close(fd)
    audit_bytes(data)
    return data, {"kind": "explicit_cached_file", "source_path": str(path),
                  "resolved_source_path": str(path.resolve(strict=True)),
                  "bytes": len(data), "sha256": SHA, "http_request_performed": False,
                  "fresh_download": False}


def fetch(out, *, source_file=None):
    out.mkdir(parents=True, exist_ok=False)
    receipt = None
    if source_file is not None:
        data, acquisition = cached_bytes(source_file)
    else:
        request = urllib.request.Request(URL, headers={"User-Agent": "SARA-pinned-tiny-llm/1.0", "Accept-Encoding": "identity"})
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200: raise ValueError("official checkpoint GET was not complete success")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) != SIZE: raise ValueError("official checkpoint response size differs")
            data = response.read(SIZE + 1)
            receipt = {"requested_url": URL, "final_host": urlparse(response.url).hostname,
                       "status": response.status, "content_length": length,
                       "etag": response.headers.get("ETag"), "bytes": len(data)}
        acquisition = {"kind": "official_http_get", "http_request_performed": True,
                       "fresh_download": True, "bytes": len(data)}
    audited = audit_bytes(data)
    (out / "stories260K.bin").write_bytes(data)
    (out / "download.json").write_text(json.dumps({"schema": "sara-pinned-tiny-llm-checkpoint-v1",
        "official_repository": "https://huggingface.co/karpathy/tinyllamas",
        "official_execution": "0bd21da7698eaf29a0d7de3992de8a46ef624add", "official_path": "stories260K/stories260K.bin",
        "license": "MIT per pinned official model card", "acquisition": acquisition,
        "download": receipt, "actual_input": audited,
        "GPU_executed": False, "automatic_gate_pass": False}, indent=2, sort_keys=True) + "\n")


def main():
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--source-file", type=Path,
                        help="explicit existing exact pinned checkpoint; never a synthetic-weight override")
    args = parser.parse_args()
    if args.check_only:
        if args.source_file is not None:
            parser.error("--source-file is an acquisition input and cannot be used with --check-only")
        print(json.dumps(audit_bytes((args.destination / "stories260K.bin").read_bytes()), sort_keys=True))
    else: fetch(args.destination, source_file=args.source_file)


if __name__ == "__main__": main()
