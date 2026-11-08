"""Capture actual owned-child loader evidence without polluting ptxas stderr.

glibc appends .PID to LD_DEBUG_OUTPUT. The one receipt we use is selected by
exclusive wait4's actual child PID, never by scanning for a convenient library.
Other child-tool loader files are retained but cannot attest this process.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

PREFIX = "runtime-loader"
MAX_BYTES = 8 * 1024 * 1024


def prepare_loader_capture(environment, work):
    """Return (child_environment, prefix) before launching in a fresh workdir.

    Caller records this explicit override as run metadata, not a user-supplied
    path. It must pass the returned environment to exactly the owned child.
    """
    if any(environment.get(key) for key in ("LD_PRELOAD", "LD_AUDIT", "LD_DEBUG_OUTPUT")):
        raise ValueError("inherited loader preload/audit/debug-output override is forbidden")
    if environment.get("LD_DEBUG") not in (None, "", "libs"):
        raise ValueError("unreviewed inherited loader-debug category")
    directory = Path(work)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("loader capture requires an existing private nonsymlink workdir")
    directory = directory.resolve(strict=True)
    prefix = directory / PREFIX
    if prefix.exists() or prefix.is_symlink() or any(directory.glob(PREFIX + ".*")):
        raise ValueError("loader output prefix must be fresh before child launch")
    deployed = dict(environment, LD_DEBUG="libs", LD_DEBUG_OUTPUT=str(prefix))
    return deployed, prefix


def bind_loader_capture(work, metrics, expected_runtime):
    """Bind the regular loader.PID file to the actual reaped MeasuredChild.

    This API validates process ownership, not exit success or OOM state. Those
    remain the executor's independent guards (an expected SIGABRT is permitted).
    """
    if (not isinstance(metrics, dict) or type(metrics.get("pid")) is not int or metrics["pid"] < 1 or
            metrics.get("reaped") is not True or metrics.get("ownership_lost") is not False or
            metrics.get("measurement") != "wait4_for_this_pid" or
            metrics.get("scope") != "child_and_descendants_waited_for_by_child" or
            type(metrics.get("exit_status")) is not int):
        raise ValueError("owned actual PID/exclusive wait4 receipt is required for loader binding")
    directory = Path(work)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("loader capture workdir is missing or a symlink")
    directory = directory.resolve(strict=True)
    path = directory / (PREFIX + "." + str(metrics["pid"]))
    if path.is_symlink():
        raise ValueError("owned loader receipt cannot be a symlink")
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ValueError("exact owned-PID loader file is missing/unreadable") from error
    try:
        information = os.fstat(descriptor)
        if not stat.S_ISREG(information.st_mode) or not 0 < information.st_size <= MAX_BYTES:
            raise ValueError("loader receipt must be a nonempty bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_BYTES + 1)
        after = os.fstat(descriptor)
        if (len(payload) != information.st_size or len(payload) > MAX_BYTES or
                (after.st_size, after.st_mtime_ns, after.st_ino) !=
                (information.st_size, information.st_mtime_ns, information.st_ino)):
            raise ValueError("loader receipt changed while binding")
    finally:
        os.close(descriptor)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ValueError("malformed loader receipt text") from error
    pids = re.findall(r"^\s*(\d+):", text, re.MULTILINE)
    libraries = re.findall(r"^\s*(\d+):\s+calling init:\s+(\S*/libcudart\.so(?:\.[0-9.]+)?)\s*$", text, re.MULTILINE)
    if not pids or any(int(pid) != metrics["pid"] for pid in pids) or len(libraries) != 1:
        raise ValueError("loader receipt has absent/foreign PID or missing/duplicate libcudart initialization")
    if not isinstance(expected_runtime, dict):
        raise ValueError("recorded expected runtime is required")
    checksum = expected_runtime.get("libcudart_sha256")
    expected_path = expected_runtime.get("libcudart_realpath")
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum) or not isinstance(expected_path, str):
        raise ValueError("expected runtime path/SHA is incomplete")
    try:
        observed = Path(libraries[0][1]).resolve(strict=True)
        expected = Path(expected_path).resolve(strict=True)
        actual_checksum = hashlib.sha256(observed.read_bytes()).hexdigest() if observed.is_file() else None
    except OSError as error:
        raise ValueError("actual runtime library disappeared or is unreadable") from error
    if observed != expected or actual_checksum != checksum:
        raise ValueError("actual owned child loaded a different runtime path/bytes")
    return {"schema": "sara-owned-runtime-loader-v1", "pid": metrics["pid"],
            "pid_source": "exclusive_wait4_for_this_pid", "loader_prefix": str(directory / PREFIX),
            "loader_path": str(path), "loader_sha256": hashlib.sha256(payload).hexdigest(),
            "loader_bytes": len(payload), "observed_loader_path": libraries[0][1],
            "libcudart_realpath": str(observed), "libcudart_sha256": checksum,
            "capture_environment": {"LD_DEBUG": "libs", "LD_DEBUG_OUTPUT": str(directory / PREFIX)},
            "evidence_scope": "actual owned process loader init; tool descendants cannot substitute their PID",
            "scientific_outcome_or_gate_issued": False}
