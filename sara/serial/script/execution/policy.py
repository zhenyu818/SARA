"""Server-only execution and CPU-only resource admission policy."""
from dataclasses import dataclass
from datetime import timezone
import hashlib
import json
import os
from pathlib import Path
import stat

UTC = timezone.utc

EXECUTION_CONFIG = Path("/etc/sara-execution.json")
EXECUTION_SCHEMA = "sara-execution-host-v1"
EXECUTION_ROLE_ENV = "SARA_EXECUTION_ROLE"
EXECUTION_SHA_ENV = "SARA_EXECUTION_PROFILE_SHA256"
CPU_ONLY_ENVIRONMENT = {"NVIDIA_VISIBLE_DEVICES": "void", "NVIDIA_DRIVER_CAPABILITIES": ""}


def cpu_only_docker_options():
    # Keep zero swap in the systemd scope, including across daemon-reload;
    # --memory-swap=--memory alone can leave that unit property unspecified.
    return ["--runtime", "runc", "--annotation",
            "org.systemd.property.MemorySwapMax=uint64 0"] + [
                item for name, value in CPU_ONLY_ENVIRONMENT.items()
                for item in ("-e", name + "=" + value)]


def validate_cpu_only_container(info):
    config = info.get("HostConfig", {})
    if (config.get("Runtime") != "runc" or config.get("DeviceRequests") not in (None, [])
            or config.get("Devices") not in (None, []) or config.get("Privileged") is not False):
        raise ValueError("CPU-only execution requires explicit runc and no GPU/device requests")
    environment = info.get("Config", {}).get("Env", [])
    if not isinstance(environment, list) or any(not isinstance(item, str) for item in environment):
        raise ValueError("actual container environment must be a string list")
    for name, value in CPU_ONLY_ENVIRONMENT.items():
        if [item for item in environment if item.startswith(name + "=")] != [name + "=" + value]:
            raise ValueError("CPU-only NVIDIA isolation environment differs")
    return True


@dataclass(frozen=True)
class ExecutionProfile:
    """An administrator-installed server role, never a trial-selected option."""
    role: str
    cpus: int
    memory_bytes: int
    config_sha256: str

    @property
    def memory(self):
        return str(self.memory_bytes // 1024 ** 3) + "g"

    def descriptor(self):
        return {"schema": EXECUTION_SCHEMA, "role": self.role, "cpus": self.cpus,
                "memory_bytes": self.memory_bytes, "swap_bytes": 0,
                "schedule": "always_open", "config_sha256": self.config_sha256}

    def environment(self):
        return {EXECUTION_ROLE_ENV: self.role, EXECUTION_SHA_ENV: self.config_sha256}


def validate_execution_document(document, checksum):
    """Pure shape validation; a document alone does not authorize execution."""
    expected = {"schema", "role", "cpus", "memory_bytes", "swap_bytes", "schedule"}
    if (not isinstance(document, dict) or set(document) != expected
            or document.get("schema") != EXECUTION_SCHEMA or document.get("role") not in ("bounded_secondary", "bounded_primary")
            or type(document.get("cpus")) is not int or not 1 <= document["cpus"] <= 1024
            or type(document.get("memory_bytes")) is not int
            or not 1024 ** 3 <= document["memory_bytes"] <= 4096 * 1024 ** 3
            or document["memory_bytes"] % 1024 ** 3 != 0
            or type(document.get("swap_bytes")) is not int or document["swap_bytes"] != 0
            or document.get("schedule") != "always_open"
            or not isinstance(checksum, str) or len(checksum) != 64
            or any(character not in "0123456789abcdef" for character in checksum)):
        raise RuntimeError("invalid administrator server execution profile or exact resource bounds")
    return ExecutionProfile(document["role"], document["cpus"], document["memory_bytes"], checksum)


def validate_host_capacity(profile, available_cpus, physical_memory_bytes):
    """Keep at least ten percent (and at least 1 GiB) outside the container."""
    if (type(available_cpus) is not int or available_cpus < 1
            or type(physical_memory_bytes) is not int or physical_memory_bytes < 1):
        raise RuntimeError("actual host CPU/physical-memory capacity is unavailable")
    reserve = max(1024 ** 3, (physical_memory_bytes + 9) // 10)
    if profile.cpus > available_cpus or profile.memory_bytes > physical_memory_bytes - reserve:
        raise RuntimeError("execution profile exceeds actual host CPU or reserved physical-memory capacity")
    return True


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate execution-profile key")
        value[key] = item
    return value


def require_active_execution(*, require_environment=False):
    """Deny local execution unless root installed the fixed host marker.

    Docker receives the same marker read-only and matching controller metadata.
    Environment variables alone cannot grant an execution role. No config-path
    or clock override is accepted from CLI, environment, queue, or trial inputs.
    """
    try:
        descriptor = os.open(str(EXECUTION_CONFIG), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or info.st_size > 4096):
                raise RuntimeError("execution marker must be a root-owned, non-writable regular file")
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise RuntimeError("execution marker exceeds its size bound")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        profile = validate_execution_document(document, hashlib.sha256(raw).hexdigest())
        validate_host_capacity(profile, os.cpu_count(), os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    except (OSError, ValueError, UnicodeError) as error:
        raise RuntimeError("local experiments/compilation are disabled; an administrator-installed server marker is required") from error
    environment_required = require_environment or Path("/.dockerenv").is_file()
    for name, expected in profile.environment().items():
        actual = os.environ.get(name)
        if (environment_required or actual is not None) and actual != expected:
            raise RuntimeError("execution role/profile metadata is missing or differs from the root-owned marker")
    return profile


def require_container_execution():
    profile = require_active_execution(require_environment=True)
    if not Path("/.dockerenv").is_file():
        raise RuntimeError("compilation/experiments require the authorized bounded CPU-only Docker worker")
    return profile


class ExecutionWindow:
    """Always-open server admission; finite job budgets remain independent."""
    @property
    def cpus(self):
        return require_active_execution().cpus

    @property
    def memory(self):
        return require_active_execution().memory

    def contains(self, now=None):
        require_active_execution()
        return True

    def dispatch_allowed(self, now=None):
        require_active_execution()
        return True

    def seconds_remaining(self, now=None):
        require_active_execution()
        # Always-open admission does not remove finite per-job/process budgets.
        return 86400.0
