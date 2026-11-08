"""Verify real cgroup limits before the job; retain whole-container counters."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

from script.execution.campaign import atomic_json
from script.execution.policy import ExecutionWindow, require_active_execution, validate_execution_document

CGROUP = Path("/sys/fs/cgroup")


def cgroup_counters(root=None):
    root = Path(root) if root is not None else CGROUP
    result = {}
    v2 = (root / "cgroup.controllers").exists()
    result["version"] = 2 if v2 else 1
    paths = {name: root / name for name in (
        "cpu.stat", "memory.peak", "memory.current", "memory.events",
        "memory.max", "memory.swap.max", "cpu.max")} if v2 else {
        "cpu.cfs_quota_us": root / "cpu" / "cpu.cfs_quota_us",
        "cpu.cfs_period_us": root / "cpu" / "cpu.cfs_period_us",
        "cpuacct.usage": root / "cpuacct" / "cpuacct.usage",
        "memory.limit_in_bytes": root / "memory" / "memory.limit_in_bytes",
        "memory.memsw.limit_in_bytes": root / "memory" / "memory.memsw.limit_in_bytes",
        "memory.max_usage_in_bytes": root / "memory" / "memory.max_usage_in_bytes",
        "memory.usage_in_bytes": root / "memory" / "memory.usage_in_bytes"}
    for name, path in paths.items():
        try:
            result[name] = path.read_text().strip()
        except OSError:
            result[name] = None
    return result


def validate_cgroup_limits(counters, cpus=8, memory=20 * 1024 ** 3):
    """Fail closed if quota, RAM cap, or zero-swap cap cannot be verified."""
    try:
        if counters["version"] == 2:
            quota, period = counters["cpu.max"].split()
            quota, period = int(quota), int(period)
            ram = int(counters["memory.max"])
            no_swap = int(counters["memory.swap.max"]) == 0
        else:
            quota, period = int(counters["cpu.cfs_quota_us"]), int(counters["cpu.cfs_period_us"])
            ram = int(counters["memory.limit_in_bytes"])
            no_swap = int(counters["memory.memsw.limit_in_bytes"]) == memory
        valid = quota > 0 and period > 0 and quota == cpus * period and ram == memory and no_swap
    except (KeyError, TypeError, ValueError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("actual cgroup must enforce exactly %d CPUs, %d bytes RAM, and zero swap" % (cpus, memory))
    return True


def validate_final_cgroup_resources(record, cpus=8, memory=20 * 1024 ** 3):
    """Validate actual limits and zero OOM independently of an exit category."""
    for stage in ("cgroup_before", "cgroup_after"):
        counters = record.get(stage)
        if not isinstance(counters, dict) or counters.get("version") != 2:
            raise ValueError("actual cgroup-v2 completion counters required")
        validate_cgroup_limits(counters, cpus=cpus, memory=memory)
        raw = counters.get("memory.events")
        if not isinstance(raw, str):
            raise ValueError("actual memory.events missing from completion receipt")
        fields = [line.split() for line in raw.splitlines()]
        if (not fields or any(len(row) != 2 or not row[1].isascii() or not row[1].isdigit() for row in fields)
                or len({row[0] for row in fields}) != len(fields)):
            raise ValueError("malformed or duplicate memory.events completion counters")
        events = {key: int(value) for key, value in fields}
        if not {"oom", "oom_kill"} <= events.keys() or any(events.get(key, 0) for key in ("oom", "oom_kill", "oom_group_kill")):
            raise ValueError("OOM event or incomplete OOM counters: no successful experiment")
    return True


def validate_completed_resources(record, cpus=8, memory=20 * 1024 ** 3):
    """A zero argv exit cannot hide OOM, lost counters or interruption."""
    if (not isinstance(record, dict) or record.get("schema_version") != 2 or record.get("limits_verified") is not True
            or type(record.get("exit_status")) is not int or record["exit_status"] != 0
            or type(record.get("child_exit_status")) is not int or record["child_exit_status"] != 0
            or record.get("window_interrupted") is not False or record.get("interrupted_signals") != []):
        raise ValueError("complete zero-exit, uninterrupted v2 job receipt required")
    return validate_final_cgroup_resources(record, cpus=cpus, memory=memory)


def validate_successful_job(state, record, cpus=8, memory=20 * 1024 ** 3):
    if (not isinstance(state, dict) or state.get("Running") is not False
            or type(state.get("ExitCode")) is not int or state["ExitCode"] != 0
            or state.get("OOMKilled") is not False):
        raise ValueError("normal stopped container with explicit OOMKilled=false required")
    return validate_completed_resources(record, cpus=cpus, memory=memory)


def validate_retained_successful_job(session, record):
    """Validate declared server limits against actual prior cgroup counters.

    Profile-free historical receipts retain their legacy 8/20 contract; this
    pure reader does not authorize execution or authenticate retained evidence.
    """
    descriptor = session.get("execution_profile")
    if descriptor is None and record.get("execution_profile") is None:
        return validate_successful_job(session.get("container_state"), record)
    if not isinstance(descriptor, dict) or record.get("execution_profile") != descriptor:
        raise ValueError("retained session/wrapper execution-profile binding differs")
    document = {key: value for key, value in descriptor.items() if key != "config_sha256"}
    try:
        profile = validate_execution_document(document, descriptor.get("config_sha256"))
    except RuntimeError as error:
        raise ValueError("retained execution-profile shape differs") from error
    return validate_successful_job(session.get("container_state"), record,
                                   cpus=profile.cpus, memory=profile.memory_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-seconds", type=int, default=1800)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing job argv")
    if not 1 <= args.max_seconds <= 86400:
        parser.error("job wall-time budget must be 1 through 86400 seconds")
    profile = require_active_execution(require_environment=True)
    before = cgroup_counters()
    started = time.monotonic()
    process = None
    interrupted = []
    record = {"schema_version": 2, "command": command, "limits_verified": False,
              "cgroup_before": before, "interrupted_signals": interrupted,
              "window_interrupted": False, "wall_time_budget_seconds": args.max_seconds,
              "execution_profile": profile.descriptor()}
    window = ExecutionWindow()

    def forward(signum, frame):
        interrupted.append(signum)
        if process is not None:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    exit_status = 78
    try:
        validate_cgroup_limits(before, cpus=profile.cpus, memory=profile.memory_bytes)
        record["limits_verified"] = True
        # Revalidate server admission immediately before launching job argv.
        if not window.dispatch_allowed():
            raise ValueError("server execution admission denied before workload launch")
        if interrupted:
            exit_status = 128 + interrupted[-1]
        else:
            process = subprocess.Popen(command, start_new_session=True)
            while process.poll() is None:
                # Independent of host polling and Docker daemon responsiveness.
                # The wrapper also enforces a finite per-job wall budget if
                # the host controller or Docker client becomes unavailable.
                wall_expired = time.monotonic() - started >= args.max_seconds
                if window.seconds_remaining() <= 0.2 or wall_expired:
                    record.update(window_interrupted=True, interruption_reason="execution_admission_end")
                    if wall_expired:
                        record["interruption_reason"] = "job_wall_time_budget"
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)
                    break
                if interrupted:
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=2)
                    break
                time.sleep(0.1)
            record["child_exit_status"] = process.returncode
            exit_status = 124 if record["window_interrupted"] else process.returncode
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        record["failure_reason"] = type(error).__name__ + ": " + str(error)
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
            record["child_exit_status"] = process.returncode
    finally:
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        record.update({"finished_utc": datetime.now(timezone.utc).isoformat(),
                       "wall_seconds": time.monotonic() - started,
                       "exit_status": exit_status, "cgroup_after": cgroup_counters(),
                       "children_cpu_user_seconds": usage.ru_utime,
                       "children_cpu_system_seconds": usage.ru_stime,
                       "children_max_rss_kib": usage.ru_maxrss,
                       "measurement_notes": {
                           "memory.peak": "whole fresh job container; null if unavailable, never inferred from sampled memory",
                           "cpu.stat": "whole container inclusive of wrapper; usage_usec is cumulative CPU time",
                           "children_max_rss_kib": "largest reported child RSS, not aggregate concurrent memory"}})
        if exit_status == 75:
            record["administrative_dispatch_refusal"] = "always-open server execution has no administrative night cutoff"
        if exit_status == 0:
            try:
                validate_completed_resources(record, cpus=profile.cpus, memory=profile.memory_bytes)
                record["completion_resources_verified"] = True
            except (TypeError, ValueError, KeyError) as error:
                exit_status = 78
                record.update(exit_status=exit_status, completion_resources_verified=False,
                              failure_kind="completion_resource_validation_failed",
                              failure_reason=str(error))
        atomic_json(args.output, record)
    return 128 + (-exit_status) if exit_status < 0 else exit_status


if __name__ == "__main__":
    raise SystemExit(main())
