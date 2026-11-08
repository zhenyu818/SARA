"""Per-child resource accounting with exclusive wait4 ownership (POSIX).

Each MeasuredChild reaps only its own PID. Concurrent trials must never measure
RUSAGE_CHILDREN differences, which include other workers' completed children.
Do not call poll/wait/communicate on ``child.process``: this wrapper exclusively
owns reaping. Redirect output to files or drain pipes independently.

wait4 accounts for the child and descendants the child itself waited for. It
does not certify an orphaned process tree's total CPU or aggregate memory. RSS
is a peak, not a sum across concurrent processes. The outer Docker/cgroup limit
remains responsible for the whole trial container. Wall time is monotonic time
from immediately before Popen until wait4 observes termination.
"""
import math
import os
import signal
import subprocess
import sys
import threading
import time

from script.execution.policy import require_container_execution


class ReapOwnershipError(RuntimeError):
    """Another waiter consumed this child's exit status/resource record."""


class MeasuredChild:
    def __init__(self, argv, **popen_options):
        if not hasattr(os, "wait4") or not hasattr(os, "killpg"):
            raise RuntimeError("per-child metrics require POSIX wait4 and process groups")
        if (not isinstance(argv, (list, tuple)) or not argv or
                any(not isinstance(value, str) for value in argv) or not argv[0]):
            raise ValueError("argv must be a nonempty string array with an executable")
        if popen_options.get("shell", False):
            raise ValueError("use an explicit argv, without a shell")
        if popen_options.get("start_new_session", True) is not True:
            raise ValueError("MeasuredChild requires its own session/process group")
        if popen_options.get("preexec_fn") is not None:
            raise ValueError("preexec_fn is unsafe in the threaded campaign executor")
        popen_options["start_new_session"] = True
        self._lock = threading.Lock()
        self._finished = None
        self._usage = None
        self._wait_status = None
        self._ownership_lost = False
        self._stop_requested = False
        require_container_execution()
        self._started = time.monotonic()
        self.process = subprocess.Popen(list(argv), **popen_options)
        self.pid = self.process.pid

    @property
    def returncode(self):
        return self.process.returncode

    def _poll_locked(self):
        if self._ownership_lost:
            raise ReapOwnershipError("wait4 ownership was lost for PID %d" % self.pid)
        if self._finished is not None:
            return self.process.returncode
        while True:
            try:
                pid, status, usage = os.wait4(self.pid, os.WNOHANG)
                break
            except InterruptedError:
                continue
            except ChildProcessError as error:
                self._ownership_lost = True
                raise ReapOwnershipError(
                    "PID %d was reaped outside MeasuredChild; resource usage is unavailable" % self.pid
                ) from error
        if pid == 0:
            return None
        if pid != self.pid:
            raise RuntimeError("wait4 returned a different child PID")
        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            code = -os.WTERMSIG(status)
        else:
            raise RuntimeError("wait4 returned a nonterminal child status")
        # Prevent Popen's destructor/internal polling from trying to reap again.
        self.process.returncode = code
        self._wait_status = status
        self._usage = usage
        self._finished = time.monotonic()
        return code

    def poll(self):
        """Return None while running; otherwise return Popen's exit/signal code."""
        with self._lock:
            return self._poll_locked()

    def _signal_group_locked(self, signum):
        # No waiter can reap this PID while this instance lock is held. Until
        # wait4 reaps the leader, even an exited zombie pins its PID/PGID, so a
        # kill cannot race with reuse of this PID by an unrelated process.
        try:
            os.killpg(self.pid, signum)
            return True
        except ProcessLookupError:
            return False

    def stop(self, grace_seconds=0.1):
        """TERM the owned process group, then KILL it, and reap the leader.

        Grace is bounded to one second. The leader is deliberately left
        unreaped during grace: otherwise a leader that exits on TERM could
        leave a descendant ignoring TERM alive, or its PID could be reused
        before group KILL. After KILL, allow at most one second for reaping;
        failure raises TimeoutError for the outer container stop to handle.
        An already reaped child is never signalled again.
        """
        if (isinstance(grace_seconds, bool) or not isinstance(grace_seconds, (int, float)) or
                not math.isfinite(grace_seconds) or not 0 <= grace_seconds <= 1):
            raise ValueError("grace_seconds must be finite and between zero and one")
        with self._lock:
            if self._ownership_lost:
                raise ReapOwnershipError("cannot signal a child after wait4 ownership was lost")
            if self._finished is not None:
                return self.process.returncode
            self._stop_requested = True
            signalled = self._signal_group_locked(signal.SIGTERM)
            if not signalled:
                code = self._poll_locked()
                if code is not None:
                    return code
            deadline = time.monotonic() + grace_seconds
            # Do not use poll here: keeping the leader unreaped pins its PID
            # until group KILL, including when descendants outlive the leader.
            while time.monotonic() < deadline:
                time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
            self._signal_group_locked(signal.SIGKILL)
            reap_deadline = time.monotonic() + 1.0
            while True:
                code = self._poll_locked()
                if code is not None:
                    return code
                if time.monotonic() >= reap_deadline:
                    raise TimeoutError("SIGKILL child %d did not become reapable" % self.pid)
                time.sleep(0.002)

    def metrics(self):
        """Return a JSON-compatible snapshot; CPU/RSS are None before reaping."""
        with self._lock:
            reaped = self._finished is not None
            usage = self._usage
            rss_bytes = (None if usage is None else
                         int(usage.ru_maxrss) * (1 if sys.platform == "darwin" else 1024))
            return {
                "schema_version": 1,
                "pid": self.pid,
                "reaped": reaped,
                "measurement": "wait4_for_this_pid",
                "scope": "child_and_descendants_waited_for_by_child",
                "cpu_user_seconds": None if usage is None else float(usage.ru_utime),
                "cpu_system_seconds": None if usage is None else float(usage.ru_stime),
                "cpu_total_seconds": None if usage is None else float(usage.ru_utime + usage.ru_stime),
                "max_rss_bytes": rss_bytes,
                "max_rss_kib": None if rss_bytes is None else rss_bytes / 1024.0,
                "wall_seconds": (self._finished if reaped else time.monotonic()) - self._started,
                "exit_status": self.process.returncode,
                "raw_wait_status": self._wait_status,
                "stop_requested": self._stop_requested,
                "ownership_lost": self._ownership_lost,
            }
