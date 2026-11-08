"""Persistent manifests and atomic per-trial commits, independent of scratch.

Repeated site IDs are legitimate draws under sampling with replacement. Only
trial IDs are unique; recovery must not silently remove repeated random draws.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

OUTCOMES = {"Masked", "SDC", "DUE", "Unknown"}


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def fingerprint(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def safe_id(value):
    value = str(value)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) or value in {".", ".."}:
        raise ValueError("invalid persistent identifier: " + repr(value))
    return value


def requested_prefix(manifest, target_count, *, dispatch_limit=1000):
    """Administrative draw ceiling; it does not alter the master identity."""
    count = len(manifest) if target_count is None else target_count
    if (type(dispatch_limit) is not int or dispatch_limit < 1 or type(count) is not int
            or not 1 <= count <= len(manifest) or count > dispatch_limit):
        raise ValueError("requested draws exceed the current phase dispatch ceiling")
    return count


class CampaignLedger:
    def __init__(self, directory, spec, manifest, resume=False, *, target_count=None):
        self.directory = Path(directory)
        if not isinstance(spec, dict):
            raise ValueError("campaign spec must be an object")
        self.master_manifest = list(manifest)
        if target_count is not None and (type(target_count) is not int or not 1 <= target_count <= len(self.master_manifest)):
            raise ValueError("target count must be a nonempty prefix of the immutable master manifest")
        self.target_count = len(self.master_manifest) if target_count is None else target_count
        self.prefix_limited = target_count is not None
        self.manifest = self.master_manifest[:self.target_count]
        self.by_id = {}
        master_ids = set()
        for row in self.master_manifest:
            if not isinstance(row, dict) or not row.get("site_id"):
                raise ValueError("every trial requires its resolved canonical site_id")
            trial_id = safe_id(row.get("trial_id", ""))
            if trial_id in master_ids:
                raise ValueError("duplicate trial_id: " + trial_id)
            master_ids.add(trial_id)
        self.by_id = {safe_id(row["trial_id"]): row for row in self.manifest}
        if not self.manifest:
            raise ValueError("an empty manifest cannot define a campaign")
        identity = {"schema_version": 1, "spec": spec, "manifest": self.master_manifest}
        self.identity = fingerprint(identity)
        self.spec = spec
        metadata = dict(identity, fingerprint=self.identity)
        metadata_path = self.directory / "campaign.json"
        if metadata_path.exists():
            if not resume:
                raise FileExistsError("campaign exists; explicitly resume it")
            if json.loads(metadata_path.read_text()) != metadata:
                raise ValueError("campaign configuration or manifest changed; create a new campaign")
        else:
            if resume:
                raise FileNotFoundError("cannot resume an absent campaign")
            atomic_json(metadata_path, metadata)
        self.results = self.directory / "trials"
        self.results.mkdir(exist_ok=True)

    def completion_path(self, name):
        """Each explicit prefix has its own immutable seal and timing history."""
        name = safe_id(name)
        if self.prefix_limited:
            return self.directory / "checkpoints" / ("%08d" % self.target_count) / name
        return self.directory / name

    def read(self, trial_id):
        trial_id = safe_id(trial_id)
        if trial_id not in self.by_id:
            raise ValueError("trial outside the currently requested prefix")
        path = self.results / (trial_id + ".json")
        if not path.exists():
            return None
        record = json.loads(path.read_text())
        if record.get("campaign_fingerprint") != self.identity or record.get("trial_id") != trial_id:
            raise ValueError("foreign or corrupt trial commit: " + trial_id)
        if record.get("manifest_fingerprint") != fingerprint(self.by_id[trial_id]):
            raise ValueError("trial commit belongs to a different site: " + trial_id)
        if record.get("outcome") not in OUTCOMES or record.get("status") != "complete":
            raise ValueError("invalid terminal trial commit: " + trial_id)
        if record.get("record_fingerprint") != fingerprint({k: v for k, v in record.items()
                                                           if k != "record_fingerprint"}):
            raise ValueError("trial commit checksum mismatch: " + trial_id)
        return record

    def pending(self):
        return [row for trial_id, row in self.by_id.items() if self.read(trial_id) is None]

    def commit(self, trial_id, result):
        trial_id = safe_id(trial_id)
        if trial_id not in self.by_id:
            raise ValueError("trial not in campaign manifest")
        if result.get("status") != "complete" or result.get("outcome") not in OUTCOMES:
            raise ValueError("interrupted or invalid attempts cannot be committed as outcomes")
        if result.get("interruption_reason"):
            raise ValueError("administrative interruption is not a fault outcome")
        record = dict(result, trial_id=trial_id, campaign_fingerprint=self.identity,
                      manifest_fingerprint=fingerprint(self.by_id[trial_id]))
        record["record_fingerprint"] = fingerprint(record)
        previous = self.read(trial_id)
        if previous is not None:
            if previous != record:
                raise ValueError("refusing to overwrite a completed trial")
            return previous
        # A single dispatcher owns a campaign; workers commit different trial IDs.
        atomic_json(self.results / (trial_id + ".json"), record)
        return record

    def interrupt(self, trial_id, attempt):
        trial_id = safe_id(trial_id)
        if trial_id not in self.by_id:
            raise ValueError("interrupted trial not in manifest")
        record = dict(attempt, status="interrupted", trial_id=trial_id,
                      campaign_fingerprint=self.identity)
        if "outcome" in record:
            raise ValueError("administrative interruption must not carry an outcome")
        atomic_json(self.directory / "attempts" / (trial_id + ".json"), record)

    def summary(self, require_complete=True):
        counts = {outcome: 0 for outcome in sorted(OUTCOMES)}
        completed = 0
        for trial_id in self.by_id:
            record = self.read(trial_id)
            if record is not None:
                counts[record["outcome"]] += 1
                completed += 1
        if require_complete and completed != len(self.manifest):
            raise ValueError("incomplete campaign cannot be published")
        return {"schema_version": 1, "campaign_fingerprint": self.identity,
                "status": "complete" if completed == len(self.manifest) else "incomplete",
                "denominator": len(self.manifest), "completed": completed, "counts": counts,
                "rates": {key: value / len(self.manifest) for key, value in counts.items()}}
