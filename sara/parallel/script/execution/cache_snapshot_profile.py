"""Value-free sources of the functional-snapshot-cache-v3 approximation.

This adapter describes consumption, not fault outcomes. Both SARA's backward
projection and GEREM's storage EFM use the same actual issue-time cache copy.
No FI payload, classification, numeric operand or query manifest is inspected.
Timing responses never select a new data source for an already issued load.
"""
from collections import defaultdict

MODEL = "functional-snapshot-cache-v3"


def instruction(row, functional=False):
    """Native cache_read_key identity, excluding only its per-block address."""
    names = ("sm", "warp", "instruction_pc",
             "instruction_issue_cycle" if functional else "instruction_issue")
    values = tuple(row.get(name) for name in names)
    return None if any(value is None for value in values) else values


def selected_copy(row, cell):
    """Select readable L1, else readable L2, else functional backing.

    HIT_RESERVED and unreadable candidates are not DATA consumers. A false
    hit is intentionally backed by functional memory rather than guessed
    bytes from a different block; it does not fall through to another copy.
    """
    first = cell.get("l1") if not row["l1_bypass"] else None
    lower = cell.get("l2")
    chosen = first if first and first.get("probe_status") == 0 else None
    chosen = chosen or (lower if lower and lower.get("probe_status") == 0 else None)
    if chosen is None:
        return None
    copy = chosen.get("copy")
    if copy is None:
        raise ValueError("snapshot_hit_missing_actual_copy")
    address = cell["address"]
    if not copy["block"] <= address < copy["block"] + copy["line_bytes"]:
        return None  # declared tag-alias functional-backing approximation
    return copy


def sector(copy, address):
    count = 1 if copy["cache_type"] == 0 else 4 if copy["cache_type"] == 1 else 0
    if not count or copy["line_bytes"] % count:
        raise ValueError("snapshot_actual_sector_geometry_required")
    size = copy["line_bytes"] // count
    begin = copy["block"] + ((address-copy["block"]) // size) * size
    return begin, size


class SnapshotProfile:
    """One first issue snapshot per instruction/block/sector, with fanout.

    A scalar request also snapshots its selected sector's sibling bytes. A
    later fill can therefore transport an error outside the scalar byte mask.
    The first observation of a sector binds its producer; timing responses or
    merged requests cannot replace that binding with a later physical source.
    """
    def __init__(self, rows, *, require_model=True):
        if require_model and (not rows or rows[0].get("cache_fault_model") != MODEL):
            raise ValueError("functional_snapshot_cache_v3_producer_required")
        self.sources = defaultdict(list)
        self.by_instruction = defaultdict(list)
        self.issue_reads = defaultdict(list)
        self.functional_records = 0
        for row in rows:
            if row.get("kind") != "functional_cache_load_source":
                continue
            self.functional_records += 1
            token = instruction(row, functional=True)
            if token is None:
                raise ValueError("snapshot_actual_instruction_identity_required")
            for cell in row["bytes"]:
                copy = selected_copy(row, cell)
                if copy is None:
                    continue
                begin, size = sector(copy, cell["address"])
                key = token, copy["block"]
                previous = [item for item in self.sources[key]
                            if item["start"] == begin and item["count"] == size]
                if previous:
                    continue
                item = dict(copy=copy, start=begin, count=size,
                            sequence=row["sequence"], cycle=row["cycle"])
                if any(begin < old["start"] + old["count"] and
                       old["start"] < begin + size for old in self.sources[key]):
                    raise ValueError("overlapping_issue_snapshot_sector_geometry")
                self.sources[key].append(item)
                self.by_instruction[token].append(item)
                self.issue_reads[row["sequence"]].append(item)

    def source(self, row, address):
        """Return an issue producer for a transported byte, or clean backing."""
        token = instruction(row)
        if token is None:
            return None  # non-instruction requests use clean functional backing
        found = [item for item in self.by_instruction.get(token, ())
                 if item["start"] <= address < item["start"] + item["count"]]
        if len(found) > 1:
            raise ValueError("transport_byte_has_multiple_issue_snapshot_sources")
        if found and found[0]["sequence"] >= row["sequence"]:
            raise ValueError("timing_transport_precedes_its_functional_issue")
        return found[0] if found else None

    def report(self):
        return dict(model=MODEL, functional_load_records=self.functional_records,
                    issue_sector_snapshots=sum(map(len, self.sources.values())),
                    source_selection="functional_issue_readable_L1_else_L2_else_backing",
                    prefault_reads="immutable_clean_issue_snapshot",
                    dirty_error_writeback="discard_to_functional_backing",
                    per_origin_replay=False)
