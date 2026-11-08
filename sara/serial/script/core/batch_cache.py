"""Batch physical DATA projection of the shared local-sensitivity model.

Each recorded assignment/transport is visited once in reverse order. This is
mask propagation, not origin replay. Immutable transport snapshots preserve
fanout identity at copy boundaries; local bit-sensitivity composition still
has the declared correlated-change/reconvergence approximations.

The declared functional-snapshot-cache-v3 model samples readable copies at
functional issue; later timing responses never change an issued operand.
Fill/store boundaries end overwritten DATA dependencies. Tag sensitivity and
genuinely unproved semantics retain Unknown in the complete fault population.
"""
from collections import defaultdict
from script.core.cache_tag_lifetime import classify_invalid_tag_suffixes

from script.core.batch_backward import Region, masks, analyze_rf
from script.core.reg_observed_analyzer import compact_cache_site_row_to_dict
from script.execution.cache_physical_facts import physical, join_functional_records, raw_physical, addressed
from script.execution.memory_effect_records import ranges, within
from script.execution.cache_snapshot_profile import SnapshotProfile, selected_copy


class PhysicalBackward:
    def __init__(self, rows, residencies, influences):
        self.rows, self.residencies, self.influences = rows, residencies, influences
        self.live, self.issue_transport = defaultdict(dict), defaultdict(dict)
        self.copies, self.dirty = {}, set()
        self.changes, self.last = defaultdict(list), {}
        self.snapshots = SnapshotProfile(rows)
        self.source_ranges = {row["sequence"]: ranges(row["ranges"]) for row in rows
                              if row.get("kind") in ("cache_fill", "cache_response")}

    def alter(self, copy, address, value, *, kill=False):
        key = physical(copy)
        offset = address - copy["block"]
        if not 0 <= offset < copy["line_bytes"]:
            raise ValueError("physical byte outside its actual copy")
        self.copies[key] = copy
        old = self.live[key].get(address, (0, 0, 0))
        new = (0, 0, 0) if kill else tuple(a | b for a, b in zip(old, value))
        if old != new:
            if any(new): self.live[key][address] = new
            else: self.live[key].pop(address, None)
            self.dirty.add(key)

    def hook(self, cycle):
        for key in self.dirty:
            copy, word = self.copies[key], [0, 0, 0]
            for address, value in self.live[key].items():
                shift = (address-copy["block"])*8
                for index in range(3): word[index] |= value[index] << shift
            value = tuple(word)
            if value != self.last.get(key, (0, 0, 0)):
                self.changes[key].append((cycle, value)); self.last[key] = value
        self.dirty.clear()

    def propagate(self):
        if any(row.get("kind") == "functional_cache_unbound" for row in self.rows):
            raise ValueError("unbound functional cache access in reported workload")
        for row in reversed(self.rows):
            kind = row.get("kind")
            if kind == "cache_hook":
                self.hook(row["cycle"])
            elif kind == "functional_cache_load_source":
                if row["atomic"]:
                    raise ValueError("atomic load outside frozen cache support")
                for (copy_key, address), (copy, value) in self.issue_transport.pop(row["sequence"], {}).items():
                    if physical(copy) != copy_key:
                        raise ValueError("issue_snapshot_copy_identity_changed")
                    self.alter(copy, address, value)
                for offset, cell in enumerate(row["bytes"]):
                    chosen = selected_copy(row, cell)
                    if chosen is None:
                        continue  # actual functional fetch from backing, no resident DATA consumed
                    value = self.influences.get((row["sequence"], offset), (0, 0, 0))
                    self.alter(chosen, cell["address"], value)
            elif kind == "cache_fill":
                copy = row["destination"]; key = physical(copy)
                coverage = self.source_ranges[row["sequence"]]
                wanted = {}
                for address, value in list(self.live[key].items()):
                    if within(address, coverage):
                        wanted[address] = value
                        self.alter(copy, address, (0, 0, 0), kill=True)
                for address, value in wanted.items():
                    source = self.snapshots.source(row, address)
                    if source is not None:
                        seq, actual = source["sequence"], source["copy"]
                        token = physical(actual), address
                        previous = self.issue_transport[seq].get(token)
                        old = previous[1] if previous else (0, 0, 0)
                        self.issue_transport[seq][token] = (actual, tuple(a | b for a, b in zip(old, value)))
            elif kind == "cache_disposition" and row["operation"] == "actual_access" and row["write"] and row["accepted_status"] != 3:
                before = row.get("before")
                if before:
                    for address in addressed(row):
                        if before["copy"]["block"] <= address < before["copy"]["block"]+before["copy"]["line_bytes"]:
                            self.alter(before["copy"], address, (0, 0, 0), kill=True)
        if self.issue_transport:
            raise ValueError("unconsumed functional issue snapshot in backward pass")
        return self

    def intervals(self, copy):
        value, end = (0, 0, 0), self.residencies["cycle_stop"]
        for cycle, current in self.changes.get(physical(copy), []):
            if cycle+1 < end:
                yield cycle+1, end, value
            value, end = current, cycle+1
        if self.residencies["first_cycle"] < end:
            yield self.residencies["first_cycle"], end, value

    def regions(self, inventory):
        spans = self.residencies["residency_spans"]
        if len(spans) != len(inventory["spans"]):
            raise ValueError("inventory must retain every actual residency")
        for span_index, (observed, span) in enumerate(zip(spans, inventory["spans"])):
            if observed["component"] != span["component"]:
                raise ValueError("physical component projection order differs")
            copy = observed["copy"]; width = span["bit_count"]
            unknown = self.tag_support["unknown_masks"][span_index]
            for start, stop, values in self.intervals(copy):
                lo, hi = max(start, span["cycle_start"]), min(stop, span["cycle_stop"])
                if lo >= hi: continue
                obs, due, expanding = (value << 57 for value in values)
                obs &= ~unknown; due &= ~unknown
                yield Region(span["component"], span["target"], lo, hi, span["bit_start"], width,
                    masks(width, obs, due, expanding | unknown),
                    "unproved_active_tag_or_batch_semantic_dependency")


def analyze_cache(trace, inventory, outputs, descriptor, directory, *, defer_provenance=False,
                  aggregate_only=False):
    if type(defer_provenance) is not bool:
        raise ValueError('explicit cache provenance policy required')
    files = descriptor["files"]
    rows, residencies = raw_physical(directory / files["cache_ledger"]["path"],
        directory / files["trace"]["path"], directory / files["trace_sidecar"]["path"])
    component = inventory["spans"][0]["component"]
    # Whole ledger retained for cross-level transport; inventory is one component.
    filtered = dict(residencies, residency_spans=[r for r in residencies["residency_spans"] if r["component"] == component])
    joined = join_functional_records(rows, trace["events"], strict_numeric=True)
    events, analysis = analyze_rf(trace, inventory, output_spec=outputs, aggregate_only=aggregate_only)
    influences = {}
    byte_masks = {}
    for raw in analysis["l1d_fault_sites"]:
        item = compact_cache_site_row_to_dict(raw)
        if trace["events"][item["event_index"]].get("kind") != "load": continue
        key = (item["event_index"], item["addr"])
        byte_masks[key] = tuple(int(item[field]) for field in
            ("observed_mask_this_site", "due_mask_this_site", "trace_expanding_mask_this_site"))
    for row in rows:
        if row.get("kind") != "functional_cache_load_source": continue
        index = joined[row["sequence"]]["event_ordinal"]-1
        for offset, cell in enumerate(row["bytes"]):
            influences[row["sequence"], offset] = byte_masks.get((index, cell["address"]), (0, 0, 0))
    projection = PhysicalBackward(rows, residencies, influences).propagate()
    projection.residencies = filtered
    projection.tag_support = classify_invalid_tag_suffixes(filtered, rows)
    analysis["cache_projection"] = {"raw_records": len(rows), "physical_histories": len(projection.changes),
        "mask_change_events": sum(map(len, projection.changes.values())), "per_origin_replay": False,
        "snapshot_profile": projection.snapshots.report(),
        "tag_support": {k:v for k,v in projection.tag_support.items() if k != "unknown_masks"},
        "support_excludes": ["unproved_live_tag_effects", "unproved_batch_semantics"],
        "inflight_windows": 0}
    if not defer_provenance:
        # Diagnostic normalized provenance is not an input to the model. The
        # production session already binds the exact own ledger/trace bytes in
        # its descriptor; it must not serialize/hash this whole ledger again.
        from script.execution.campaign import fingerprint
        analysis["normalized_cache_input_fingerprint"] = fingerprint([
            {key:value for key,value in row.items() if key != "observer_thread"}
            for row in rows if row["kind"].startswith(("cache_","functional_cache_"))])
    return events, analysis, projection.regions(inventory)
