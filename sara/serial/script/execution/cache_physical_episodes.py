"""Neutral physical residency preparation from closed actual cache records.

This layer reconstructs sampled physical state, including invalid storage. It
never issues a replay origin, a GEREM byte-consumer profile or mapping authority.
All derived lifetimes use the actual post-core/pre-FI hook, not stored u32 times.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path

from script.execution.memory_effect_records import decode, integer, read_closed_ledger
from script.execution.method_input_context import FrozenDict, FrozenList


IDENTITY = ("cache_instance", "geometry_epoch", "line", "allocation_version",
            "block", "tag", "line_bytes", "actual_allocated_lines", "cache_type")


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): value.update(chunk)
    return value.hexdigest()


def identity(row):
    if not isinstance(row, dict): raise ValueError("physical_identity_missing")
    result = {key: integer(row.get(key)) for key in IDENTITY}
    if (not result["cache_instance"] or not result["geometry_epoch"] or not result["line_bytes"]
            or result["line"] >= result["actual_allocated_lines"] or result["cache_type"] not in (0, 1)):
        raise ValueError("physical_identity_domain")
    return result


def _validate_sector_states(row, copy):
    states = row.get("sector_state")
    expected = 1 if copy["cache_type"] == 0 else 4
    if not isinstance(states, list) or len(states) != expected or copy["line_bytes"] % expected:
        raise ValueError("physical_sector_shape")
    for item in states:
        if (not isinstance(item, dict) or set(item) != {"status", "readable"} or integer(item.get("status")) > 3
                or type(item.get("readable")) is not bool):
            raise ValueError("physical_sector_state")
    return states


def sector_states(row, copy):
    return deepcopy(_validate_sector_states(row, copy))


def _empty_frozen_instance_attributes(value):
    # Exact Frozen containers still have writable instance dictionaries. Their
    # attributes can shadow get/items/__deepcopy__; inspect no such method.
    attributes = object.__getattribute__(value, "__dict__")
    return type(attributes) is dict and dict.__len__(attributes) == 0


def _plain_sector_state_input(row):
    """Route without invoking user getters, iterators, hashes or copy hooks.

    Only known exact containers are inspected, using built-in operations;
    exact Frozen containers must first have empty plain instance dictionaries.
    The physical-copy argument is deliberately not inspected by this probe.
    Unknown/subclass/nested shapes retain one complete legacy snapshot call.
    """
    kind = type(row)
    if kind is not dict and kind is not FrozenDict:
        return False
    if kind is FrozenDict and not _empty_frozen_instance_attributes(row):
        return False
    if any(type(key) is not str for key in dict.keys(row)):
        return False
    states = dict.get(row, "sector_state")
    kind = type(states)
    if kind is not list and kind is not FrozenList:
        return False
    if kind is FrozenList and not _empty_frozen_instance_attributes(states):
        return False
    for item in list.__iter__(states):
        kind = type(item)
        if kind is not dict and kind is not FrozenDict:
            return False
        if kind is FrozenDict and not _empty_frozen_instance_attributes(item):
            return False
        for key, value in dict.items(item):
            if type(key) is not str:
                return False
            kind = type(value)
            if not (kind is type(None) or kind is bool or kind is int or kind is str
                    or (kind is float and math.isfinite(value))):
                return False
    return True


def _validate_discarded_sector_states(row, copy):
    if _plain_sector_state_input(row):
        _validate_sector_states(row, copy)
    else:
        sector_states(row, copy)


def _plain_hook_mapping(value):
    kind = type(value)
    if kind is not dict and kind is not FrozenDict:
        return False
    if kind is FrozenDict and not _empty_frozen_instance_attributes(value):
        return False
    return all(type(key) is str for key in dict.keys(value))


def _plain_hook_copy(value):
    if not _plain_hook_mapping(value) or set(dict.keys(value)) != set(IDENTITY):
        return False
    return all(type(item) is int for item in dict.values(value))


def _plain_hook_states(value):
    kind = type(value)
    if kind is not list and kind is not FrozenList:
        return False
    if kind is FrozenList and not _empty_frozen_instance_attributes(value):
        return False
    for item in list.__iter__(value):
        if (not _plain_hook_mapping(item)
                or set(dict.keys(item)) != {"status", "readable"}
                or type(dict.__getitem__(item, "status")) is not int
                or type(dict.__getitem__(item, "readable")) is not bool):
            return False
    return True


def _hook_sector_snapshot(row, raw_copy, previous, normalized_copy):
    """Omit only a snapshot proved equal to the already retained RLE state.

    These probes use built-in operations on exact, hook-free containers only.
    Unknown/custom/malformed comparison operands retain the entire old call
    before the old comparison. A retained new interval still owns its deepcopy.
    The boolean is separate from the copied value: a custom deepcopy is allowed
    to return any object, including None, on the unchanged fallback path.
    """
    if (_plain_hook_mapping(row) and _plain_hook_copy(raw_copy)
            and _plain_hook_copy(normalized_copy) and _plain_hook_mapping(previous)
            and _plain_hook_copy(dict.get(previous, "copy"))
            and _plain_hook_states(dict.get(row, "sector_state"))
            and _plain_hook_states(dict.get(previous, "sector_state"))):
        # Keep the original validation even when the two states are identical.
        states = _validate_sector_states(row, raw_copy)
        if (dict.__getitem__(previous, "copy") == normalized_copy
                and dict.__getitem__(previous, "sector_state") == states):
            return True, None
        return False, deepcopy(states)
    return False, sector_states(row, raw_copy)


class ResidencyBuilder:
    """Pure RLE reconstruction; retained authenticity is independently required."""
    def __init__(self):
        self.expected = None
        self.state, self.owners, self.slots = {}, {}, {}
        self.dirty_owners, self.dirty_slots = set(), set()
        self.owner_bits, self.active_bits = {}, 0
        self.last_cycle = self.first_cycle = None
        self.hooks = self.total_bits = 0
        self.spans, self.owner_spans = [], []
        self.open_slots, self.open_owners, self.instance_owners = {}, {}, {}
        self.access_records = []
        self.closed = False

    def consume(self, row):
        kind = row.get("kind")
        if self.closed: raise ValueError("record_after_derived_close")
        if kind == "cache_topology":
            keys = row.get("owners")
            if (self.expected is not None or not isinstance(keys, list) or not keys
                    or any(not isinstance(key, str) for key in keys) or len(keys) != len(set(keys))):
                raise ValueError("physical_owner_topology")
            self.expected = set(keys)
        elif kind == "cache_owner":
            owner = deepcopy(row); key = owner["key"]
            self.state[key] = self.owners[key] = owner
            self.dirty_owners.add(key)
        elif kind == "cache_slot":
            item = deepcopy(row); copy = identity(item.get("copy"))
            owner_key, index = item.get("owner_key"), copy["line"]
            if not isinstance(owner_key, str) or item.get("key") != owner_key + ":" + str(index):
                raise ValueError("canonical_physical_slot_key_required")
            _validate_discarded_sector_states(item, copy)
            slots = self.slots.setdefault(owner_key, {})
            if index not in slots: self.dirty_owners.add(owner_key)
            slots[index] = item; self.state[item["key"]] = item
            self.dirty_slots.add((owner_key, index))
        elif kind == "cache_removed":
            old = self.state.pop(row.get("key"), None)
            if old is None: raise ValueError("unseen_state_removal")
            if old["kind"] == "cache_owner":
                self.owners.pop(old["key"]); self.dirty_owners.add(old["key"])
            else:
                owner_key, index = old["owner_key"], old["copy"]["line"]
                self.slots[owner_key].pop(index); self.dirty_owners.add(owner_key)
                self.dirty_slots.add((owner_key, index))
        elif kind == "cache_hook": self.hook(row)
        elif kind in {"cache_access", "cache_fill", "cache_response", "functional_cache_load_source",
                      "functional_cache_store_intent", "functional_cache_unbound", "cache_disposition",
                      "cache_write_request_sent"}:
            self.access_records.append(deepcopy(row))
        elif kind == "close":
            if self.dirty_owners or self.dirty_slots: raise ValueError("physical_change_without_actual_hook")
            self.closed = True

    def validate_owner(self, key):
        owner = self.owners.get(key)
        if owner is None: raise ValueError("whole_owner_domain_missing")
        component, scope = owner.get("component"), integer(owner.get("scope"))
        if (component not in {"l1d", "l2"} or key != component + ":" + str(scope)
                or owner.get("owner_key") != key or type(owner.get("disabled")) is not bool):
            raise ValueError("physical_owner_shape")
        slots = self.slots.get(key, {})
        if owner["disabled"]:
            if (integer(owner.get("active_lines")) != 0 or owner.get("present") is not False
                    or owner.get("actual_backing_capacity_known") is not False or slots):
                raise ValueError("disabled_owner_nonempty")
            return 0
        if (owner.get("present") is not True or owner.get("actual_backing_capacity_known") is not True
                or owner.get("active_index_allocation_validated") is not True):
            raise ValueError("unresolved_required_physical_owner")
        lines = integer(owner.get("active_lines"), positive=True)
        capacity = integer(owner.get("actual_allocated_lines"), positive=True)
        width = integer(owner.get("line_bytes"), positive=True)
        cache_type = integer(owner.get("cache_type"))
        if lines > capacity: raise ValueError("active_domain_exceeds_actual_backing")
        if cache_type not in (0, 1) or width % (1 if cache_type == 0 else 4):
            raise ValueError("physical_owner_geometry")
        # Canonical nonnegative keys + cardinality + bounds prove the complete
        # current index domain without enumerating configured capacity per tick.
        if len(slots) != lines or any(index >= lines for index in slots):
            raise ValueError("physical_slot_missing_or_extra_index")
        for index, item in slots.items():
            self.validate_slot(key, index, item)
        return lines * (57 + width * 8)

    def validate_slot(self, key, index, item):
        owner = self.owners.get(key)
        if owner is None: raise ValueError("whole_owner_domain_missing")
        copy = identity(item.get("copy"))
        if (owner["disabled"] or copy["line"] != index or index >= owner["active_lines"]
                or any(copy[name] != owner[name] for name in ("line_bytes", "actual_allocated_lines", "cache_type"))):
            raise ValueError("slot_and_actual_owner_shape_disagree")
        _validate_discarded_sector_states(item, copy)
        location = (key, owner["component"], owner["scope"])
        known = self.instance_owners.setdefault(copy["cache_instance"], location)
        if known != location: raise ValueError("physical_instance_reused_by_other_owner")

    def hook(self, row):
        cycle = integer(row.get("cycle")); self.hooks += 1
        if integer(row.get("hook"), positive=True) != self.hooks or (self.last_cycle is not None and cycle != self.last_cycle + 1):
            raise ValueError("physical_hook_gap_or_repeat")
        if self.first_cycle is None: self.first_cycle = cycle
        if self.expected is None or set(self.owners) != self.expected:
            raise ValueError("whole_owner_domain_missing")
        for key in sorted(self.dirty_owners):
            bits = self.validate_owner(key)
            self.active_bits += bits - self.owner_bits.get(key, 0); self.owner_bits[key] = bits
            owner = self.owners[key]
            view = {name: owner.get(name) for name in ("component", "scope", "disabled", "present", "active_lines",
                    "actual_allocated_lines", "line_bytes", "cache_type", "actual_backing_capacity_known",
                    "active_index_allocation_validated")}
            previous = self.open_owners.get(key)
            if previous is None or previous["view"] != view:
                if previous is not None: previous["end_cycle"] = cycle
                previous = dict(owner_key=key, view=view, start_cycle=cycle, end_cycle=None)
                self.open_owners[key] = previous; self.owner_spans.append(previous)
            self.dirty_slots.update((key, index) for index in self.slots.get(key, {}))
        for token in sorted(self.dirty_slots):
            key, index = token; item = self.slots.get(key, {}).get(index)
            previous = self.open_slots.get(token)
            if item is None:
                if previous is not None: previous["end_cycle"] = cycle; self.open_slots.pop(token)
                continue
            self.validate_slot(key, index, item)
            copy = identity(item["copy"])
            unchanged, states = _hook_sector_snapshot(item, item["copy"], previous, copy)
            if unchanged: continue
            if previous is not None and previous["copy"] == copy and previous["sector_state"] == states: continue
            if previous is not None: previous["end_cycle"] = cycle
            owner = self.owners[key]
            current = dict(owner_key=key, component=owner["component"], scope=owner["scope"], copy=copy,
                           sector_state=states, start_cycle=cycle, end_cycle=None)
            self.open_slots[token] = current; self.spans.append(current)
        self.dirty_owners.clear(); self.dirty_slots.clear()
        self.last_cycle = cycle; self.total_bits += self.active_bits
        if (integer(row.get("active_bit_count")) != self.active_bits
                or integer(row.get("cumulative_bit_cycles")) != self.total_bits
                or integer(row.get("state_keys")) != len(self.state)
                or integer(row.get("unresolved_expected_bits")) != 0):
            raise ValueError("derived_physical_raw_mass_disagrees")

    def report(self, include_timing_records=True):
        if type(include_timing_records) is not bool: raise ValueError("explicit_timing_record_output_policy_required")
        if not self.closed or not self.hooks: raise ValueError("closed_whole_physical_window_required")
        for span in list(self.open_slots.values()) + list(self.open_owners.values()):
            span["end_cycle"] = self.last_cycle + 1
        mass = sum((span["end_cycle"]-span["start_cycle"]) * (57+span["copy"]["line_bytes"]*8)
                   for span in self.spans)
        if mass != self.total_bits: raise ValueError("residency_interval_mass_lost")
        for row in self.access_records:
            candidates = [row.get(key) for key in ("before_copy", "selected_copy", "source", "destination")]
            candidates += [row[name]["copy"] for name in ("before", "after") if row.get(name) is not None]
            for cell in row.get("bytes", []):
                candidates += [cell[name]["copy"] for name in ("l1", "l2") if cell.get(name) and cell[name].get("copy") is not None]
            for value in candidates:
                if value is not None and identity(value)["cache_instance"] not in self.instance_owners:
                    raise ValueError("timing_copy_owner_never_independently_observed")
        result = dict(schema="sara-neutral-physical-cache-residencies-v1", coordinate_system="simulator_physical_cache_slots",
                    phase="after_all_core_instruction_events_at_cycle", first_cycle=self.first_cycle,
                    cycle_stop=self.last_cycle+1, hook_ticks=self.hooks, bit_cycles=self.total_bits,
                    owner_views=self.owner_spans, residency_spans=self.spans, timing_records=self.access_records,
                    functional_consumer_coverage_complete=False, complete_byte_accesses=False,
                    unresolved_authority=["complete_per_byte_version_consumer_profile",
                                          "actual_accepted_dirty_writeback_semantics",
                                          "source_bound_retained_worker_and_population_admission"],
                    mapping_certified=False, replay_authorized=False, all_gates_pass=False)
        if not include_timing_records:
            result.pop("timing_records")
            result["timing_records_policy"] = "omitted_unconsumed_duplicate_after_full_owner_validation_raw_records_retained"
        return result


def prepare_physical_residencies(ledger, trace, sidecar, *, expected_budget_bytes):
    """Reopen checked actual raw files; never accept a caller certification flag."""
    paths = tuple(Path(item) for item in (ledger, trace, sidecar))
    before = [digest(item) for item in paths]
    checked = read_closed_ledger(*paths, expected_budget_bytes=expected_budget_bytes, expected_cache_state=True)
    builder = ResidencyBuilder()
    with paths[0].open("rb") as stream:
        for line in stream: builder.consume(decode(line))
    result = builder.report()
    if result["bit_cycles"] != checked["cache_bit_cycles"] or result["hook_ticks"] != checked["cache_hook_ticks"]:
        raise ValueError("independent_raw_checker_mass_disagrees")
    if before != [digest(item) for item in paths]: raise ValueError("retained_raw_changed_during_preparation")
    result["raw_inputs_sha256"] = dict(zip(("ledger", "trace", "completeness"), before))
    return result
