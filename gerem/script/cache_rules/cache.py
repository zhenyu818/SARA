"""Deliberately linear reconstruction of GEREM's storage cache EFM.

Inputs are the own raw records and physical residencies returned by the
independent closed-ledger reader.  That reader's byte/source/closure checks
remain mandatory.  This module does not read FI outcomes, SARA answers, or a
prepared cache predictor, and does not import SnapshotProfile/CacheEFM.

Each trial scans the physical spans and future actual records again.  There
are no query indexes, memoized answers, or cross-component model sharing.
Coordinates describe the state AFTER all accesses at the fault cycle; only
strictly later cycles consume the injected value.

The method does not fully specify false-tag-hit behavior, issue/service
ordering, or a cache writeback implementation.  RECONSTRUCTION_ASSUMPTIONS
states the choices here.  In particular, an observed, uniquely matched dirty
WB enqueue is a DCR manifestation; it is NOT proof of corrupt values reaching
functional backing memory under the old functional-snapshot-cache-v3 FI.
"""

from collections.abc import Mapping


RECONSTRUCTION_ASSUMPTIONS = (
    "fault_coordinate_is_state_after_all_accesses_at_its_cycle",
    "accepted_actual_read_or_response_before_assignment_is_DCR",
    "uniquely_matched_actual_dirty_WB_enqueue_is_DCR",
    "dirty_WB_enqueue_does_not_prove_corrupt_value_commit_or_FI_propagation",
    "modified_sector_is_transferred_in_full_including_unstored_bytes",
    "valid_tag_with_future_actual_matching_lookup_is_EBC",
    "tag_false_hits_changed_control_and_other_counterfactual_routes_are_not_reconstructed",
    "no_future_actual_consumer_is_benign_and_close_is_not_a_writeback",
)

_COPY_KEYS = frozenset(("cache_instance", "geometry_epoch", "line",
                       "allocation_version", "block", "tag", "line_bytes",
                       "actual_allocated_lines", "cache_type"))


def _integer(value, label, positive=False):
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError("invalid " + label)
    return value


def _copy(value):
    if not isinstance(value, Mapping) or set(value) != _COPY_KEYS:
        raise ValueError("complete actual physical copy required")
    for key in _COPY_KEYS:
        _integer(value[key], "copy " + key)
    if (not value["cache_instance"] or not value["geometry_epoch"]
            or not value["line_bytes"]
            or value["line"] >= value["actual_allocated_lines"]
            or value["cache_type"] not in (0, 1)
            or (value["cache_type"] == 1 and value["line_bytes"] % 4)):
        raise ValueError("invalid actual cache allocation")
    return value


def _same(left, right):
    return left is not None and right is not None and all(
        left[name] == right[name] for name in _COPY_KEYS)


def _slot_same(left, right):
    return all(left[name] == right[name] for name in (
        "cache_instance", "geometry_epoch", "line", "line_bytes",
        "actual_allocated_lines", "cache_type"))


def _snapshot(value):
    if not isinstance(value, Mapping) or set(value) != {"copy", "sector_state"}:
        raise ValueError("actual before/after snapshot required")
    copy = _copy(value["copy"])
    states = value["sector_state"]
    if not isinstance(states, (list, tuple)) or len(states) != (1 if copy["cache_type"] == 0 else 4):
        raise ValueError("actual sector coverage required")
    for state in states:
        if (not isinstance(state, Mapping) or set(state) != {"status", "readable"}
                or type(state["status"]) is not int or state["status"] not in (0, 1, 2, 3)
                or type(state["readable"]) is not bool):
            raise ValueError("invalid actual sector state")
    return copy, states


def _inputs(rows, residencies):
    if not isinstance(rows, (list, tuple)) or not isinstance(residencies, Mapping):
        raise ValueError("decoded own rows and physical residencies required")
    spans = residencies.get("residency_spans")
    if not isinstance(spans, (list, tuple)) or not spans:
        raise ValueError("nonempty complete physical spans required")
    prior = -1
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("raw record object required")
        sequence = _integer(row.get("sequence"), "record sequence")
        if sequence <= prior:
            raise ValueError("raw record sequence must be strictly increasing")
        prior = sequence
    for span in spans:
        if span.get("component") not in ("l1d", "l2"):
            raise ValueError("actual cache component required")
        _integer(span.get("scope"), "physical owner")
        start = _integer(span.get("start_cycle"), "span start")
        if _integer(span.get("end_cycle"), "span stop") <= start:
            raise ValueError("empty physical span")
        _snapshot({"copy": span.get("copy"), "sector_state": span.get("sector_state")})
    return spans


def _row_cycle(row):
    return _integer(row.get("global_cycle") if row.get("kind") == "cache_fill"
                    else row.get("cycle"), "actual event cycle")


def _covered(ranges, address):
    if not isinstance(ranges, (list, tuple)):
        raise ValueError("actual transfer ranges required")
    covered = False
    for item in ranges:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError("invalid transfer range")
        first = _integer(item[0], "range start")
        count = _integer(item[1], "range count", positive=True)
        covered = covered or first <= address < first + count
    return covered


def _addressed(row, copy, address):
    mask = row.get("byte_mask")
    if (not isinstance(mask, str) or not mask or len(mask) > 256
            or set(mask) - {"0", "1"}):
        raise ValueError("actual byte mask required")
    block = _integer(row.get("request_block"), "actual request block")
    # Native bitset::to_string puts bit zero at the RIGHT of the string.
    offset = address - block
    return (copy["block"] <= address < copy["block"] + copy["line_bytes"]
            and 0 <= offset < len(mask) and mask[-1-offset] == "1")


def _resolve_writeback(wb, rows, spans):
    """Prove one queued WB's original victim; no dirty/close inference."""
    if wb.get("kind") != "cache_write_request_sent" or wb.get("event_type") != 0:
        raise ValueError("actual WRITE_BACK_REQUEST_SENT required")
    _integer(wb.get("event_type"), "writeback event type")
    component = wb.get("component")
    if component not in ("l1d", "l2"):
        raise ValueError("writeback component required")
    parent = _integer(wb.get("parent_service_request_lifetime"), "WB service parent", True)
    request = _integer(wb.get("request_lifetime"), "WB request", True)
    cycle = _row_cycle(wb)
    if request == parent:
        raise ValueError("writeback must have its own request lifetime")
    matches = []
    competing = 0
    for row in rows:
        if row.get("component") != component or row.get("cycle") != cycle:
            continue
        if (row.get("kind") == "cache_write_request_sent" and row.get("event_type") == 0
                and row.get("parent_service_request_lifetime") == parent):
            competing += 1
        if (row.get("kind") == "cache_disposition" and row.get("operation") == "actual_access"
                and row.get("request_lifetime") == parent):
            matches.append(row)
    if len(matches) != 1 or competing != 1:
        raise ValueError("writeback requires one unique parent disposition and one WB")
    disposition = matches[0]
    if (disposition.get("accepted_status") != 2 or disposition.get("probe_status") != 2
            or type(disposition.get("write")) is not bool
            or disposition["sequence"] <= wb["sequence"]):
        raise ValueError("writeback parent must be a later recorded accepted MISS")
    policy = _integer(disposition.get("write_policy"), "write policy")
    if policy not in (1, 4):  # WRITE_BACK or LOCAL_WB_GLOBAL_WT, not write-through.
        raise ValueError("actual parent policy does not support dirty WB")
    before, states = _snapshot(disposition.get("before"))
    after, _ = _snapshot(disposition.get("after"))
    if (not _slot_same(before, after)
            or after["allocation_version"] <= before["allocation_version"]
            or after["block"] == before["block"]):
        raise ValueError("writeback victim must undergo actual same-slot replacement")
    if _integer(wb.get("request_address"), "actual WB address") != before["block"]:
        raise ValueError("actual WB request address differs from victim")
    if _integer(disposition.get("request_block"), "parent requested block") != after["block"]:
        raise ValueError("actual replacement is not the parent requested block")
    owners = set()
    for span in spans:
        other = span["copy"]
        if other["cache_instance"] == before["cache_instance"]:
            if (span["component"] != component or other["geometry_epoch"] != before["geometry_epoch"]
                    or other["line_bytes"] != before["line_bytes"]
                    or other["cache_type"] != before["cache_type"]
                    or other["actual_allocated_lines"] != before["actual_allocated_lines"]):
                raise ValueError("WB physical owner or geometry is not independently observed")
            owners.add(span["scope"])
    if len(owners) != 1:
        raise ValueError("WB source must have one independently observed physical owner")
    sector_bytes = before["line_bytes"] // len(states)
    transferred = [[before["block"] + index*sector_bytes, sector_bytes]
                   for index, state in enumerate(states) if state["status"] == 3]
    if not transferred:
        raise ValueError("observed WB victim has no MODIFIED sector")
    count = sum(size for _start, size in transferred)
    block = _integer(wb.get("evicted_block"), "legacy evicted block")
    modified = _integer(wb.get("evicted_modified_bytes"), "legacy modified byte count")
    reconstructed = block == 0 and modified == 0 and not disposition["write"]
    if not reconstructed and (block != before["block"] or modified != count):
        raise ValueError("explicit evicted fields disagree with actual victim extent")
    return {
        "writeback_sequence": wb["sequence"], "disposition_sequence": disposition["sequence"],
        "component": component, "scope": next(iter(owners)), "cycle": cycle,
        "request_lifetime": request, "parent_service_request_lifetime": parent,
        "source_copy": dict(before), "transferred_ranges": transferred,
        "transferred_bytes": count,
        "read_miss_default_evicted_fields_reconstructed": reconstructed,
        "accepted_stage": "actual_cache_miss_queue_enqueue",
        "corrupt_value_commit_proven": False,
    }


def _dirty_replacement(disposition):
    """Actual accepted WB-policy dirty replacement, not terminal cleanup."""
    if (disposition.get("kind") != "cache_disposition"
            or disposition.get("operation") != "actual_access"
            or disposition.get("accepted_status") != 2
            or disposition.get("probe_status") != 2
            or disposition.get("write_policy") not in (1, 4)):
        return False
    if disposition.get("before") is None or disposition.get("after") is None:
        return False
    before, states = _snapshot(disposition["before"])
    after, _ = _snapshot(disposition["after"])
    return (any(state["status"] == 3 for state in states)
            and _slot_same(before, after)
            and after["allocation_version"] > before["allocation_version"]
            and after["block"] != before["block"])


def _require_replacement_writeback(disposition, rows, spans):
    parent = _integer(disposition.get("request_lifetime"), "replacement request", True)
    candidates = [row for row in rows if row.get("kind") == "cache_write_request_sent"
                  and row.get("event_type") == 0
                  and row.get("parent_service_request_lifetime") == parent
                  and row.get("component") == disposition.get("component")
                  and row.get("cycle") == disposition.get("cycle")]
    if len(candidates) != 1:
        raise ValueError("actual dirty replacement lacks one unique observed WB")
    return _resolve_writeback(candidates[0], rows, spans)


def capability_report(rows, residencies):
    """Recheck EVERY observed WB, recording failures without certifying source.

    Run on each actual own raw input before a formal campaign.  A fixture PASS
    or zero WB events is not actual producer qualification.  The caller must
    separately bind the original source/image and closed-ledger validation.
    This report is not retained by NaiveCacheEFM and is not a query index.
    """
    spans = _inputs(rows, residencies)
    records, errors = [], []
    for row in rows:
        if row.get("kind") != "cache_write_request_sent":
            continue
        event = _integer(row.get("event_type"), "write request event type")
        if event > 3:
            raise ValueError("unknown actual write request event type")
        if event != 0:
            continue
        try:
            records.append(_resolve_writeback(row, rows, spans))
        except ValueError as error:
            errors.append({"writeback_sequence": row["sequence"], "reason": str(error)})
    replacements = 0
    for row in rows:
        if _dirty_replacement(row):
            replacements += 1
            try:
                _require_replacement_writeback(row, rows, spans)
            except ValueError as error:
                errors.append({"disposition_sequence": row["sequence"], "reason": str(error)})
    headers = [row for row in rows if row.get("kind") == "header"]
    header = headers[0] if len(headers) == 1 else {}
    return {
        "schema": "gerem-method-cache-writeback-capability-v1",
        "status": "REFUSED" if errors else "ASSOCIATIONS_VERIFIED",
        "writebacks_seen": sum(row.get("kind") == "cache_write_request_sent" and row.get("event_type") == 0 for row in rows),
        "matched_writebacks": len(records), "actual_dirty_replacements": replacements,
        "all_observed_writebacks_uniquely_matched": not errors,
        "dirty_writeback_observed": bool(records), "writebacks": records, "errors": errors,
        "source_fingerprint": header.get("source_fingerprint"), "image_id": header.get("image_id"),
        "declared_capture_model": header.get("cache_fault_model"),
        "closed_raw_loader_required": True, "input_integrity_verified_by_this_module": False,
        "actual_producer_certified": False, "full_method_fidelity_certified": False,
        "reconstruction_assumptions": list(RECONSTRUCTION_ASSUMPTIONS),
    }


def _answer(efm, reason=None):
    probability = None if efm is None else 1.0 if efm == "dcr" else 0.0
    return {"efm": efm, "p_sdc": probability, "p_crash": None,
            "independent_due_prediction": False, "unknown_mass": int(efm is None),
            "support_status": "unmapped" if efm is None else "method_rule_with_explicit_reconstruction",
            "outcome": None if efm is None else "SDC" if efm == "dcr" else "Masked",
            "reason": reason, "reconstruction_assumptions": list(RECONSTRUCTION_ASSUMPTIONS)}


def l2_active_lines(owner_views, owner, cycle, copy):
    """Fault-hook geometry, not backing capacity; never guess a missing owner.

    Owner views are the original closed ResidencyBuilder's half-open epochs.
    Copy allocation fields remain their original backing-store identity.
    """
    if not isinstance(owner_views,(list,tuple)):
        return None,'missing_actual_owner_views'
    matches = []
    for row in owner_views:
        if not isinstance(row,Mapping) or not isinstance(row.get('view'),Mapping):
            return None,'malformed_actual_owner_view'
        view = row['view']
        if view.get('component') != 'l2' or view.get('scope') != owner:
            continue
        if (type(view.get('scope')) is not int or view['scope'] < 0
                or row.get('owner_key') != 'l2:'+str(owner)):
            return None,'malformed_actual_owner_identity'
        first,stop = row.get('start_cycle'),row.get('end_cycle')
        if type(first) is not int or type(stop) is not int or first < 0 or stop <= first:
            return None,'malformed_actual_owner_interval'
        if first <= cycle < stop:
            matches.append(view)
    if len(matches) != 1:
        return None,'missing_owner_at_fault_cycle' if not matches else 'ambiguous_owner_at_fault_cycle'
    view = matches[0]
    if (view.get('disabled') is not False or view.get('present') is not True
            or view.get('actual_backing_capacity_known') is not True
            or view.get('active_index_allocation_validated') is not True):
        return None,'unavailable_owner_at_fault_cycle'
    active,capacity = view.get('active_lines'),view.get('actual_allocated_lines')
    if (type(active) is not int or active <= 0 or type(capacity) is not int
            or capacity < active or type(view.get('line_bytes')) is not int
            or type(view.get('cache_type')) is not int):
        return None,'malformed_actual_owner_geometry'
    if (any(view[key] != copy[key] for key in ('actual_allocated_lines','line_bytes','cache_type'))
            or copy['line'] >= active):
        return None,'owner_and_fault_copy_geometry_disagree'
    return active,None


def unsupported_l2_geometry(reason):
    result = _answer(None,reason)
    result['support_status'] = 'unsupported_actual_L2_owner_geometry'
    result['unsupported_geometry_reason'] = reason
    return result


class NaiveCacheEFM:
    """One own component per instance; scan raw events afresh for every trial."""

    def __init__(self, rows, residencies):
        self.rows, self.residencies = rows, residencies
        self.spans = _inputs(rows, residencies)
        self._component = None

    def capability_report(self):
        return capability_report(self.rows, self.residencies)

    def query(self, trial):
        if not isinstance(trial, Mapping) or not isinstance(trial.get("target"), Mapping):
            return _answer(None, "canonical trial and target required")
        component, target = trial.get("component"), trial["target"]
        if component not in ("l1d", "l2"):
            return _answer(None, "unsupported cache component")
        if self._component is not None and self._component != component:
            raise ValueError("one cache component per model; no cross-component sharing")
        self._component = component
        try:
            cycle = _integer(trial.get("cycle"), "fault cycle")
            bit = _integer(trial.get("bit"), "fault bit")
            owner = _integer(target.get("sm" if component == "l1d" else "bank"), "target owner")
            line = _integer(target.get("line"), "target line")
        except ValueError as error:
            return _answer(None, str(error))
        matches = [span for span in self.spans if span["component"] == component
                   and span["scope"] == owner and span["copy"]["line"] == line
                   and span["start_cycle"] <= cycle < span["end_cycle"]]
        if not matches:
            return _answer(None, "fault is outside its actual physical residency")
        if len(matches) != 1:
            raise ValueError("overlapping actual physical fault residencies")
        span = matches[0]; copy = span["copy"]; width = copy["line_bytes"]
        if (target.get("line_size_bytes") != width or type(target.get("line_size_bytes")) is not int
                or target.get("tag_bits") != 57 or type(target.get("tag_bits")) is not int):
            return _answer(None, "exact original physical width and tag57 required")
        first = line * (57 + 8*width)
        if component == "l2":
            lines,error = l2_active_lines(self.residencies.get('owner_views'),owner,cycle,copy)
            if error is not None:
                return unsupported_l2_geometry(error)
            if type(target.get('lines_per_bank')) is not int or target['lines_per_bank'] != lines:
                return unsupported_l2_geometry('target_lines_per_bank_disagrees_with_actual_active_owner')
            first += owner * lines * (57 + 8*width)
        inside = bit - first
        if not 0 <= inside < 57 + 8*width:
            return _answer(None, "flat bit disagrees with actual bank/line")
        is_tag = inside < 57
        if is_tag and not any(state["status"] != 0 for state in span["sector_state"]):
            return _answer("benign", "invalid tag has no valid actual lookup consumer")
        address = copy["block"] + (0 if is_tag else (inside-57)//8)
        if not is_tag:
            states = span["sector_state"]
            sector = states[(address-copy["block"]) // (width//len(states))]
            if sector["status"] not in (2, 3):
                return _answer("benign", "faulted DATA sector is initially invalid or reserved")
        death = max(item["end_cycle"] for item in self.spans
                    if item["component"] == component and item["scope"] == owner
                    and item["copy"]["line"] == line)
        for later in self.spans:
            if (later["component"] != component or later["scope"] != owner
                    or later["copy"]["line"] != line or later["start_cycle"] <= cycle):
                continue
            if not _same(copy, later["copy"]):
                death = min(death, later["start_cycle"])
            else:
                states = later["sector_state"]
                invalid = (not any(state["status"] != 0 for state in states) if is_tag else
                           states[(address-copy["block"]) // (width//len(states))]["status"] == 0)
                if invalid:
                    death = min(death, later["start_cycle"])
        for row in self.rows:
            kind = row.get("kind")
            if kind not in ("cache_access", "cache_disposition", "cache_response",
                            "cache_fill", "cache_write_request_sent"):
                continue
            if row.get("component") != component:
                continue
            when = _row_cycle(row)
            if not cycle < when <= death:
                continue
            if kind == "cache_write_request_sent":
                if row.get("event_type") == 0:
                    evidence = _resolve_writeback(row, self.rows, self.spans)
                    if (not is_tag and _same(copy, evidence["source_copy"])
                            and _covered(evidence["transferred_ranges"], address)):
                        return _answer("dcr", "actual uniquely matched dirty writeback enqueue")
                continue
            if kind == "cache_fill":
                if not is_tag and _same(copy, _copy(row.get("destination"))) and _covered(row.get("ranges"), address):
                    return _answer("benign", "actual fill assigns the faulted byte before a read")
                continue
            if kind == "cache_response":
                if not is_tag and _same(copy, _copy(row.get("source"))) and _covered(row.get("ranges"), address):
                    return _answer("dcr", "actual response consumes the resident byte")
                continue
            if kind == "cache_disposition":
                if row.get("operation") != "actual_access":
                    continue
                if _dirty_replacement(row):
                    _require_replacement_writeback(row, self.rows, self.spans)
                before = row.get("before")
                source = _snapshot(before)[0] if before is not None else None
            else:
                source = _copy(row["before_copy"]) if row.get("before_copy") is not None else None
            if source is None or not _same(copy, source) or row.get("accepted_status") == 3:
                continue
            if is_tag:
                if row.get("probe_status") in (0, 1, 4) and row.get("request_block") == copy["block"]:
                    return _answer("ebc", "valid tag has a future actual matching lookup")
            elif row.get("write") is False and row.get("accepted_status") == 0:
                if _addressed(row, source, address):
                    return _answer("dcr", "actual accepted read before overwrite")
            elif kind == "cache_disposition" and row.get("write") is True:
                if _addressed(row, source, address):
                    return _answer("benign", "actual accepted store overwrites the byte")
        return _answer("benign", "no later actual consumer before assignment or physical-copy death")
