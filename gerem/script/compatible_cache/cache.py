"""FI-compatibility variant: preserve actual WB facts; enqueue alone is not DCR.

All input, coordinate and association helpers are exact v2 function objects.
The query is the v2 body with only the independently-decisive WB return retired.
This explicit compatibility policy is not the original method's WB assumption.
"""
from script.cache_rules import cache as original

Mapping = original.Mapping
_COPY_KEYS = original._COPY_KEYS
_integer,_copy,_same,_slot_same = original._integer,original._copy,original._same,original._slot_same
_snapshot,_inputs,_row_cycle = original._snapshot,original._inputs,original._row_cycle
_covered,_addressed = original._covered,original._addressed
_resolve_writeback,_dirty_replacement = original._resolve_writeback,original._dirty_replacement
_require_replacement_writeback = original._require_replacement_writeback
l2_active_lines = original.l2_active_lines
POLICY = 'actual-WB-facts-retained-enqueue-not-independent-DCR-v3'
RECONSTRUCTION_ASSUMPTIONS = tuple(
    'uniquely_matched_actual_dirty_WB_enqueue_is_fact_not_independent_DCR'
    if item == 'uniquely_matched_actual_dirty_WB_enqueue_is_DCR' else item
    for item in original.RECONSTRUCTION_ASSUMPTIONS)


def _policy(value):
    return dict(value,reconstruction_assumptions=list(RECONSTRUCTION_ASSUMPTIONS))


def _answer(efm,reason=None):
    return _policy(original._answer(efm,reason))


def unsupported_l2_geometry(reason):
    return _policy(original.unsupported_l2_geometry(reason))


def capability_report(rows,residencies):
    return _policy(original.capability_report(rows,residencies))


class NaiveCacheEFM(original.NaiveCacheEFM):
    def capability_report(self):
        return capability_report(self.rows,self.residencies)

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
                        continue  # FI compatibility: verified enqueue alone is not a read.
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
