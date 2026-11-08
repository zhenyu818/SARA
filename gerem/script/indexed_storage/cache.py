"""Original v2 indexes and ordered query; only standalone WB-DCR is retired."""
from copy import deepcopy
from script.physical_index import cache as original
from script.compatible_cache import cache as method

Mapping = method.Mapping
_integer,_answer,_same = method._integer,method._answer,method._same
_copy,_snapshot,_covered = method._copy,method._snapshot,method._covered
_row_cycle,_addressed,_dirty_replacement = method._row_cycle,method._addressed,method._dirty_replacement
copy_key,_Associations = original.copy_key,original._Associations
POLICY = 'v2-active-L2-index-with-FI-compatible-WB-consumer-policy-v3'


def capability_report(rows,residencies,*,associations=None):
    return method._policy(original.capability_report(rows,residencies,associations=associations))


class PreparedCacheIndex(original.PreparedCacheIndex):
    def __init__(self,rows,residencies):
        super().__init__(rows,residencies)
        self.report = method._policy(self.report)


class IndexedCacheEFM(method.NaiveCacheEFM):
    def __init__(self,rows,residencies,*,index=None):
        self._index = index if index is not None else PreparedCacheIndex(rows,residencies)
        if self._index.rows is not rows or self._index.residencies is not residencies:
            raise ValueError('prepared physical index does not own these exact verified facts')
        self.rows,self.residencies,self.spans = rows,residencies,self._index.spans
        self._component = None; self._queries = 0

    def capability_report(self):
        return deepcopy(self._index.report)

    def statistics(self):
        return dict(self._index.statistics(),queries=self._queries,complete_fault_answers_cached=False,
                    dirty_writeback_facts_unchanged=True,standalone_writeback_is_DCR=False)

    def query(self, trial):
        self._queries += 1
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
        slot_spans = self._index.spans_by.get((component,owner,line),())
        matches = [span for span in slot_spans if span["component"] == component
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
            lines,error = method.l2_active_lines(self._index.owner_views_for(component,owner),owner,cycle,copy)
            if error is not None:
                return method.unsupported_l2_geometry(error)
            if type(target.get('lines_per_bank')) is not int or target['lines_per_bank'] != lines:
                return method.unsupported_l2_geometry('target_lines_per_bank_disagrees_with_actual_active_owner')
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
        death = max(item["end_cycle"] for item in slot_spans
                    if item["component"] == component and item["scope"] == owner
                    and item["copy"]["line"] == line)
        for later in slot_spans:
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
        for row in self._index.events(component,copy,cycle,death):
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
                    evidence = self._index.writebacks[row["sequence"]]
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
                    self._index.require_replacement(row)
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
