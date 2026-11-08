"""Complete physical indexes; the method_v1 accepted-WB query rules retained."""
from bisect import bisect_left,bisect_right
from collections import defaultdict
from copy import deepcopy
from script.cache_rules import cache as method

Mapping = method.Mapping
_integer,_answer,_same = method._integer,method._answer,method._same
_copy,_snapshot,_covered = method._copy,method._snapshot,method._covered
_row_cycle,_addressed,_dirty_replacement = method._row_cycle,method._addressed,method._dirty_replacement
POLICY = 'method-v2-active-L2-owner-accepted-WB-physical-copy-index-v1'


def copy_key(value):
    return tuple(value[key] for key in sorted(method._COPY_KEYS))


class _Associations:
    def __init__(self,rows,spans):
        self.rows,self.spans = rows,spans
        self.buckets = defaultdict(list); self.instances = defaultdict(list); self.resolved = {}
        self.resolutions = self.reuses = 0
        for span in spans: self.instances[span['copy']['cache_instance']].append(span)
        self.safe = True
        for row in rows:
            if row.get('kind') == 'cache_write_request_sent' and row.get('event_type') == 0:
                parent = row.get('parent_service_request_lifetime')
            elif row.get('kind') == 'cache_disposition' and row.get('operation') == 'actual_access':
                parent = row.get('request_lifetime')
            else: continue
            key = (row.get('component'),row.get('cycle'),parent)
            try: self.buckets[key].append(row)
            except TypeError: self.safe = False

    def bucket(self,row,parent):
        if not self.safe: return self.rows
        try: return self.buckets.get((row.get('component'),row.get('cycle'),parent),())
        except TypeError: return self.rows

    def resolve(self,wb):
        sequence = wb['sequence']
        if sequence in self.resolved:
            self.reuses += 1; return self.resolved[sequence]
        rows = self.bucket(wb,wb.get('parent_service_request_lifetime')); spans = self.spans
        matches = [row for row in rows if row.get('kind') == 'cache_disposition'
            and row.get('operation') == 'actual_access' and row.get('component') == wb.get('component')
            and row.get('cycle') == wb.get('cycle') and row.get('request_lifetime') == wb.get('parent_service_request_lifetime')]
        if len(matches)==1:
            before = matches[0].get('before')
            if isinstance(before,Mapping) and isinstance(before.get('copy'),Mapping):
                instance = before['copy'].get('cache_instance')
                if type(instance) is int: spans = self.instances.get(instance,())
        value = method._resolve_writeback(wb,rows,spans)
        self.resolutions += 1; self.resolved[sequence] = value
        return value

    def require(self,disposition):
        parent = _integer(disposition.get('request_lifetime'),'replacement request',True)
        rows = self.bucket(disposition,parent)
        candidates = [row for row in rows if row.get('kind') == 'cache_write_request_sent'
            and row.get('event_type') == 0 and row.get('parent_service_request_lifetime') == parent
            and row.get('component') == disposition.get('component') and row.get('cycle') == disposition.get('cycle')]
        if len(candidates)!=1: raise ValueError('actual dirty replacement lacks one unique observed WB')
        return self.resolve(candidates[0])


def capability_report(rows,residencies,*,associations=None):
    spans = method._inputs(rows,residencies) if associations is None else associations.spans
    associations = associations if associations is not None else _Associations(rows,spans)
    records,errors = [],[]; replacements = 0; observed = 0
    for row in rows:
        if row.get('kind') != 'cache_write_request_sent': continue
        event = _integer(row.get('event_type'),'write request event type')
        if event>3: raise ValueError('unknown actual write request event type')
        if event!=0: continue
        observed += 1
        try: records.append(associations.resolve(row))
        except ValueError as error: errors.append(dict(writeback_sequence=row['sequence'],reason=str(error)))
    for row in rows:
        if method._dirty_replacement(row):
            replacements += 1
            try: associations.require(row)
            except ValueError as error: errors.append(dict(disposition_sequence=row['sequence'],reason=str(error)))
    headers = [row for row in rows if row.get('kind')=='header']; header = headers[0] if len(headers)==1 else {}
    return dict(schema='gerem-method-cache-writeback-capability-v1',status='REFUSED' if errors else 'ASSOCIATIONS_VERIFIED',
        writebacks_seen=observed,matched_writebacks=len(records),actual_dirty_replacements=replacements,
        all_observed_writebacks_uniquely_matched=not errors,dirty_writeback_observed=bool(records),writebacks=records,errors=errors,
        source_fingerprint=header.get('source_fingerprint'),image_id=header.get('image_id'),declared_capture_model=header.get('cache_fault_model'),
        closed_raw_loader_required=True,input_integrity_verified_by_this_module=False,actual_producer_certified=False,
        full_method_fidelity_certified=False,reconstruction_assumptions=list(method.RECONSTRUCTION_ASSUMPTIONS))


class PreparedCacheIndex:
    def __init__(self,rows,residencies):
        self.rows,self.residencies = rows,residencies
        self.spans = method._inputs(rows,residencies)
        self.owner_views = residencies.get('owner_views')
        self.owner_views_by = defaultdict(list)
        self.owner_index_safe = isinstance(self.owner_views,(list,tuple))
        if self.owner_index_safe:
            for row in self.owner_views:
                view = row.get('view') if isinstance(row,Mapping) else None
                if (not isinstance(view,Mapping) or view.get('component') not in ('l1d','l2')
                        or type(view.get('scope')) is not int or view['scope'] < 0):
                    self.owner_index_safe = False
                    break
                self.owner_views_by[view['component'],view['scope']].append(row)
        self.associations = _Associations(rows,self.spans)
        self.report = capability_report(rows,residencies,associations=self.associations)
        if self.report['status'] != 'ASSOCIATIONS_VERIFIED':
            raise ValueError('actual dirty-writeback associations refused: '+str(self.report['errors']))
        self.writebacks = {item['writeback_sequence']:item for item in self.report['writebacks']}
        self.replacements = {item['disposition_sequence']:item for item in self.report['writebacks']}
        self.spans_by = defaultdict(list); grouped = defaultdict(list)
        for span in self.spans:
            self.spans_by[span['component'],span['scope'],span['copy']['line']].append(span)
        for row in rows:
            kind = row.get('kind'); source = None
            if kind == 'cache_write_request_sent':
                if row.get('event_type') != 0: continue
                source = self.writebacks[row['sequence']]['source_copy']
            elif kind == 'cache_response': source = _copy(row.get('source'))
            elif kind == 'cache_fill': source = _copy(row.get('destination'))
            elif kind == 'cache_disposition':
                if row.get('operation') != 'actual_access': continue
                before = row.get('before'); source = _snapshot(before)[0] if before is not None else None
            elif kind == 'cache_access':
                source = _copy(row['before_copy']) if row.get('before_copy') is not None else None
            else: continue
            if source is not None:
                grouped[row.get('component'),copy_key(source)].append((_row_cycle(row),row['sequence'],row))
        self.event_tables = {}
        for key,items in grouped.items():
            items.sort(key=lambda item:(item[0],item[1]))
            self.event_tables[key] = ([item[0] for item in items],items)

    def events(self,component,copy,cycle,death):
        times,items = self.event_tables.get((component,copy_key(copy)),((),()))
        selected = items[bisect_right(times,cycle):bisect_right(times,death)]
        # The original scientific query visits native record sequence, which is
        # not assumed equal to timing-cycle order across all record families.
        return [item[2] for item in sorted(selected,key=lambda item:item[1])]

    def require_replacement(self,row):
        if row['sequence'] not in self.replacements:
            raise ValueError('actual dirty replacement lacks its unique verified writeback')
        return self.replacements[row['sequence']]

    def owner_views_for(self,component,scope):
        return self.owner_views_by.get((component,scope),()) if self.owner_index_safe else self.owner_views

    def statistics(self):
        return dict(raw_records=len(self.rows),residency_spans=len(self.spans),
            physical_slot_keys=len(self.spans_by),physical_copy_event_keys=len(self.event_tables),
            verified_writeback_associations=len(self.writebacks),
            association_bucket_keys=len(self.associations.buckets),association_resolutions=self.associations.resolutions,
            association_resolution_reuses=self.associations.reuses,
            owner_geometry_keys=len(self.owner_views_by),owner_geometry_index_safe=self.owner_index_safe,
            size_semantics='entry counts, not heap bytes or reset memory peaks')


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
        return dict(self._index.statistics(),queries=self._queries,
                    complete_fault_answers_cached=False,dirty_writeback_semantics_unchanged=True)

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
