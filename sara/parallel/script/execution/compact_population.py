"""Analysis-only complete storage populations, independent of FI selectors.

The semantic digest describes the set of target/bit/cycle coordinates. It is
deliberately different from a legacy FI inventory's byte fingerprint. Neither
rates preparation nor its analysis reads another method's inventory or draws.
The immutable shared manifest is checked by coordinate membership only when a
paired/probabilistic method requests it; its IDs and ranks are never rewritten.
"""
from bisect import bisect_right
from collections import defaultdict
from collections.abc import Sequence
from copy import deepcopy
import json
from pathlib import Path

from script.execution.campaign import atomic_json, fingerprint, requested_prefix
from script.execution.fault_manifest import integer, location_identity

SCHEMA = "sara-analysis-population-v2"
DOMAIN_SCHEMA = "sara-semantic-storage-domain-v1"
RF_MODEL = "active-allocated-simulator-rf-smem-single-bit-v1"
SHARED_LIFETIME = ("logical_cta", "shared_object_slot", "page_index", "page_bytes",
                   "shared_storage_uid", "shared_owner_epoch", "shared_allocator_slot")


def _storage_rows(inventory):
    rows = inventory.get("spans")
    if isinstance(rows, SharedByteSpans):
        return rows.pages
    if not isinstance(rows, list) or not rows:
        raise ValueError("complete nonempty storage population required")
    return rows


def _rectangle(row):
    """One physical coordinate rectangle, without collector fragmentation."""
    component = row.get("component")
    if component not in {"rf", "smem", "smem_page", "l1d", "l2"}:
        raise ValueError("unknown population storage component")
    target = dict(row["target"])
    start = integer(row.get("cycle_start"), "cycle_start")
    stop = integer(row.get("cycle_stop"), "cycle_stop", 1)
    if stop <= start:
        raise ValueError("nonempty half-open population lifetime required")
    if component == "smem_page":
        first = 8 * integer(row.get("byte_start"), "byte_start")
        width = 8 * integer(row.get("byte_count"), "byte_count", 1)
        component = "smem"
        location_identity(component, dict(target, byte_addr=first // 8))
    else:
        first = integer(row.get("bit_start", 0), "bit_start")
        width = integer(row.get("bit_count"), "bit_count", 1)
        location_identity(component, target)
        if component == "smem":
            if first != 8 * target["byte_addr"] or width != 8:
                raise ValueError("shared byte and global injector bit coordinates disagree")
            target.pop("byte_addr")
        if component == "rf" and (target["width_bits"] not in {1, 8, 16, 32, 64, 128}
                or first + width > target["width_bits"]):
            raise ValueError("RF population exceeds actual typed storage width")
    return dict(component=component, target=target, cycle_start=start,
                cycle_stop=stop, bit_start=first, bit_count=width)


def _canonical_rectangles(rows):
    # Join adjacent bytes first, then adjacent lifetimes. This makes full-page
    # native records and the old per-byte inventory describe the same domain.
    by_time = defaultdict(list)
    targets, location_contracts = {}, {}
    mass = 0
    for source in rows:
        row = _rectangle(source)
        target = row["target"]
        identity_target = dict(target, byte_addr=0) if row["component"] == "smem" else target
        location = (row["component"], location_identity(row["component"], identity_target))
        if location in location_contracts and location_contracts[location] != target:
            raise ValueError("inconsistent metadata for the same canonical storage location")
        location_contracts[location] = target
        token = (row["component"], fingerprint(row["target"]))
        targets[token] = row["target"]
        by_time[token, row["cycle_start"], row["cycle_stop"]].append(
            (row["bit_start"], row["bit_start"] + row["bit_count"]))
        mass += (row["cycle_stop"] - row["cycle_start"]) * row["bit_count"]
    boundaries = defaultdict(lambda: defaultdict(list))
    for (token, start, stop), intervals in by_time.items():
        merged = []
        for first, last in sorted(intervals):
            if merged and first < merged[-1][1]:
                raise ValueError("duplicate/overlapping population bits")
            if merged and first == merged[-1][1]:
                merged[-1] = (merged[-1][0], last)
            else:
                merged.append((first, last))
        for first, last in merged:
            boundaries[token][start].append((first, last, 1))
            boundaries[token][stop].append((first, last, -1))
    result = []
    for token, changes in sorted(boundaries.items()):
        cycles = sorted(changes)
        active, previous, open_rows = {}, None, []
        for index, cycle in enumerate(cycles):
            deltas = defaultdict(int)
            for first, last, delta in changes[cycle]:
                deltas[first, last] += delta
            for key, delta in deltas.items():
                active[key] = active.get(key, 0) + delta
                if active[key] == 0:
                    del active[key]
                elif active[key] != 1:
                    raise ValueError("duplicate/overlapping population lifetimes")
            windows = []
            for first, last in sorted(active):
                if windows and first < windows[-1][1]:
                    raise ValueError("overlapping canonical population rectangles")
                if windows and first == windows[-1][1]:
                    windows[-1] = (windows[-1][0], last)
                else:
                    windows.append((first, last))
            if index == len(cycles) - 1:
                if active:
                    raise ValueError("unclosed population rectangles")
                break
            stop = cycles[index + 1]
            if windows == previous:
                for row in open_rows:
                    row["cycle_stop"] = stop
            else:
                open_rows = [dict(component=token[0], target=targets[token],
                    cycle_start=cycle, cycle_stop=stop, bit_start=first, bit_count=last-first)
                    for first, last in windows]
                result.extend(open_rows)
            previous = windows
    if mass != sum((r["cycle_stop"]-r["cycle_start"])*r["bit_count"] for r in result):
        raise ValueError("semantic compaction changed population bit-cycle mass")
    return result, mass


class SemanticPopulation:
    """Exact complete coordinate domain; no FI selector, sampler or ACK index."""
    def __init__(self, inventory):
        self.inventory = inventory
        for key in ("fault_model", "coordinate_system", "time_basis"):
            if not isinstance(inventory.get(key), str) or not inventory[key]:
                raise ValueError("population requires " + key)
        if inventory["time_basis"] != "simulator_global_cycle":
            raise ValueError("actual global cycle coordinates required")
        rectangles, self.mass = _canonical_rectangles(_storage_rows(inventory))
        if not rectangles or not self.mass:
            raise ValueError("empty population cannot define an analysis")
        self.component = rectangles[0]["component"]
        if any(row["component"] != self.component for row in rectangles):
            raise ValueError("one complete component required per method condition")
        self.window = dict(first_cycle=min(r["cycle_start"] for r in rectangles),
                           cycle_stop=max(r["cycle_stop"] for r in rectangles))
        self.document = dict(schema=DOMAIN_SCHEMA,
            **{key: inventory[key] for key in ("fault_model", "coordinate_system", "time_basis")},
            bit_cycles=self.mass, spans=rectangles)
        self.identity = fingerprint(self.document)
        self.spans = core_inventory(inventory)["spans"]
        # No index is constructed by rates. Pairing builds its own tiny
        # coordinate membership lookup after the shared core has been frozen.
        self._membership = None

    def contains(self, trial):
        component = trial.get("component")
        target = dict(trial.get("target", {}))
        if component != self.component:
            return False
        location_identity(component, target)
        cycle = integer(trial.get("cycle"), "trial.cycle")
        bit = integer(trial.get("bit"), "trial.bit")
        if component == "smem":
            if bit // 8 != target.pop("byte_addr"):
                return False
        if self._membership is None:
            groups = defaultdict(lambda: defaultdict(list))
            for row in self.document["spans"]:
                groups[fingerprint(row["target"])][row["bit_start"], row["bit_count"]].append(
                    (row["cycle_start"], row["cycle_stop"]))
            self._membership = {key: {bits: (tuple(a for a, b in sorted(values)), tuple(sorted(values)))
                for bits, values in windows.items()} for key, windows in groups.items()}
        for (first, width), (starts, intervals) in self._membership.get(fingerprint(target), {}).items():
            if first <= bit < first + width:
                index = bisect_right(starts, cycle) - 1
                if index >= 0 and cycle < intervals[index][1]:
                    return True
        return False

    def validate_manifest(self, manifest, target_count=1000, seed=2026, *, dispatch_limit=1000):
        if (not isinstance(manifest, dict) or manifest.get("sampling") != "with_replacement"
                or manifest.get("seed") != seed or manifest.get("population_size") != self.mass):
            raise ValueError("shared manifest seed/sampling/full population mass disagrees")
        contract = manifest.get("population_contract", {})
        if any(contract.get(key) != self.inventory[key] for key in ("fault_model", "coordinate_system", "time_basis")):
            raise ValueError("shared manifest uses another storage fault model")
        count = requested_prefix(manifest["trials"], target_count, dispatch_limit=dispatch_limit)
        master_fingerprint = manifest.get("population_fingerprint")
        if not isinstance(master_fingerprint, str) or not master_fingerprint:
            raise ValueError("explicit immutable legacy master identity required")
        parent_range = manifest.get('parent_draw_range')
        first_draw = 0
        if parent_range is not None:
            if (not isinstance(parent_range, list) or len(parent_range) != 2
                    or any(type(v) is not int for v in parent_range)
                    or parent_range[0] < 0
                    or parent_range[1] - parent_range[0] != len(manifest['trials'])):
                raise ValueError('invalid explicit immutable parent draw range')
            first_draw = parent_range[0]
        identifiers = set()
        # The master is generated/frozen by common study preparation. Each own
        # method loads/binds the complete immutable file, but maps/checks only
        # the requested draws; unused future prefixes are not method queries.
        for draw, trial in enumerate(manifest["trials"][:count]):
            trial_id = trial.get("trial_id")
            if (not isinstance(trial_id, str) or not trial_id
                    or trial.get("draw_index") != first_draw + draw or trial_id in identifiers
                    or trial.get("population_fingerprint") != manifest.get("population_fingerprint")):
                raise ValueError("immutable shared draw identity disagreement")
            identifiers.add(trial["trial_id"])
            site = {key: trial[key] for key in ("population_fingerprint", "component", "target", "cycle", "bit")}
            if fingerprint(site) != trial.get("site_id"):
                raise ValueError("shared site ID does not match its unchanged coordinates")
            # Preserve rank byte-for-byte; it belongs to the old full inventory
            # ordering, not this independently acquired semantic representation.
            if not 0 <= integer(trial.get("population_rank"), "population_rank") < self.mass:
                raise ValueError("shared draw rank out of its original full population")
            if not self.contains(trial):
                raise ValueError("shared draw is absent from own complete population")
        return manifest["trials"][:count]


class SharedByteSpans(Sequence):
    """Core's existing byte projection over compact pages, with O(pages) RAM."""
    def __init__(self, pages):
        self.pages = pages
        self.ends = []
        count = 0
        for row in pages:
            count += row["byte_count"]
            self.ends.append(count)

    def __len__(self):
        return self.ends[-1] if self.ends else 0

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self))) ]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        page = bisect_right(self.ends, index)
        row = self.pages[page]
        address = row["byte_start"] + index - (self.ends[page-1] if page else 0)
        return dict(component="smem", target=dict(row["target"], byte_addr=address),
            lifecycle=row["lifecycle"], cycle_start=row["cycle_start"], cycle_stop=row["cycle_stop"],
            bit_start=8*address, bit_count=8)


def core_inventory(inventory):
    if isinstance(inventory.get("spans"), SharedByteSpans):
        return inventory
    rows = _storage_rows(inventory)
    if rows[0]["component"] == "smem_page":
        return dict(inventory, spans=SharedByteSpans(rows))
    return inventory


def semantic_population(inventory):
    return SemanticPopulation(inventory)


def to_compact_inventory(inventory):
    """Strip executor-only fields; retain every coordinate and mapping fact."""
    rows = []
    for row in _storage_rows(inventory):
        compact = {key: deepcopy(row[key]) for key in ("component", "target", "cycle_start", "cycle_stop")}
        for key in ("bit_start", "bit_count", "byte_start", "byte_count", "mapping_supported"):
            if key in row:
                compact[key] = row[key]
        if "lifecycle" in row:
            names = SHARED_LIFETIME if row["component"] in {"smem", "smem_page"} else ("logical_cta", "frame_index", "frame_count")
            compact["lifecycle"] = {key: row["lifecycle"][key] for key in names}
        rows.append(compact)
    result = {key: deepcopy(value) for key, value in inventory.items()
              if key not in {"spans", "schema_version", "schema", "population_fingerprint", "population_id"}}
    result.update(schema=SCHEMA, schema_version=2, spans=rows)
    return result


def read_inventory(path):
    from script.execution.method_input_context import read_json
    value = read_json(path)
    if value.get("schema") == SCHEMA:
        if value.get("schema_version") != 2:
            raise ValueError("unsupported compact analysis inventory")
        if any("hook_selectors" in row or "ack_expected" in row for row in _storage_rows(value)):
            raise ValueError("analysis inventory must not contain FI execution metadata")
        population = semantic_population(value)
        return core_inventory(value), population
    # Read-only legacy compatibility for public evidence/neutral comparison.
    # New rates producers use compact-v2 and never need FI selector validation.
    from script.execution.fault_manifest import FaultPopulation
    return value, FaultPopulation(value)


def read_own_population(capture, component):
    from script.execution.population_inventory import (read_stream, validate_lifecycle,
        validate_production_blockers, COMPACT_SCHEMA)
    capture = Path(capture)
    metadata = json.loads((capture / "capture.json").read_text())
    if component not in {"rf", "smem"}:
        raise ValueError("cache population must come from its own actual cache ledger")
    if metadata.get("collection") not in {"sara", "gerem-rf", "gerem-smem"}:
        raise ValueError("analysis population must belong to this method's clean acquisition")
    if metadata.get("minimal_population") is not True or metadata.get("component") != component:
        raise ValueError("own component-specific minimal acquisition required")
    path = capture / "population.jsonl.gz"
    if not path.is_file():
        path = capture / "population.jsonl"
    stream = read_stream(path, decode_budgets=metadata.get("population_transport", {}).get("decode_budgets"))
    if stream["header"].get("schema") != COMPACT_SCHEMA:
        raise ValueError("new method acquisition requires compact native population protocol")
    if stream["header"].get("component_filter") != component:
        raise ValueError("native complete component filter differs from requested method")
    validate_production_blockers(stream["blockers"])
    rows = []
    wanted = "rf" if component == "rf" else "smem_page"
    for row in stream["spans"]:
        validate_lifecycle(row, stream["header"])
        if row["component"] != wanted:
            continue
        if row["mapping_supported"] is not True:
            raise ValueError("unresolved mapping cannot be removed from population mass")
        rows.append({key: value for key, value in row.items() if key != "kind"})
    inventory = dict(schema=SCHEMA, schema_version=2, fault_model=RF_MODEL,
        coordinate_system="simulator_hook_allocated_storage", time_basis="simulator_global_cycle",
        collection_header=stream["header"], collection_window=stream["footer"],
        population_transport=stream["transport"], spans=rows)
    population = semantic_population(inventory)
    if population.mass != stream["mass"][component]:
        raise ValueError("own compact population changed the complete emitter mass")
    return inventory, population


def _write_descriptor(capture, component, inventory, *, with_trace):
    from script.execution.method_input_context import file_digest as digest
    from script.execution.method_input_context import current_context
    capture = Path(capture)
    metadata = json.loads((capture / "capture.json").read_text())
    population = semantic_population(inventory)
    inventory_name = "inventory-" + component + ".json"
    destination = capture / inventory_name
    if destination.exists():
        if json.loads(destination.read_text()) != inventory:
            raise ValueError("refuse to replace frozen own population")
    else:
        atomic_json(destination, inventory)
    roles = {"inventory": inventory_name, "output_spec": "output-spec.json"}
    if with_trace:
        roles["trace"] = "trace.json.gz"
    if component in {"l1d", "l2"}:
        roles["cache_ledger"] = "memory.jsonl"
        if with_trace:
            roles["trace_sidecar"] = "trace.json.gz.completeness.json"
    context = current_context(capture)
    if context is not None:
        # Native production capture declares a 2-GiB ledger; transport readers
        # independently retain their original trace/sidecar bounds. Avoid an
        # eager descriptor hash loading an oversized file before those checks.
        from script.execution.trace_transport import PHYSICAL_BYTES
        for role, maximum in (('trace', PHYSICAL_BYTES), ('cache_ledger', 2147483648),
                              ('trace_sidecar', 16 * 1024**2)):
            if role in roles:
                context.check_size(capture / roles[role], maximum)
    descriptor = dict(schema="sara-batch-inputs-v2" if with_trace else "sara-population-inputs-v2",
        case=metadata["case"], arguments=metadata["arguments"], binary_sha256=metadata["actual_binary_sha256"],
        simulator_libraries=metadata["simulator_libraries"], population_mass=population.mass,
        population_fingerprint=population.identity, population_identity_kind=DOMAIN_SCHEMA,
        files={role: {"path": name, "sha256": digest(capture / name)} for role, name in roles.items()})
    target = capture / ("inputs-" + component + ".json")
    if target.exists():
        if json.loads(target.read_text()) != descriptor:
            raise ValueError("refuse to replace frozen own method descriptor")
    else:
        atomic_json(target, descriptor)
    return dict(input_path=str(target), population_mass=population.mass,
        semantic_population_fingerprint=population.identity, compact_spans=len(_storage_rows(inventory)),
        whole_population_retained=True, manifest_draws=0)


def prepare_compact_capture(capture, component, *, with_trace=True):
    inventory, _ = read_own_population(capture, component)
    return _write_descriptor(capture, component, inventory, with_trace=with_trace)


def prepare_compact_cache_capture(capture, component, inventory, *, with_trace=True):
    if component not in {"l1d", "l2"}:
        raise ValueError("one actual cache component required")
    return _write_descriptor(capture, component, to_compact_inventory(inventory), with_trace=with_trace)
