"""A separate, current-VALID/MODIFIED cache bit-cycle population.

This is an operational occupancy subset of the original physical population,
not an output-sensitive or future-consumer population.  No FI result, numeric
operand, GEREM probability, SARA mask or query outcome defines membership.
All coordinates retain the native tag-first 57+DATA layout.  Original cache
inventories and manifests are never modified by these functions.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from script.execution.cache_inventory_core import _inventory, _owner_at, topology_from_config
from script.execution.cache_physical_episodes import identity, sector_states
from script.execution.campaign import fingerprint
from script.execution.fault_manifest import FaultPopulation, location_identity


POPULATION_ID = "current-valid-resident-cache-v1"
# The physical realization is unchanged.  Selection identity belongs to the
# new population and its explicit contract, not to a fabricated new injector.
FAULT_MODEL = "all-active-physical-cache-tag57-and-data-invalid-pending-single-bit-v2"
CONTRACT_SCHEMA = "sara-cache-valid-resident-site-v1"
VALID_STATUSES = frozenset((2, 3))  # native INVALID=0, RESERVED=1, VALID=2, MODIFIED=3
PHASE = "after_all_core_instruction_events_at_cycle"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_UINT64 = (1 << 64) - 1
_UINT32 = (1 << 32) - 1


def _uint(value, name, positive=False, maximum=_UINT64):
    if type(value) is not int or value < int(positive) or value > maximum:
        raise ValueError("invalid valid-resident integer: " + name)
    return value


def _rows(residencies):
    if (not isinstance(residencies, dict)
            or residencies.get("schema") != "sara-neutral-physical-cache-residencies-v1"
            or residencies.get("phase") != PHASE):
        raise ValueError("closed actual post-core physical residencies required")
    rows = residencies.get("residency_spans")
    if not isinstance(rows, list):
        raise ValueError("actual residency spans required")
    for row in rows:
        copy = identity(row.get("copy"))
        states = sector_states(row, copy)
        start = _uint(row.get("start_cycle"), "start_cycle")
        stop = _uint(row.get("end_cycle"), "end_cycle", positive=True)
        if stop <= start or row.get("component") not in {"l1d", "l2"}:
            raise ValueError("nonempty actual cache residency required")
        _uint(row.get("scope"), "scope", maximum=_UINT32)
        if row.get("owner_key") != row["component"] + ":" + str(row["scope"]):
            raise ValueError("actual cache owner identity differs")
        yield row, copy, states


def _windows(copy, states, kind):
    """Disjoint local bit windows; TAG occurs once, never once per sector."""
    valid = [index for index, state in enumerate(states) if state["status"] in VALID_STATUSES]
    if kind in (None, "tag") and valid:
        yield 0, 57
    if kind in (None, "data"):
        sector_bits = copy["line_bytes"] * 8 // len(states)
        for index in valid:
            yield 57 + index * sector_bits, sector_bits


def build_valid_resident_inventory(residencies, topology, *, component, kind=None):
    """Return a new inventory; an empty ``spans`` means this group is N/A.

    ``kind=None`` is the DATA+TAG population used by the new cache cohorts.
    Optional DATA/TAG-only populations support explicit, separately reported
    checks.  Sampling uses FaultPopulation unchanged and weights bit-cycles,
    rather than choosing cycles/lines/sectors with equal probability.
    """
    if component not in {"l1d", "l2"} or kind not in (None, "data", "tag"):
        raise ValueError("explicit cache component and optional data/tag kind required")
    # Validate the complete original owner/geometry/mass domain first.  This
    # does not use future-consumer authority or any classification adapter.
    original, _ = _inventory(residencies, topology)
    from script.execution.compact_population import semantic_population
    component_original = dict(original, fault_model=FAULT_MODEL,
        spans=[row for row in original["spans"] if row["component"] == component])
    component_population = semantic_population(component_original) if component_original["spans"] else None
    originals = {(row["component"], row["target"].get("sm", row["target"].get("bank")),
                  row["target"]["line"], row["cycle_start"], row["cycle_stop"]): row
                 for row in original["spans"]}
    spans = []
    for row, copy, states in _rows(residencies):
        if row["component"] != component:
            continue
        owner = _owner_at(residencies, row["owner_key"], row["start_cycle"])
        if (owner.get("disabled") or copy["line"] >= owner["active_lines"]
                or any(copy[name] != owner[name] for name in
                       ("actual_allocated_lines", "line_bytes", "cache_type"))
                or (any(state["status"] in VALID_STATUSES for state in states)
                    and not copy["allocation_version"])):
            raise ValueError("valid-resident span differs from actual allocated owner")
        base = originals[(component, row["scope"], copy["line"], row["start_cycle"], row["end_cycle"])]
        for first, count in _windows(copy, states, kind):
            selected = deepcopy(base)
            selected["bit_start"] = base["bit_start"] + first
            selected["bit_count"] = count
            spans.append(selected)
    result = dict(original, population_id=POPULATION_ID + ("-" + kind if kind else ""),
                  fault_model=FAULT_MODEL, spans=spans)
    result.update(selection=dict(schema="sara-cache-current-valid-selection-v1", phase=PHASE,
        data_sector_statuses=[2, 3], tag_line_rule="any_sector_status_2_or_3_once_per_line",
        readable_filter=False, future_consumer_filter=False, outcome_filter=False,
        kind=kind or "data+tag",
        original_population_fingerprint=component_population.identity if component_population else None,
        original_component_population_mass=component_population.mass if component_population else 0,
        original_combined_inventory_fingerprint=fingerprint(original)))
    if spans:
        FaultPopulation(result)  # reject duplicate rectangles, invalid selectors and geometry
    return result


def selected_site_contract(residencies, trial, *, _index=None):
    """Bind one selected coordinate to the exact clean pre-flip physical state.

    The flat JSON is deliberately small enough for a strict bounded native
    reader.  Readability is witnessed but is NOT a membership filter.  The
    caller must preserve the contract file as a trial execution input and pass
    ``-fi_valid_resident_contract <that-file>`` only for this new cohort.
    """
    component = trial.get("component")
    if component not in {"l1d", "l2"}:
        raise ValueError("valid-resident contract requires a cache point")
    target = trial["target"]
    location_identity(component, target)
    cycle = _uint(trial.get("cycle"), "cycle", maximum=_UINT32)
    bit = _uint(trial.get("bit"), "bit", maximum=_UINT32 - 1)
    population = trial.get("population_fingerprint")
    if not isinstance(population, str) or _HEX64.fullmatch(population) is None:
        raise ValueError("selected population fingerprint required")
    scope = target["sm"] if component == "l1d" else target["bank"]
    candidates = _rows(residencies) if _index is None else _index.get((component, scope, target["line"]), ())
    matches = [(row, copy, states) for row, copy, states in candidates
               if row["component"] == component and row["scope"] == scope
               and copy["line"] == target["line"]
               and row["start_cycle"] <= cycle < row["end_cycle"]]
    if len(matches) != 1:
        raise ValueError("selected site lacks one actual physical residency")
    row, copy, states = matches[0]
    owner = _owner_at(residencies, row["owner_key"], cycle)
    if (owner.get("disabled") or copy["line_bytes"] != target["line_size_bytes"]
            or copy["line"] >= owner["active_lines"]
            or any(copy[name] != owner[name] for name in
                   ("actual_allocated_lines", "line_bytes", "cache_type"))):
        raise ValueError("selected site differs from actual active cache geometry")
    slots = copy["line"] if component == "l1d" else scope * owner["active_lines"] + copy["line"]
    if component == "l2" and target["lines_per_bank"] != owner["active_lines"]:
        raise ValueError("selected L2 flattened bank geometry differs")
    inside = bit - slots * (57 + copy["line_bytes"] * 8)
    if not 0 <= inside < 57 + copy["line_bytes"] * 8:
        raise ValueError("selected bit does not name the declared physical line")
    if inside < 57:
        kind = "tag"
        valid = any(state["status"] in VALID_STATUSES for state in states)
    else:
        kind = "data"
        sector = (inside - 57) // (copy["line_bytes"] * 8 // len(states))
        valid = states[sector]["status"] in VALID_STATUSES
    if not valid or not copy["allocation_version"]:
        raise ValueError("selected cache point is not currently VALID/MODIFIED")
    result = dict(schema=CONTRACT_SCHEMA, population_fingerprint=population,
        component=component, kind=kind, cycle=cycle, bit=bit + 1, scope=scope,
        cluster=target.get("cluster", 0), core=target.get("core", 0), line=copy["line"],
        active_lines=owner["active_lines"], tag_bits=57,
        sector_status=[state["status"] for state in states],
        sector_readable=[int(state["readable"]) for state in states], **{
            name: copy[name] for name in ("cache_instance", "geometry_epoch", "allocation_version",
                "block", "tag", "line_bytes", "actual_allocated_lines", "cache_type")})
    result["contract_id"] = fingerprint(result)
    validate_site_contract(result)
    return result


def validate_site_contract(contract):
    """Validate a saved contract without consulting prediction/FI outcomes."""
    names = {"schema", "population_fingerprint", "contract_id", "component", "kind", "cycle", "bit",
        "scope", "cluster", "core", "line", "active_lines", "tag_bits", "cache_instance",
        "geometry_epoch", "allocation_version", "block", "tag", "line_bytes",
        "actual_allocated_lines", "cache_type", "sector_status", "sector_readable"}
    if not isinstance(contract, dict) or set(contract) != names or contract["schema"] != CONTRACT_SCHEMA:
        raise ValueError("invalid valid-resident contract schema")
    for name in ("population_fingerprint", "contract_id"):
        if not isinstance(contract[name], str) or _HEX64.fullmatch(contract[name]) is None:
            raise ValueError("invalid valid-resident digest")
    if fingerprint({key: value for key, value in contract.items() if key != "contract_id"}) != contract["contract_id"]:
        raise ValueError("valid-resident contract digest differs")
    for name in names - {"schema", "population_fingerprint", "contract_id", "component", "kind",
                          "sector_status", "sector_readable"}:
        _uint(contract[name], name)
    if contract["component"] not in {"l1d", "l2"} or contract["kind"] not in {"data", "tag"}:
        raise ValueError("invalid valid-resident component/kind")
    for name in ("active_lines", "line_bytes", "actual_allocated_lines", "cache_instance",
                 "geometry_epoch", "allocation_version", "bit"):
        _uint(contract[name], name, positive=True)
    for name in ("cycle", "bit", "scope", "cluster", "core", "line", "active_lines"):
        _uint(contract[name], name, maximum=_UINT32)
    count = 1 if contract["cache_type"] == 0 else 4 if contract["cache_type"] == 1 else 0
    statuses, readable = contract["sector_status"], contract["sector_readable"]
    if (not count or contract["line_bytes"] % count or contract["tag_bits"] != 57
            or contract["active_lines"] > contract["actual_allocated_lines"]
            or contract["line"] >= contract["active_lines"]
            or not isinstance(statuses, list) or not isinstance(readable, list)
            or len(statuses) != count or len(readable) != count):
        raise ValueError("invalid valid-resident sector/line geometry")
    for value in statuses:
        _uint(value, "sector status", maximum=3)
    for value in readable:
        _uint(value, "sector readability", maximum=1)
    slot = contract["line"]
    if contract["component"] == "l2":
        if contract["cluster"] or contract["core"]:
            raise ValueError("L2 contract has L1 scope fields")
        slot += contract["scope"] * contract["active_lines"]
    inside = contract["bit"] - 1 - slot * (57 + 8 * contract["line_bytes"])
    if not 0 <= inside < 57 + 8 * contract["line_bytes"]:
        raise ValueError("contract bit outside its exact physical line")
    if contract["kind"] == "tag":
        valid = inside < 57 and any(status in VALID_STATUSES for status in statuses)
    else:
        valid = inside >= 57 and statuses[(inside - 57) // (8 * contract["line_bytes"] // count)] in VALID_STATUSES
    if not valid:
        raise ValueError("contract bit is not a current valid-resident point")
    return contract


def attach_valid_resident_contracts(manifest, residencies):
    """Copy a new manifest and bind each draw; never alter an existing master."""
    result = deepcopy(manifest)
    if result.get("sampling") != "with_replacement" or not isinstance(result.get("trials"), list):
        raise ValueError("with-replacement manifest required")
    # Index immutable physical slots once; a 10K master must not scan the whole
    # multi-owner residency stream afresh for every draw.
    index = {}
    for row, copy, states in _rows(residencies):
        index.setdefault((row["component"], row["scope"], copy["line"]), []).append((row, copy, states))
    for rows in index.values():
        rows.sort(key=lambda item: item[0]["start_cycle"])
        if any(a[0]["end_cycle"] > b[0]["start_cycle"] for a, b in zip(rows, rows[1:])):
            raise ValueError("overlapping physical residency contracts")
    for trial in result["trials"]:
        if trial.get("population_fingerprint") != result.get("population_fingerprint"):
            raise ValueError("manifest/trial population identity differs")
        contract = selected_site_contract(residencies, trial, _index=index)
        if "valid_resident_contract" in trial and trial["valid_resident_contract"] != contract:
            raise ValueError("refuse to replace a frozen valid-resident contract")
        trial["valid_resident_contract"] = contract
    return result


def validate_native_witness(contract, log_text):
    """Require exactly one matching pre-flip witness, in addition to FI ACKs.

    This proves occupancy/identity admission only.  The ordinary independent
    ACK validator must still prove the actual one-bit native mutation and the
    complete output checker must establish the trial outcome.
    """
    validate_site_contract(contract)
    if not isinstance(log_text, str):
        raise ValueError("complete native log text required")
    lines = [line for line in log_text.splitlines() if line.startswith("GPUFI_VALID_RESIDENT ")]
    if len(lines) != 1:
        raise ValueError("one native valid-resident pre-flip witness required")
    fields = {}
    for token in lines[0].split()[1:]:
        if token.count("=") != 1:
            raise ValueError("malformed native valid-resident witness")
        key, value = token.split("=", 1)
        if key in fields:
            raise ValueError("duplicate native valid-resident witness field")
        fields[key] = value
    expected = {key: (",".join(str(item) for item in value) if isinstance(value, list) else str(value))
                for key, value in contract.items()}
    expected["status"] = "verified"
    if fields != expected:
        raise ValueError("native valid-resident pre-flip identity/state differs")
    return fields


def cache_populations(capture):
    """Read one own closed population capture; return four unsampled groups.

    Each group contains inventory/population/residencies; population is None
    for an empty valid-resident group.  This helper writes nothing and invokes
    neither FI nor a predictor.  Authentic image/native/input admission remains
    the responsibility of the enclosing source-bound acquisition workflow.
    """
    from script.execution.cache_physical_facts import raw_physical
    root = Path(capture).resolve(strict=True)
    metadata = json.loads((root / "capture.json").read_text())
    configuration = (root / "gpgpusim.config").read_bytes()
    if hashlib.sha256(configuration).hexdigest() != metadata.get("effective_config_sha256"):
        raise ValueError("cache capture executed configuration differs")
    rows, residencies = raw_physical(root / "memory.jsonl")
    if (rows[0].get("source_fingerprint") != metadata.get("native_source_fingerprint")
            or rows[0].get("capture_profile") != "storage-population-v1"):
        raise ValueError("own closed population-only native producer required")
    topology = topology_from_config(configuration.decode("utf-8"))
    whole, _ = _inventory(residencies, topology)
    groups = {}
    for component in ("l1d", "l2"):
        original = dict(whole, spans=[row for row in whole["spans"] if row["component"] == component],
            fault_model="all-active-physical-cache-tag57-and-data-invalid-pending-single-bit-v2")
        selected = build_valid_resident_inventory(residencies, topology, component=component)
        for name, inventory in ((component, original), ("valid_" + component, selected)):
            groups[name] = dict(inventory=inventory,
                population=FaultPopulation(inventory) if inventory["spans"] else None,
                residencies=residencies)
    return groups
