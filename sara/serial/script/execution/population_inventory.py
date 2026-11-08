"""Convert the independent hook-membership stream to an uncertified population.

Membership is allocated simulator storage, never a future-consumer filter. A
closed stream is evidence of observer closure only; it is not a correctness or
coverage certificate. This producer cannot enable a formal campaign.
"""
import argparse
from collections import defaultdict
import copy
import json
from pathlib import Path
import re
import resource
import time

from script.common.outcome_oracle import validate_raw_outputs
from script.execution.build_identity import digest
from script.execution.campaign import atomic_json, fingerprint
from script.execution.fault_manifest import FaultPopulation, integer
from script.execution.population_transport import iter_population_rows

SCHEMA = "sara-allocated-population-v1"
COMPACT_SCHEMA = "sara-allocated-population-compact-v2"
MODEL = "active-allocated-simulator-rf-smem-single-bit-v1"
PHASE = "after_all_core_instruction_events_at_cycle"
PENDING = ["independent_per_tick_membership_and_boundary_validation_pending",
           "application_lifecycle_coverage_not_certified",
           "collection_execution_descriptor_binding_not_independently_certified",
           "physical_capacity_not_in_allocated_container_model",
           "cache_population_and_cache_G0_not_certified"]


def validate_production_blockers(blockers):
    """Reject omitted/unresolved membership before production preparation.

    These two legacy warnings are discharged only for the source-bound current
    method path: profile1 cannot inject, and the collector and injector use the
    same complete all-kernel walk with explicit thread/shared-owner lifetimes.
    This gate is not an independent coverage certificate. Row mapping,
    lifecycle, closure and bit-cycle checks remain mandatory in its callers.
    """
    allowed = {
        "collection_requires_fault_free_profile0_perthread_allkernels",
        "multi_kernel_lifecycle_unverified",
    }
    if (not isinstance(blockers, list) or
            any(not isinstance(reason, str) or not reason for reason in blockers)):
        raise ValueError("explicit population collector blocker list required")
    unresolved = sorted(set(blockers) - allowed)
    if unresolved:
        raise ValueError("unresolved production population blockers: " + ", ".join(unresolved))


def exact_keys(row, required, optional=()):
    if not isinstance(row, dict) or not required <= row.keys() or not row.keys() <= required | set(optional):
        raise ValueError("missing or unknown lifecycle fields")


def read_stream(path, *, codec="auto", decode_budgets=None):
    """Stream transport validation; retain every span in the legacy list API.

    Removes read_text/splitlines/all-JSON temporary duplication. It does not
    promise constant memory for the retained span dictionaries or consumers.
    """
    transport={};rows=iter_population_rows(path,transport,codec=codec,**(decode_budgets or {}))
    try:header=next(rows)
    except StopIteration:raise ValueError("incomplete population stream")
    compact = header.get("schema") == COMPACT_SCHEMA
    exact_keys(header, {"kind", "schema", "phase", "model", "coordinate_system", "time_basis",
                        "num_shaders", "smem_limit_bytes", "smem_page_bytes", "smem_initialization"},
               {"shared_identity_contract", "component_filter"} if compact else {"shared_identity_contract"})
    if compact:
        # The filter selects an entire storage component, never live consumers
        # or sampled sites. Empty ticks still belong to the closed hook window.
        if header.get("component_filter") not in {"rf", "smem", "all"}:
            raise ValueError("explicit complete component population required")
    if (header["kind"] != "header" or header["schema"] not in {SCHEMA, COMPACT_SCHEMA} or header["phase"] != PHASE or
            header["model"] != MODEL or header["coordinate_system"] != "simulator_hook_allocated_storage" or
            header["time_basis"] != "simulator_global_cycle" or header["smem_page_bytes"] != 16384 or
            header["smem_initialization"] != "lazy_zero_page_retained_across_cta"):
        raise ValueError("unsupported population collector model or hook phase")
    if "shared_identity_contract" in header and header["shared_identity_contract"] != "actual_allocator_persistent_object_owner_epoch_v1":
        raise ValueError("unrecognized persistent shared identity contract")
    integer(header["num_shaders"], "num_shaders", 1)
    integer(header["smem_limit_bytes"], "smem_limit_bytes", 1)
    spans,blockers,mass=[],[],{"rf":0,"smem":0};events=defaultdict(int);footer=None
    descriptors, used = {}, set()
    minimum_start=None;maximum_stop=0
    for row in rows:
        if footer is not None:raise ValueError("population records follow closed footer")
        if row.get("kind")=="footer":footer=row;continue
        if row.get("kind")=="blocker":
            exact_keys(row,{"kind","reason"})
            if not isinstance(row["reason"],str) or not row["reason"] or row["reason"] in blockers:
                raise ValueError("invalid or duplicate collector blocker")
            blockers.append(row["reason"]);continue
        if compact and row.get("kind") == "descriptor":
            exact_keys(row, {"kind", "id", "component", "mapping_supported", "target", "lifecycle"},
                       {"bit_start", "bit_count", "byte_start", "byte_count"})
            identifier = integer(row["id"], "descriptor.id")
            if identifier in descriptors:
                raise ValueError("redefined compact population descriptor")
            descriptors[identifier] = {key: value for key, value in row.items() if key not in {"kind", "id"}}
            continue
        if compact:
            exact_keys(row, {"kind", "descriptor", "cycle_start", "cycle_stop"})
            identifier = integer(row["descriptor"], "descriptor")
            if identifier not in descriptors:
                raise ValueError("population span precedes its descriptor")
            used.add(identifier)
            row = dict(descriptors[identifier], kind="span", cycle_start=row["cycle_start"], cycle_stop=row["cycle_stop"])
            if header["component_filter"] != "all" and row["component"] != {"rf": "rf", "smem": "smem_page"}[header["component_filter"]]:
                raise ValueError("compact component filter and emitted storage disagree")
        else:
            exact_keys(row, {"kind", "cycle_start", "cycle_stop", "component", "mapping_supported", "target",
                             "hook_selectors", "ack_expected", "lifecycle"}, {"bit_start", "bit_count", "byte_start", "byte_count"})
        if row["kind"]!="span" or row["component"] not in {"rf","smem_page"}:raise ValueError("unsupported lifecycle row")
        a=integer(row["cycle_start"],"cycle_start");b=integer(row["cycle_stop"],"cycle_stop",1)
        if b<=a:raise ValueError("population span lies outside the observed half-open window")
        minimum_start=a if minimum_start is None else min(minimum_start,a);maximum_stop=max(maximum_stop,b)
        if type(row["mapping_supported"]) is not bool:raise ValueError("explicit mapping support required")
        if row["component"]=="rf":
            if "byte_start" in row or "byte_count" in row or row.get("bit_start")!=0:
                raise ValueError("RF population must include the full allocated typed register")
            bits=integer(row.get("bit_count"),"bit_count");component="rf"
        else:
            if "bit_start" in row or "bit_count" in row:raise ValueError("shared page uses byte coordinates")
            address=integer(row.get("byte_start"),"byte_start");count=integer(row.get("byte_count"),"byte_count",1)
            if address%16384 or count!=min(16384,header["smem_limit_bytes"]-address) or address>=header["smem_limit_bytes"]:
                raise ValueError("shared page must include every in-limit allocated byte")
            bits,component=count*8,"smem"
        mass[component]+=(b-a)*bits;events[a]+=1;events[b]-=1;spans.append(row)
    if footer is None:raise ValueError("missing closed population footer")
    exact_keys(footer, {"kind", "collection_closed", "first_cycle", "cycle_stop", "hook_ticks",
                        "zero_member_ticks", "rf_bit_cycles", "smem_bit_cycles", "spans", "blocker_count"},
               {"descriptors"} if compact else ())
    if compact and (footer.get("descriptors") != len(descriptors) or used != set(descriptors)):
        raise ValueError("compact descriptor closure/count disagreement")
    if footer["kind"]!="footer" or footer["collection_closed"] is not True:raise ValueError("missing closed population footer")
    for field in ("first_cycle","cycle_stop","hook_ticks","zero_member_ticks","rf_bit_cycles","smem_bit_cycles","spans","blocker_count"):
        integer(footer[field],field)
    if compact:
        integer(footer["descriptors"], "descriptors")
    start,stop=footer["first_cycle"],footer["cycle_stop"]
    if stop<=start or footer["hook_ticks"]!=stop-start or footer["zero_member_ticks"]>stop-start:
        raise ValueError("observer must cover every hook tick including empty phases")
    if minimum_start is not None and (minimum_start<start or maximum_stop>stop):
        raise ValueError("population span lies outside the observed half-open window")
    if len(spans)!=footer["spans"] or len(blockers)!=footer["blocker_count"]:raise ValueError("population footer row counts disagree")
    if mass!={"rf":footer["rf_bit_cycles"],"smem":footer["smem_bit_cycles"]}:
        raise ValueError("population bit-cycle mass disagrees with per-tick collector accounting")
    active,cursor,empty=0,start,0
    for cycle in sorted(events):
        if active==0:empty+=cycle-cursor
        active+=events[cycle]
        if active<0:raise ValueError("invalid population interval balance")
        cursor=cycle
    if active!=0:raise ValueError("unclosed population membership")
    empty+=stop-cursor
    if empty!=footer["zero_member_ticks"]:raise ValueError("empty hook tick accounting disagrees with membership intervals")
    return {"header":header,"footer":footer,"spans":spans,"blockers":blockers,"mass":mass,"transport":transport}


def validate_lifecycle(row, header):
    if header.get("schema") == COMPACT_SCHEMA:
        return validate_compact_lifecycle(row, header)
    target, hooks, ack, life = (row[key] for key in ("target", "hook_selectors", "ack_expected", "lifecycle"))
    if not all(isinstance(item, dict) for item in (target, hooks, ack, life)):
        raise ValueError("lifecycle metadata objects required")
    if hooks.get("-kernel_n") != "0" or hooks.get("-per_warp") != "0":
        raise ValueError("collector uses the exact all-kernel active-thread hook walk")
    if not isinstance(life.get("logical_cta"), str) or not re.fullmatch(r"[0-9]+,[0-9]+,[0-9]+", life["logical_cta"]):
        raise ValueError("logical CTA coordinates required independently of physical slot")
    slot = integer(target.get("cta_slot"), "cta_slot")
    sm = integer(target.get("sm"), "sm")
    local = integer(target.get("cta_id"), "cta_id")
    if sm >= header["num_shaders"] or slot != local * header["num_shaders"] + sm:
        raise ValueError("shared slot disagrees with actual allocator coordinates")
    if ack.get("cta") != life["logical_cta"]:
        raise ValueError("acknowledgement loses logical CTA generation")
    ack_fields = {"component", "thread", "kernel", "sm", "cta_slot", "cta", "width"}
    if row["component"] == "rf":
        ack_fields |= {"reg", "reg_uid"}
    actual_shared = row["component"] == "smem_page" and header.get("shared_identity_contract") == "actual_allocator_persistent_object_owner_epoch_v1"
    if actual_shared:ack_fields |= {"shared_storage_uid","shared_owner_epoch","shared_allocator_slot"}
    exact_keys(ack, ack_fields)
    for field in ack_fields - {"component", "cta", "reg"}:
        if not isinstance(ack[field], str) or not re.fullmatch(r"[0-9]+", ack[field]):
            raise ValueError("acknowledgement identity must retain exact numeric hook fields")
    if row["component"] == "smem_page" and (ack["component"] != "smem" or ack["width"] != "8"):
        raise ValueError("shared population acknowledgement must identify a single byte")
    if row["component"] == "rf":
        exact_keys(life, {"logical_cta", "frame_index", "frame_count", "active_thread_index", "register_walk_index"})
        integer(life["frame_index"], "frame_index")
        integer(life["frame_count"], "frame_count", 1)
        index = integer(life["active_thread_index"], "active_thread_index")
        reg_index = integer(life["register_walk_index"], "register_walk_index", 1)
        if life["frame_index"] >= life["frame_count"]:
            raise ValueError("register frame out of range")
        if set(hooks) != {"-kernel_n", "-per_warp", "-thread_rand", "-register_rand_n"} or hooks["-thread_rand"] != str(index) or hooks["-register_rand_n"] != str(reg_index):
            raise ValueError("RF numeric selector differs from actual hook walk")
        if row["bit_count"] != target.get("width_bits"):
            raise ValueError("RF mass must include full declared width")
    else:
        identity_fields = {"shared_storage_uid", "shared_owner_epoch", "shared_allocator_slot"}
        exact_keys(life, {"logical_cta", "shared_object_slot", "page_index", "page_bytes", "shared_scope_index"}, identity_fields)
        actual_identity = header.get("shared_identity_contract") == "actual_allocator_persistent_object_owner_epoch_v1"
        if (set(life) & identity_fields) != (identity_fields if actual_identity else set()):
            raise ValueError("complete declared actual shared identity required")
        if actual_identity and (integer(life["shared_storage_uid"], "shared_storage_uid", 1) < 1
                or integer(life["shared_owner_epoch"], "shared_owner_epoch", 1) < 1
                or integer(life["shared_allocator_slot"], "shared_allocator_slot") != slot):
            raise ValueError("actual persistent shared owner identity invalid")
        if actual_identity and any(ack.get(name) != str(life[name]) for name in identity_fields):
            raise ValueError("shared actual owner acknowledgement disagrees with lifecycle")
        index = integer(life["shared_scope_index"], "shared_scope_index")
        if (integer(life["shared_object_slot"], "shared_object_slot") != slot or
                integer(life["page_index"], "page_index") * 16384 != row["byte_start"] or life["page_bytes"] != 16384):
            raise ValueError("shared page allocator identity disagrees")
        if set(hooks) != {"-kernel_n", "-per_warp", "-block_rand", "-block_n"} or hooks["-block_rand"] != str(index) or hooks["-block_n"] != "1":
            raise ValueError("shared selector differs from actual scope walk")


def validate_compact_lifecycle(row, header):
    """Validate analysis coordinates without constructing FI walk selectors.

    The same actual allocator/register identities and complete lifecycle are
    required. Numeric hook-walk indexes and expected injection ACKs select an
    FI action; they do not affect the analysis population or its mapping.
    """
    from script.execution.fault_manifest import location_identity
    target, life = row.get("target"), row.get("lifecycle")
    if not isinstance(target, dict) or not isinstance(life, dict):
        raise ValueError("compact target and actual lifecycle objects required")
    if (not isinstance(life.get("logical_cta"), str)
            or not re.fullmatch(r"[0-9]+,[0-9]+,[0-9]+", life["logical_cta"])):
        raise ValueError("logical CTA generation required")
    sm = integer(target.get("sm"), "sm")
    slot = integer(target.get("cta_slot"), "cta_slot")
    local = integer(target.get("cta_id"), "cta_id")
    integer(target.get("kernel"), "kernel", 1)
    if sm >= header["num_shaders"] or slot != local * header["num_shaders"] + sm:
        raise ValueError("compact storage slot differs from actual allocator")
    if row["component"] == "rf":
        location_identity("rf", target)
        exact_keys(life, {"logical_cta", "frame_index", "frame_count"})
        if (integer(life["frame_count"], "frame_count", 1) != 1
                or integer(life["frame_index"], "frame_index") != 0):
            raise ValueError("multi_frame_lifecycle_unverified")
        if row.get("bit_start") != 0 or row.get("bit_count") != target["width_bits"]:
            raise ValueError("compact RF must retain the complete allocated register")
        if target["width_bits"] not in {1, 8, 16, 32, 64, 128}:
            raise ValueError("unsupported native typed RF width")
    elif row["component"] == "smem_page":
        exact_keys(target, {"sm", "cta_slot", "kernel", "cta_id"})
        required = {"logical_cta", "shared_object_slot", "page_index", "page_bytes",
                    "shared_storage_uid", "shared_owner_epoch", "shared_allocator_slot"}
        exact_keys(life, required)
        if header.get("shared_identity_contract") != "actual_allocator_persistent_object_owner_epoch_v1":
            raise ValueError("actual persistent shared identity required")
        if (integer(life["shared_storage_uid"], "shared_storage_uid", 1) < 1
                or integer(life["shared_owner_epoch"], "shared_owner_epoch", 1) < 1
                or integer(life["shared_allocator_slot"], "shared_allocator_slot") != slot
                or integer(life["shared_object_slot"], "shared_object_slot") != slot
                or integer(life["page_index"], "page_index") * 16384 != row["byte_start"]
                or life["page_bytes"] != 16384):
            raise ValueError("compact shared allocator lifetime disagreement")
    else:
        raise ValueError("unsupported compact population component")


def build_inventory(stream, provenance):
    """Return (inventory or None, audit), keeping blocked mass in the audit."""
    from script.execution.fi_campaign import validate_site_binding
    if stream["header"].get("schema") == COMPACT_SCHEMA:
        raise ValueError("analysis-only compact population cannot create FI execution selectors")
    blocked = list(stream["blockers"])
    audit = {"schema_version": 1, "model": MODEL, "coordinate_system": "simulator_hook_allocated_storage",
             "raw_bit_cycles": stream["mass"], "raw_span_count": len(stream["spans"]),
             "observed_window": stream["footer"], "collector_blockers": blocked,
             "coverage_certified": False, "certification_blockers": list(PENDING), "provenance": provenance}
    canonical = []
    kernels, generations = set(), defaultdict(set)
    rf_width_mass = defaultdict(int)
    for row in stream["spans"]:
        validate_lifecycle(row, stream["header"])
        if not row["mapping_supported"]:
            blocked.append("unresolved_mapping_retained_in_raw_mass")
        if row["component"] == "rf" and row["lifecycle"]["frame_count"] != 1:
            blocked.append("multi_frame_lifecycle_unverified")
        kernels.add(row["target"].get("kernel"))
        generation = (row["target"].get("kernel"), row["lifecycle"]["logical_cta"])
        generations[row["target"]["cta_slot"]].add(generation)
        span = {key: copy.deepcopy(row[key]) for key in
                ("cycle_start", "cycle_stop", "target", "hook_selectors", "ack_expected", "lifecycle")}
        if row["component"] == "rf":
            rf_width_mass[str(row["bit_count"])] += (row["cycle_stop"] - row["cycle_start"]) * row["bit_count"]
            canonical.append(dict(span, component="rf", bit_start=0, bit_count=row["bit_count"]))
        else:
            for address in range(row["byte_start"], row["byte_start"] + row["byte_count"]):
                byte = copy.deepcopy(span)
                byte["target"]["byte_addr"] = address
                byte["ack_expected"]["byte_addr"] = str(address)
                canonical.append(dict(byte, component="smem", bit_start=address * 8, bit_count=8))
    if len(kernels) > 1:
        blocked.append("multi_kernel_lifecycle_unverified")
    audit["allocation_generations_per_slot"] = {str(slot): len(values) for slot, values in sorted(generations.items())}
    audit["rf_width_bit_cycles"] = dict(sorted(rf_width_mass.items()))
    audit["collector_blockers"] = sorted(set(blocked))
    audit["raw_mass_completeness_certified"] = False
    if blocked:
        audit["status"] = "blocked"
        return None, audit
    inventory = {"schema_version": 1, "population_id": "allocated-" + fingerprint(provenance)[:24],
                 "fault_model": MODEL, "coordinate_system": "simulator_hook_allocated_storage",
                 "time_basis": "simulator_global_cycle", "coverage_certified": False,
                 "certification_blockers": list(PENDING), "provenance": provenance,
                 "collection_header": stream["header"], "collection_window": stream["footer"], "spans": canonical}
    if not canonical:
        audit["status"] = "empty"
        return None, audit
    population = FaultPopulation(inventory)
    if population.mass != sum(stream["mass"].values()):
        raise ValueError("canonicalization changed the population denominator")
    # Check both endpoints of every span against the shared executor contract.
    previous = 0
    for end in population.ends:
        validate_site_binding(population.resolve(previous))
        validate_site_binding(population.resolve(end - 1))
        previous = end
    audit.update(status="uncertified_inventory", population_fingerprint=population.identity,
                 population_size=population.mass, canonical_span_count=len(canonical))
    return inventory, audit


def collect_provenance(stream_path, spec_path, session_path):
    """Bind actual files; never accept an arbitrary caller input fingerprint."""
    from script.execution.fi_campaign import execution_input_descriptor, fault_records, relative_name
    spec = json.loads(spec_path.read_text())
    session = json.loads(session_path.read_text())
    if (session.get("status") != "passed" or session.get("container_state", {}).get("ExitCode") != 0 or
            session.get("container_state", {}).get("OOMKilled") is not False):
        raise ValueError("population requires a successful, non-OOM, uninterrupted Docker session")
    evidence = session_path.parent / "evidence"
    resources = json.loads((evidence / "job_resources.json").read_text())
    if (resources.get("limits_verified") is not True or resources.get("window_interrupted") is not False or
            resources.get("interrupted_signals") != [] or resources.get("exit_status") != 0 or
            resources.get("child_exit_status") != 0):
        raise ValueError("population collection lacks verified uninterrupted execution limits")
    golden = (spec_path.parent / spec["golden_log"]).resolve()
    for item in (stream_path, golden):
        if evidence.resolve() not in item.resolve().parents:
            raise ValueError("stream and golden log must belong to the retained session evidence")
    output_path = spec_path.parent / spec["output_spec"]
    outputs = json.loads(output_path.read_text())
    if not validate_raw_outputs(golden, outputs)["valid"] or fault_records(golden):
        raise ValueError("population needs complete fault-free golden raw outputs")
    if "GPGPU-Sim" not in golden.read_text(errors="replace"):
        raise ValueError("golden is not a simulator execution")
    command = spec.get("command")
    if not isinstance(command, list) or not command or any(not isinstance(value, str) for value in command) or not command[0].startswith("./"):
        raise ValueError("population command requires an explicitly hashed executable asset")
    assets = {str(relative_name(key)): digest(spec_path.parent / value) for key, value in spec["assets"].items()}
    if str(relative_name(command[0][2:])) not in assets or "gpgpusim.config" in assets:
        raise ValueError("invalid population execution assets")
    config_path = spec_path.parent / spec["base_config"]
    descriptor = execution_input_descriptor(spec, assets, digest(config_path), fingerprint(outputs))
    identity = spec.get("identity", {})
    for field in ("source_fingerprint", "image_id"):
        if not isinstance(session.get(field), str) or not session[field] or identity.get(field) != session[field]:
            raise ValueError("population source/image identity differs from retained session")
    if fingerprint(session.get("source_files", {})) != session["source_fingerprint"]:
        raise ValueError("retained session source manifest fingerprint disagrees")
    if identity.get("input_fingerprint") != fingerprint(descriptor) or identity.get("fault_model") != MODEL:
        raise ValueError("population input/model identity differs from actual descriptor")
    root = Path(__file__).resolve().parents[2]
    required = ("src/gpgpu-sim/gpu-sim.cc", "src/gpgpu-sim/gpu-sim.h", "src/gpgpu-sim/population_inventory.h")
    for name in required:
        if session.get("source_files", {}).get(name) != digest(root / name):
            raise ValueError("collector source differs from retained session snapshot")
    return {"identity": {**identity, "input_fingerprint": fingerprint(descriptor)},
            "execution_input_descriptor": descriptor, "stream_sha256": digest(stream_path),
            "golden_sha256": digest(golden), "session_sha256": digest(session_path),
            "resource_evidence_sha256": digest(evidence / "job_resources.json"),
            "producer_sha256": digest(Path(__file__)), "manifest_module_sha256": digest(
                Path(__file__).with_name("fault_manifest.py")),
            "collection_to_application_completion_binding": "pending_independent_validation"}


def main():
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_SELF)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stream", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()
    if args.inventory.exists() or args.audit.exists():
        raise FileExistsError("never overwrite published population evidence")
    stream = read_stream(args.stream)
    provenance = collect_provenance(args.stream, args.spec, args.session)
    inventory, audit = build_inventory(stream, provenance)
    if inventory is not None:
        atomic_json(args.inventory, inventory)
    after = resource.getrusage(resource.RUSAGE_SELF)
    audit["producer_metrics"] = {
        "wall_seconds": time.monotonic() - started,
        "cpu_user_seconds": after.ru_utime - before.ru_utime,
        "cpu_system_seconds": after.ru_stime - before.ru_stime,
        "max_rss_kib_process": after.ru_maxrss,
        "scope": "producer after imports through inventory serialization; final audit write excluded",
        "collection_metrics": "not measured here; include separate observer run and full preprocessing in end-to-end reports"}
    audit["result_fingerprint"] = fingerprint(audit)
    atomic_json(args.audit, audit)
    if inventory is None:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
