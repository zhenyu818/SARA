"""Strict additive cache-source record shapes; no issuer or semantic authority."""
from script.execution.memory_effect_records import integer, copy_identity, bytes_hex

EXTENSIONS = frozenset(("functional_cache_load_source", "functional_cache_store_intent", "functional_cache_unbound",
                        "cache_disposition", "cache_write_request_sent"))


def snapshot(value):
    if value is None: return
    if not isinstance(value, dict) or set(value) != {"copy", "sector_state"}:
        raise ValueError("cache_disposition_snapshot_shape")
    item = copy_identity(value["copy"])
    count = 1 if item["cache_type"] == 0 else 4 if item["cache_type"] == 1 else 0
    if not count or len(value["sector_state"]) != count: raise ValueError("cache_disposition_sector_count")
    for state in value["sector_state"]:
        if set(state) != {"status", "readable"} or integer(state["status"]) > 3 or type(state["readable"]) is not bool:
            raise ValueError("cache_disposition_sector_type")


def candidate(value):
    if value is None: return
    if not isinstance(value, dict) or type(value.get("route_disabled")) is not bool:
        raise ValueError("functional_candidate_shape")
    if value["route_disabled"]:
        if value.get("probe_status") is not None or value.get("copy") is not None:
            raise ValueError("disabled_candidate_has_copy")
    else:
        if integer(value.get("probe_status")) > 4 or integer(value.get("write_policy")) > 4:
            raise ValueError("functional_candidate_route_or_policy")
        if value.get("copy") is not None: copy_identity(value["copy"])
        if value["probe_status"] in (0, 1, 4) and value.get("copy") is None:
            raise ValueError("functional_candidate_copy_missing")


def validate_request_origin(row, live_requests, parents):
    request = integer(row.get("request_lifetime"), positive=True)
    owner = integer(row.get("instruction_request_lifetime"), positive=True)
    if request not in live_requests or owner not in live_requests:
        raise ValueError("instruction_request_owner_not_live")
    cursor = request; actual_ancestors = {request}
    while True:
        parent = parents.get(cursor)
        if type(parent) is not int or parent < 0 or parent >= cursor:
            raise ValueError("instruction_owner_not_actual_request_ancestor")
        if not parent: break
        if parent not in live_requests: raise ValueError("instruction_request_ancestor_not_live")
        actual_ancestors.add(parent); cursor = parent
    if owner not in actual_ancestors:
        raise ValueError("instruction_owner_not_actual_request_ancestor")
    if integer(row.get("root_lifetime"), positive=True) != cursor:
        raise ValueError("instruction_request_root_changed")
    values = [row.get(key) for key in ("dynamic_warp_instruction_uid", "instruction_pc", "instruction_issue")]
    if any(value is not None for value in values):
        for value in values: integer(value)


def validate_extension(row, live_requests, parents, *, values_required=True):
    kind = row["kind"]
    if kind not in EXTENSIONS: raise ValueError("unknown_functional_cache_extension")
    integer(row.get("cycle"))
    if kind == "functional_cache_unbound":
        for name in ("kernel_uid", "thread_id"): integer(row.get(name), positive=True)
        for name in ("address_space_enum", "address", "width_bits"): integer(row.get(name))
        if type(row.get("global")) is not bool or type(row.get("write")) is not bool:
            raise ValueError("typed_unbound_functional_access")
        if row.get("operation") != "functional_access_without_supported_execution_scope":
            raise ValueError("unreviewed_unbound_functional_reason")
    elif kind.startswith("functional_cache_"):
        for name in ("kernel_uid", "thread_id", "thread_instruction_ordinal"):
            integer(row.get(name), positive=True)
        for name in ("dynamic_warp_instruction_uid", "instruction_issue_cycle", "instruction_pc", "sm", "warp", "address"):
            integer(row.get(name))
        n = integer(row.get("count"), positive=True)
        if n > 16 or row["address"] + n > 2**32: raise ValueError("functional_access_range_or_width")
        if values_required: bytes_hex(row.get("actual_operand_bytes"), n)
        elif row.get("actual_operand_bytes") is not None: raise ValueError("value_free_population_has_operand_payload")
        if (type(row.get("atomic")) is not bool or type(row.get("l1_bypass")) is not bool
                or type(row.get("write")) is not bool or row["write"] != kind.endswith("store_intent")):
            raise ValueError("functional_access_typed_kind")
        if not isinstance(row.get("bytes"), list) or len(row["bytes"]) != n:
            raise ValueError("functional_byte_coverage_missing")
        for offset, cell in enumerate(row["bytes"]):
            if integer(cell.get("address")) != row["address"] + offset: raise ValueError("functional_byte_gap")
            if row["l1_bypass"] and cell.get("l1") is not None: raise ValueError("bypass_candidate_present")
            candidate(cell.get("l1")); candidate(cell.get("l2"))
            if cell.get("l2_bank") is not None: integer(cell["l2_bank"])
    else:
        request = integer(row.get("request_lifetime"), positive=True)
        if request not in live_requests: raise ValueError("cache_extension_outside_actual_request")
        validate_request_origin(row, live_requests, parents)
        if row.get("component") not in {"l1d", "l2"}: raise ValueError("cache_extension_component")
        if kind == "cache_disposition":
            if row.get("operation") not in {"actual_access", "actual_fill"}: raise ValueError("cache_disposition_operation")
            snapshot(row.get("before")); snapshot(row.get("after"))
            if integer(row.get("write_policy")) > 4: raise ValueError("cache_disposition_policy")
            if row["operation"] == "actual_access":
                if type(row.get("write")) is not bool or integer(row.get("accepted_status")) > 4 or integer(row.get("probe_status")) > 4:
                    raise ValueError("cache_disposition_access_shape")
                mask = row.get("byte_mask")
                if not isinstance(mask, str) or not mask or len(mask) > 256 or set(mask)-{"0","1"}:
                    raise ValueError("cache_disposition_actual_byte_mask")
                integer(row.get("sector_mask")); integer(row.get("request_block"))
        else:
            parent = integer(row.get("parent_service_request_lifetime"))
            if parent and parent not in live_requests: raise ValueError("writeback_service_parent_not_live")
            if integer(row.get("event_type")) > 3: raise ValueError("actual_write_request_kind")
            integer(row.get("evicted_block")); integer(row.get("evicted_modified_bytes"))
