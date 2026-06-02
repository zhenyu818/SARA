#!/usr/bin/env python3
"""Per-trial exact classification for recorded FI injection points."""

import argparse
import bisect
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import exact_sdc_compute as esc
import outcome_oracle as shared_output_oracle

CLASS_LABELS = ("Masked", "SDC", "DUE")
FI_IDENTITY_FIELDS = [
    "cycle",
    "active_threads_size",
    "thread_rand",
    "chosen_thread_uid",
    "reg",
    "reg_uid",
    "bit",
    "datatype_bits",
    "seed",
    "per_warp",
    "kernel",
    "warp_rand",
    "block_rand",
    "local_bits",
    "shared_bits",
    "l1d_shader",
    "l1d_bits",
    "l1c_shader",
    "l1c_bits",
    "l1t_shader",
    "l1t_bits",
    "l2_bits",
    "gmem_byte_seed",
    "gmem_target_addr",
]


def normalize_outcome(value: str) -> str:
    v = str(value or "").strip().lower()
    if "sdc" in v:
        return "SDC"
    if "due" in v:
        return "DUE"
    if "masked" in v:
        return "Masked"
    return ""


def parse_int_maybe(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    s = str(value).strip()
    if s == "":
        return default
    try:
        return int(s, 0)
    except ValueError:
        return default


def parse_uid_list(value: Any) -> List[int]:
    if value is None:
        return []
    s = str(value).strip()
    if not s:
        return []
    out: List[int] = []
    for tok in s.replace(",", ":").split(":"):
        t = tok.strip()
        if not t:
            continue
        try:
            out.append(int(t, 0))
        except ValueError:
            continue
    uniq = sorted({x for x in out if x >= 0})
    return uniq


def parse_bit_field(value: Any) -> Optional[int]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    tok = s.replace(",", ":").split(":", 1)[0].strip()
    if not tok:
        return None
    try:
        return int(tok, 0)
    except ValueError:
        return None


def parse_int_list(value: Any) -> List[int]:
    if value is None:
        return []
    out: List[int] = []
    for tok in str(value).replace(",", ":").split(":"):
        t = tok.strip()
        if not t:
            continue
        try:
            out.append(int(t, 0))
        except ValueError:
            continue
    return out


def load_output_spec(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        return []
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        if "base" not in item or "bytes" not in item:
            continue
        try:
            base = int(str(item.get("base")), 0)
            size = int(item.get("bytes"))
        except Exception:
            continue
        if size <= 0:
            continue
        row = {"base": int(base), "bytes": int(size)}
        if item.get("name") is not None:
            row["name"] = str(item.get("name"))
        if item.get("space") is not None:
            row["space"] = str(item.get("space"))
        out.append(row)
    return out


def load_cycles_domain(path: Path) -> Set[int]:
    domain: Set[int] = set()
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text())
        rows: Iterable[Any]
        if isinstance(raw, dict):
            rows = raw.get("cycles", [])
        else:
            rows = raw
        if isinstance(rows, list):
            for item in rows:
                if isinstance(item, dict) and "cycle" in item:
                    domain.add(int(item["cycle"]))
                elif isinstance(item, list) and len(item) >= 1:
                    domain.add(int(item[0]))
        return domain

    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        tok = s.replace(",", " ").split()[0]
        domain.add(int(tok, 0))
    return domain


def load_injection_points(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader]


def load_analyzer_for_point_classification(path: Path) -> Dict[str, Any]:
    """Load analyzer output with the same binary-manifest path as exact SARA.

    Normal SARA exact computation accepts ``analyzer_output.json`` either as a
    full JSON payload or as a compact manifest pointing at a pickle payload.
    Reuse the canonical compute loader so FI comparison classification sees
    the same analyzer payload shape as the aggregate SARA timing path.
    """

    analyzer = esc._load_analyzer_output_for_compute(Path(path))  # type: ignore[attr-defined]
    read_events = analyzer.get("read_events", [])
    if isinstance(read_events, list):
        normalized: List[Any] = []
        changed = False
        for rec in read_events:
            if esc._is_compact_read_event_row(rec):  # type: ignore[attr-defined]
                normalized.append(esc._expand_compact_read_event_row(rec))  # type: ignore[attr-defined]
                changed = True
            else:
                normalized.append(rec)
        if changed:
            analyzer = dict(analyzer)
            analyzer["read_events"] = normalized
    return analyzer


def load_fi_outcomes(path: Path) -> Dict[int, Dict[str, str]]:
    out: Dict[int, Dict[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            trial = parse_int_maybe(row.get("trial"))
            if trial is None:
                continue
            out[int(trial)] = {
                "fi_outcome": normalize_outcome(row.get("outcome", "")),
                "due_reason": str(row.get("due_reason", "")).strip(),
                "exit_status": str(row.get("exit_status", "")).strip(),
                "run_batch": str(row.get("run_batch", "")).strip(),
                "tmp_file": str(row.get("tmp_file", "")).strip(),
            }
    return out


def make_resolver(
    by_uid: Dict[Tuple[int, int, int], Dict[str, Any]],
    by_name: Dict[Tuple[int, int, str], Dict[str, Any]],
):
    cache: Dict[Tuple[int, int, str, Tuple[int, ...]], Optional[Dict[str, Any]]] = {}

    def resolve(
        tid: int,
        read_cycle: int,
        label: str,
        uids: Sequence[int],
    ) -> Optional[Dict[str, Any]]:
        key = (tid, read_cycle, label, tuple(uids))
        if key in cache:
            return cache[key]

        rec = by_name.get((tid, read_cycle, label))
        if rec is None:
            merged: Optional[Dict[str, Any]] = None
            for uid in uids:
                rec_uid = by_uid.get((tid, read_cycle, int(uid)))
                if rec_uid is not None:
                    merged = esc.merge_classification_record(merged, rec_uid)
            rec = merged
        cache[key] = rec
        return rec

    return resolve


def parse_reason_set(spec: str) -> Set[str]:
    out: Set[str] = set()
    for tok in str(spec).replace(",", ":").split(":"):
        t = tok.strip().lower()
        if not t:
            continue
        out.add(t)
    return out


def resolve_trial_run_log(
    fi_info: Dict[str, str],
    fi_run_log_prefix: Optional[str],
    fi_run_log_root: Optional[str],
) -> Optional[Path]:
    tmp_file = str(fi_info.get("tmp_file", "")).strip()
    if not tmp_file:
        return None

    cand0 = Path(tmp_file)
    if cand0.is_file():
        return cand0

    run_batch = str(fi_info.get("run_batch", "")).strip()
    batch_id = parse_int_maybe(run_batch)

    candidates: List[Path] = []
    if fi_run_log_prefix and batch_id is not None:
        candidates.append(Path(f"{fi_run_log_prefix}{int(batch_id)}") / tmp_file)
    if fi_run_log_root:
        root = Path(fi_run_log_root)
        if batch_id is not None:
            candidates.append(root / str(int(batch_id)) / tmp_file)
            candidates.append(root / f"logs{int(batch_id)}" / tmp_file)
        candidates.append(root / tmp_file)

    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def load_semantic_oracle_db(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {"version": 1, "entries": {}}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"version": 1, "entries": {}}
    if not isinstance(raw, dict):
        return {"version": 1, "entries": {}}
    entries = raw.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}
    return {"version": 1, "entries": entries}


def save_semantic_oracle_db(path: Optional[Path], db: Dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(db, indent=2, sort_keys=True) + "\n")


def normalize_oracle_class(value: str) -> Optional[str]:
    v = str(value).strip().lower()
    if v == "masked":
        return "Masked"
    if v == "sdc":
        return "SDC"
    if v == "due":
        return "DUE"
    return None


def semantic_oracle_oracle_for_trial(
    *,
    trial: int,
    fi_info: Dict[str, str],
    fi_run_log_prefix: Optional[str],
    fi_run_log_root: Optional[str],
    golden_log: Optional[Path],
    output_spec_rows: Sequence[Dict[str, Any]],
    tol_policy: Dict[str, Any],
    timeout_statuses: Set[int],
    semantic_db: Dict[str, Any],
    semantic_stats: Dict[str, Any],
) -> Dict[str, Any]:
    semantic_stats["queries"] = int(semantic_stats.get("queries", 0)) + 1
    entries = semantic_db.setdefault("entries", {})
    if not isinstance(entries, dict):
        entries = {}
        semantic_db["entries"] = entries

    run_log = resolve_trial_run_log(fi_info, fi_run_log_prefix, fi_run_log_root)
    run_log_str = str(run_log) if run_log is not None else ""
    exit_status = parse_int_maybe(fi_info.get("exit_status"))

    cache_key = json.dumps(
        {
            "trial": int(trial),
            "run_log": run_log_str,
            "exit_status": exit_status,
            "golden_log": str(golden_log) if golden_log is not None else "",
            "output_spec_size": len(output_spec_rows),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    cached = entries.get(cache_key)
    if isinstance(cached, dict):
        semantic_stats["cache_hits"] = int(semantic_stats.get("cache_hits", 0)) + 1
        out = dict(cached)
        out["cache_hit"] = True
        out["cache_key"] = cache_key
        return out

    semantic_stats["cache_misses"] = int(semantic_stats.get("cache_misses", 0)) + 1

    if golden_log is None or not golden_log.is_file():
        semantic_stats["infra_errors"] = int(semantic_stats.get("infra_errors", 0)) + 1
        infra_counts: Counter = semantic_stats.setdefault("infra_error_reason_counts", Counter())
        infra_counts.update(["missing_golden_log"])
        result = {
            "ok": False,
            "infra_error": True,
            "error_reason": "missing_golden_log",
            "run_log": run_log_str,
        }
        entries[cache_key] = dict(result)
        return result

    if run_log is None or not run_log.is_file():
        semantic_stats["infra_errors"] = int(semantic_stats.get("infra_errors", 0)) + 1
        infra_counts = semantic_stats.setdefault("infra_error_reason_counts", Counter())
        infra_counts.update(["missing_run_log"])
        result = {
            "ok": False,
            "infra_error": True,
            "error_reason": "missing_run_log",
            "run_log": run_log_str,
        }
        entries[cache_key] = dict(result)
        return result

    oracle = shared_output_oracle.compare_fi_logs(
        golden_log=golden_log,
        run_log=run_log,
        output_spec=output_spec_rows,
        tol_policy=tol_policy,
        exit_status=exit_status,
        timeout_exit_statuses=timeout_statuses,
    )
    oracle_cls = normalize_oracle_class(oracle.get("classification"))
    detail = oracle.get("detail", {})
    oracle_reason = str(detail.get("reason", "")).strip()
    if oracle_cls is None:
        semantic_stats["infra_errors"] = int(semantic_stats.get("infra_errors", 0)) + 1
        infra_counts = semantic_stats.setdefault("infra_error_reason_counts", Counter())
        infra_counts.update(["invalid_oracle_class"])
        result = {
            "ok": False,
            "infra_error": True,
            "error_reason": "invalid_oracle_class",
            "oracle_reason": oracle_reason,
            "run_log": str(run_log),
        }
        entries[cache_key] = dict(result)
        return result

    result = {
        "ok": True,
        "infra_error": False,
        "classification": oracle_cls,
        "oracle_reason": oracle_reason,
        "oracle_detail": detail,
        "run_log": str(run_log),
    }
    entries[cache_key] = dict(result)
    out = dict(result)
    out["cache_hit"] = False
    out["cache_key"] = cache_key
    return out


def predict_point(
    *,
    cycle: int,
    thread_uid: int,
    reg_label: str,
    reg_uids: Sequence[int],
    bit_1based: int,
    reads: Dict[int, Dict[int, List[int]]],
    writes: Dict[int, Dict[int, List[int]]],
    resolve_read_record,
) -> Tuple[str, Dict[str, Any]]:
    def fmt_mask(v: int) -> str:
        return f"0x{(int(v) & esc.MASK64):016x}"

    bit0_query = bit_1based - 1

    def semantic_due_reason_detail_for_bit(rec: Dict[str, Any]) -> Tuple[str, str]:
        reason = ""
        detail = ""
        reason_map = rec.get("semantic_due_reason_by_bit")
        if isinstance(reason_map, dict):
            reason = str(reason_map.get(str(bit0_query), "")).strip()
        if not reason:
            reason = str(rec.get("semantic_due_reason_this_read", "")).strip()

        detail_map = rec.get("semantic_due_detail_by_bit")
        if isinstance(detail_map, dict) and str(bit0_query) in detail_map:
            detail_raw = detail_map.get(str(bit0_query))
            if isinstance(detail_raw, (dict, list)):
                detail = json.dumps(detail_raw, sort_keys=True)
            else:
                detail = str(detail_raw or "").strip()
        if not detail:
            detail_raw = rec.get("semantic_due_detail_this_read", "")
            if isinstance(detail_raw, (dict, list)):
                detail = json.dumps(detail_raw, sort_keys=True)
            else:
                detail = str(detail_raw or "").strip()

        return reason, detail

    def extract_masks(rec: Dict[str, Any]) -> Dict[str, int]:
        src_w = max(0, min(64, int(rec.get("src_width_bits", 64))))
        wmask = esc.width_mask(src_w)
        observed_mask = esc.parse_mask(rec.get("observed_mask_this_read", 0)) & wmask
        due_mask = esc.parse_mask(rec.get("due_mask_this_read", 0)) & wmask
        trace_mask = esc.parse_mask(rec.get("trace_expanding_mask_this_read", 0)) & wmask
        semantic_masked = esc.parse_mask(rec.get("semantic_masked_mask_this_read", 0)) & wmask
        semantic_sdc = esc.parse_mask(rec.get("semantic_sdc_mask_this_read", 0)) & wmask
        semantic_due = esc.parse_mask(rec.get("semantic_due_mask_this_read", 0)) & wmask
        semantic_covered = (semantic_masked | semantic_sdc | semantic_due) & trace_mask
        return {
            "observed_mask": observed_mask,
            "due_mask": due_mask,
            "trace_expanding_mask": trace_mask,
            "semantic_masked_mask": semantic_masked,
            "semantic_sdc_mask": semantic_sdc,
            "semantic_due_mask": semantic_due,
            "due_oracle_mask": trace_mask & semantic_due,
            "due_static_mask": ((~trace_mask) & wmask) & due_mask,
            "trace_policy_fallback_mask": trace_mask & ((~semantic_covered) & wmask),
        }

    def rec_source_payload(rec: Dict[str, Any], masks: Dict[str, int]) -> Dict[str, Any]:
        due_reason, due_detail = semantic_due_reason_detail_for_bit(rec)
        return {
            "consumer_inst_pc": str(rec.get("pc", "")),
            "consumer_inst_opcode": str(rec.get("opcode", "")),
            "observed_mask": fmt_mask(masks["observed_mask"]),
            "trace_expanding_mask": fmt_mask(masks["trace_expanding_mask"]),
            "semantic_sdc_mask": fmt_mask(masks["semantic_sdc_mask"]),
            "semantic_masked_mask": fmt_mask(masks["semantic_masked_mask"]),
            "semantic_due_mask": fmt_mask(masks["semantic_due_mask"]),
            "predicted_due_reason": due_reason,
            "predicted_due_detail": due_detail,
        }

    def apply_source_payload(
        payload: Optional[Dict[str, Any]],
        debug: Dict[str, Any],
    ) -> None:
        if payload is None:
            return
        debug["consumer_inst_pc"] = str(payload.get("consumer_inst_pc", ""))
        debug["consumer_inst_opcode"] = str(payload.get("consumer_inst_opcode", ""))
        debug["observed_mask"] = str(payload.get("observed_mask", debug["observed_mask"]))
        debug["trace_expanding_mask"] = str(
            payload.get("trace_expanding_mask", debug["trace_expanding_mask"])
        )
        debug["semantic_sdc_mask"] = str(payload.get("semantic_sdc_mask", debug["semantic_sdc_mask"]))
        debug["semantic_masked_mask"] = str(
            payload.get("semantic_masked_mask", debug["semantic_masked_mask"])
        )
        debug["semantic_due_mask"] = str(payload.get("semantic_due_mask", debug["semantic_due_mask"]))
        debug["predicted_due_reason"] = str(
            payload.get("predicted_due_reason", debug.get("predicted_due_reason", ""))
        )
        debug["predicted_due_detail"] = str(
            payload.get("predicted_due_detail", debug.get("predicted_due_detail", ""))
        )

    debug: Dict[str, Any] = {
        "missing_analyzer_records": 0,
        "consuming_reads_considered": 0,
        "model": esc.CANONICAL_RF_FAULT_MODEL,
        "predicted_reason": "",
        "consumer_inst_pc": "",
        "consumer_inst_opcode": "",
        "observed_mask": fmt_mask(0),
        "trace_expanding_mask": fmt_mask(0),
        "semantic_sdc_mask": fmt_mask(0),
        "semantic_masked_mask": fmt_mask(0),
        "semantic_due_mask": fmt_mask(0),
        "predicted_due_reason": "",
        "predicted_due_detail": "",
    }

    if bit_1based < 1:
        debug["reason"] = "invalid_bit"
        debug["predicted_reason"] = "observed_path"
        return "Masked", debug

    if thread_uid < 0:
        debug["reason"] = "inactive_thread"
        debug["predicted_reason"] = "observed_path"
        return "Masked", debug

    if not reg_uids:
        debug["reason"] = "no_reg_uid_mapping"
        debug["predicted_reason"] = "observed_path"
        return "Masked", debug

    tid_reads = reads.get(thread_uid, {})
    read_cycle_set: Set[int] = set()
    for uid in reg_uids:
        read_cycle_set.update(tid_reads.get(int(uid), []))
    if not read_cycle_set:
        debug["reason"] = "no_reads_for_reg"
        debug["predicted_reason"] = "observed_path"
        return "Masked", debug
    read_cycles = sorted(read_cycle_set)

    ge_mode = esc.CANONICAL_CONSUMER_COMPARE == "ge"

    if esc.CANONICAL_RF_FAULT_MODEL == "persistent":
        tid_writes = writes.get(thread_uid, {})
        write_cycle_set: Set[int] = set()
        for uid in reg_uids:
            write_cycle_set.update(tid_writes.get(int(uid), []))
        write_cycles = sorted(write_cycle_set)

        seg_lo = -(10**30)
        seg_hi = 10**30
        if write_cycles:
            idx_hi = bisect.bisect_right(write_cycles, cycle)
            if idx_hi > 0:
                seg_lo = int(write_cycles[idx_hi - 1])
            if idx_hi < len(write_cycles):
                seg_hi = int(write_cycles[idx_hi])

        lo_idx = bisect.bisect_left(read_cycles, seg_lo)
        hi_idx = len(read_cycles) if seg_hi >= 10**30 else bisect.bisect_right(read_cycles, seg_hi)
        seg_reads = read_cycles[lo_idx:hi_idx]
        if not seg_reads:
            debug["reason"] = "no_reads_in_lifetime_segment"
            debug["predicted_reason"] = "observed_path"
            return "Masked", debug

        if ge_mode:
            start_idx = bisect.bisect_left(seg_reads, cycle)
        else:
            start_idx = bisect.bisect_right(seg_reads, cycle)
        if start_idx >= len(seg_reads):
            debug["reason"] = "no_consumer_after_injection"
            debug["predicted_reason"] = "observed_path"
            return "Masked", debug

        due_agg = 0
        sdc_agg = 0
        due_oracle_agg = 0
        due_static_agg = 0
        semantic_sdc_agg = 0
        semantic_masked_agg = 0
        trace_policy_fallback_agg = 0
        trace_agg = 0
        considered = 0
        missing = 0
        first_payload: Optional[Dict[str, Any]] = None
        reason_payloads: Dict[str, Dict[str, Any]] = {}
        for rc in seg_reads[start_idx:]:
            rec = resolve_read_record(thread_uid, int(rc), reg_label, reg_uids)
            if rec is None:
                missing += 1
                continue
            considered += 1
            masks_raw = extract_masks(rec)
            if first_payload is None:
                first_payload = rec_source_payload(rec, masks_raw)
            due_mask, sdc_mask, _trace_added_sdc = esc.final_due_sdc_masks(
                rec,
                esc.CANONICAL_TRACE_EXPANDING_POLICY,
            )
            due_agg |= due_mask
            sdc_agg |= sdc_mask
            due_oracle_agg |= masks_raw["due_oracle_mask"]
            due_static_agg |= masks_raw["due_static_mask"]
            semantic_sdc_agg |= masks_raw["semantic_sdc_mask"]
            semantic_masked_agg |= masks_raw["semantic_masked_mask"]
            trace_policy_fallback_agg |= masks_raw["trace_policy_fallback_mask"]
            trace_agg |= masks_raw["trace_expanding_mask"]

            payload = rec_source_payload(rec, masks_raw)
            bit_mask = 1 << (bit_1based - 1) if bit_1based <= 64 else 0
            for reason_name, reason_mask in (
                ("due_oracle", masks_raw["due_oracle_mask"]),
                ("due_static", masks_raw["due_static_mask"]),
                ("trace_semantic", masks_raw["semantic_sdc_mask"] | masks_raw["semantic_masked_mask"]),
                ("trace_policy_fallback", masks_raw["trace_policy_fallback_mask"]),
                ("observed_path", masks_raw["observed_mask"]),
            ):
                if bit_mask != 0 and (reason_mask & bit_mask) != 0 and reason_name not in reason_payloads:
                    reason_payloads[reason_name] = payload

        sdc_agg &= ~due_agg
        bit0 = bit_1based - 1
        debug["missing_analyzer_records"] = missing
        debug["consuming_reads_considered"] = considered
        if first_payload is not None:
            apply_source_payload(first_payload, debug)
        if bit0 >= 64:
            debug["predicted_reason"] = "observed_path"
            return "Masked", debug
        if ((due_agg >> bit0) & 1) != 0:
            if ((due_oracle_agg >> bit0) & 1) != 0:
                debug["predicted_reason"] = "due_oracle"
                apply_source_payload(reason_payloads.get("due_oracle"), debug)
                if not str(debug.get("predicted_due_reason", "")).strip():
                    debug["predicted_due_reason"] = "due_oracle"
                if not str(debug.get("predicted_due_detail", "")).strip():
                    debug["predicted_due_detail"] = debug["predicted_due_reason"]
            else:
                debug["predicted_reason"] = "due_static"
                apply_source_payload(reason_payloads.get("due_static"), debug)
                debug["predicted_due_reason"] = "due_static"
                debug["predicted_due_detail"] = "due_static_mask"
            return "DUE", debug
        if ((sdc_agg >> bit0) & 1) != 0:
            if ((semantic_sdc_agg >> bit0) & 1) != 0:
                debug["predicted_reason"] = "trace_semantic"
                apply_source_payload(reason_payloads.get("trace_semantic"), debug)
            elif ((trace_policy_fallback_agg >> bit0) & 1) != 0:
                debug["predicted_reason"] = "trace_policy_fallback"
                apply_source_payload(reason_payloads.get("trace_policy_fallback"), debug)
            else:
                debug["predicted_reason"] = "observed_path"
                apply_source_payload(reason_payloads.get("observed_path"), debug)
            return "SDC", debug
        if ((trace_policy_fallback_agg >> bit0) & 1) != 0:
            debug["predicted_reason"] = "trace_policy_fallback"
            apply_source_payload(reason_payloads.get("trace_policy_fallback"), debug)
        elif ((trace_agg >> bit0) & 1) != 0:
            debug["predicted_reason"] = "trace_semantic"
            apply_source_payload(reason_payloads.get("trace_semantic"), debug)
        else:
            debug["predicted_reason"] = "observed_path"
            apply_source_payload(reason_payloads.get("observed_path"), debug)
        return "Masked", debug

    # Canonical SARA uses the persistent RF lifetime model. The transient branch
    # is retained only as a defensive fallback if the canonical constant changes
    # in a future documented method revision.
    rc = None
    if ge_mode:
        idx = bisect.bisect_left(read_cycles, cycle)
    else:
        idx = bisect.bisect_right(read_cycles, cycle)
    if idx < len(read_cycles):
        rc = read_cycles[idx]
    if rc is None:
        debug["reason"] = "no_consumer_after_injection"
        debug["predicted_reason"] = "observed_path"
        return "Masked", debug

    rec = resolve_read_record(thread_uid, int(rc), reg_label, reg_uids)
    if rec is None:
        debug["missing_analyzer_records"] = 1
        debug["predicted_reason"] = "observed_path"
        return "Masked", debug

    masks_raw = extract_masks(rec)
    apply_source_payload(rec_source_payload(rec, masks_raw), debug)
    cls, cls_reason = esc.classify_bit_with_reason(
        rec,
        bit_1based - 1,
        esc.CANONICAL_TRACE_EXPANDING_POLICY,
    )
    if cls == "due":
        if ((masks_raw["due_oracle_mask"] >> (bit_1based - 1)) & 1) != 0:
            debug["predicted_reason"] = "due_oracle"
            if not str(debug.get("predicted_due_reason", "")).strip():
                debug["predicted_due_reason"] = "due_oracle"
            if not str(debug.get("predicted_due_detail", "")).strip():
                debug["predicted_due_detail"] = debug["predicted_due_reason"]
        else:
            debug["predicted_reason"] = "due_static"
            debug["predicted_due_reason"] = "due_static"
            debug["predicted_due_detail"] = "due_static_mask"
        return "DUE", debug
    if cls == "sdc":
        if cls_reason == "trace_semantic":
            debug["predicted_reason"] = "trace_semantic"
        elif cls_reason == "trace_policy_fallback":
            debug["predicted_reason"] = "trace_policy_fallback"
        else:
            debug["predicted_reason"] = "observed_path"
        return "SDC", debug
    if cls_reason == "trace_policy_fallback":
        debug["predicted_reason"] = "trace_policy_fallback"
    elif cls_reason == "trace_semantic":
        debug["predicted_reason"] = "trace_semantic"
    else:
        debug["predicted_reason"] = "observed_path"
    return "Masked", debug


def classify_trials(args: argparse.Namespace) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    analyzer = load_analyzer_for_point_classification(args.analyzer_output)
    by_uid, by_name, reg_to_uids = esc.build_analyzer_indexes(analyzer)
    reads, writes = esc.parse_regfile_accesses(args.regfile_trace)
    active_threads_by_cycle = esc.load_active_threads_log(args.active_threads_log)

    cycles_domain = load_cycles_domain(args.cycles)
    register_labels = esc.parse_register_list(str(args.registers))
    register_label_set = set(register_labels)
    label_to_uids: Dict[str, List[int]] = {
        label: sorted(int(u) for u in reg_to_uids.get(label, set())) for label in register_labels
    }

    points = load_injection_points(args.fi_injection_points)

    fi_outcomes: Dict[int, Dict[str, str]] = {}
    if args.fi_outcomes is not None and args.fi_outcomes.exists():
        fi_outcomes = load_fi_outcomes(args.fi_outcomes)

    semantic_oracle_reasons: Set[str] = set()
    semantic_oracle_enabled = bool(args.semantic_oracle_enable)
    if semantic_oracle_enabled:
        semantic_oracle_reasons = parse_reason_set(args.semantic_oracle_reasons)
        if not semantic_oracle_reasons:
            semantic_oracle_reasons = {"observed_path"}

    output_spec_rows = load_output_spec(args.output_spec if semantic_oracle_enabled else None)
    tol_policy: Dict[str, Any] = {}
    timeout_statuses = set(parse_int_list(args.output_oracle_timeout_exit_statuses))
    if not timeout_statuses:
        timeout_statuses = {124, 137}

    semantic_oracle_db = load_semantic_oracle_db(
        args.semantic_oracle_db if semantic_oracle_enabled else None
    )
    semantic_oracle_stats: Dict[str, Any] = {
        "enabled": bool(semantic_oracle_enabled),
        "queries": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "applied": 0,
        "changed": 0,
        "infra_errors": 0,
        "reason_counts": Counter(),
        "transition_counts": Counter(),
        "infra_error_reason_counts": Counter(),
        "samples": [],
        "output_spec_count": int(len(output_spec_rows)),
    }

    resolve_read_record = make_resolver(by_uid, by_name)

    rows: List[Dict[str, Any]] = []
    for point in points:
        trial = parse_int_maybe(point.get("trial"), 0)
        cycle = parse_int_maybe(point.get("cycle"), -1)
        logged_active_size = parse_int_maybe(point.get("active_threads_size"), -1)
        thread_rand = parse_int_maybe(point.get("thread_rand"), -1)
        chosen_thread_uid_logged = parse_int_maybe(point.get("chosen_thread_uid"), -1)
        reg = str(point.get("reg", "")).strip()
        bit = parse_bit_field(point.get("bit"))
        datatype_bits = parse_int_maybe(point.get("datatype_bits"), 0)
        seed = str(point.get("seed", "")).strip()

        expected_ids = tuple(active_threads_by_cycle.get(int(cycle), ())) if cycle is not None else tuple()
        expected_active_size = len(expected_ids)
        expected_chosen_thread_uid = -1
        if expected_active_size > 0 and thread_rand is not None and thread_rand >= 0:
            expected_chosen_thread_uid = int(expected_ids[thread_rand % expected_active_size])

        effective_thread_uid = chosen_thread_uid_logged if chosen_thread_uid_logged is not None else -1
        if effective_thread_uid is None or effective_thread_uid < 0:
            effective_thread_uid = expected_chosen_thread_uid

        provided_reg_uids = parse_uid_list(point.get("reg_uid"))
        mapped_reg_uids = label_to_uids.get(reg, [])
        effective_reg_uids = provided_reg_uids if provided_reg_uids else mapped_reg_uids

        parameter_differences: List[str] = []
        cycle_in_cycles = cycle in cycles_domain
        cycle_in_active_log = cycle in active_threads_by_cycle
        if not cycle_in_cycles or not cycle_in_active_log:
            parameter_differences.append("cycle_mapping")

        active_size_match = (
            logged_active_size == expected_active_size if logged_active_size is not None and logged_active_size >= 0 else None
        )
        if active_size_match is False and "cycle_mapping" not in parameter_differences:
            parameter_differences.append("cycle_mapping")
        chosen_thread_match = (
            chosen_thread_uid_logged == expected_chosen_thread_uid
            if chosen_thread_uid_logged is not None and chosen_thread_uid_logged >= 0 and expected_chosen_thread_uid >= 0
            else (False if expected_chosen_thread_uid >= 0 else None)
        )
        if chosen_thread_match is False:
            parameter_differences.append("thread_uid_mapping")

        reg_in_register_domain = reg in register_label_set
        reg_has_analyzer_uid = len(mapped_reg_uids) > 0
        reg_uid_match = None
        if provided_reg_uids:
            reg_uid_match = set(provided_reg_uids).issubset(set(mapped_reg_uids))
        if (not reg_in_register_domain) or (not reg_has_analyzer_uid) or (reg_uid_match is False):
            parameter_differences.append("reg_naming")

        bit_in_range = (
            bit is not None
            and datatype_bits is not None
            and datatype_bits > 0
            and 1 <= bit <= datatype_bits
        )
        if bit_in_range is False:
            parameter_differences.append("bit_indexing")

        if bit is None:
            predicted = "Masked"
            pred_debug = {
                "reason": "missing_bit",
                "predicted_reason": "observed_path",
                "consumer_inst_pc": "",
                "consumer_inst_opcode": "",
                "observed_mask": f"0x{0:016x}",
                "trace_expanding_mask": f"0x{0:016x}",
                "semantic_sdc_mask": f"0x{0:016x}",
                "semantic_masked_mask": f"0x{0:016x}",
                "semantic_due_mask": f"0x{0:016x}",
                "predicted_due_reason": "",
                "predicted_due_detail": "",
            }
        else:
            predicted, pred_debug = predict_point(
                cycle=int(cycle),
                thread_uid=int(effective_thread_uid),
                reg_label=reg,
                reg_uids=effective_reg_uids,
                bit_1based=int(bit),
                reads=reads,
                writes=writes,
                resolve_read_record=resolve_read_record,
            )

        fi_info = fi_outcomes.get(int(trial), {})
        predicted_outcome_base = predicted
        predicted_reason_base = str(pred_debug.get("predicted_reason", "")).strip()
        predicted_outcome_final = predicted_outcome_base
        predicted_reason_final = predicted_reason_base
        predicted_before_semantic_oracle = predicted_outcome_base
        predicted_reason_before_semantic_oracle = predicted_reason_base
        semantic_oracle_applied = False
        semantic_oracle_result: Dict[str, Any] = {}
        if (
            semantic_oracle_enabled
            and fi_info
            and predicted_reason_before_semantic_oracle.lower() in semantic_oracle_reasons
        ):
            semantic_oracle_result = semantic_oracle_oracle_for_trial(
                trial=int(trial),
                fi_info=fi_info,
                fi_run_log_prefix=args.fi_run_log_prefix,
                fi_run_log_root=args.fi_run_log_root,
                golden_log=args.golden_log,
                output_spec_rows=output_spec_rows,
                tol_policy=tol_policy,
                timeout_statuses=timeout_statuses,
                semantic_db=semantic_oracle_db,
                semantic_stats=semantic_oracle_stats,
            )
            if bool(semantic_oracle_result.get("ok", False)):
                semantic_oracle_applied = True
                semantic_oracle_stats["applied"] = int(semantic_oracle_stats.get("applied", 0)) + 1
                reason_counts: Counter = semantic_oracle_stats.setdefault(
                    "reason_counts", Counter()
                )
                reason_counts.update([predicted_reason_before_semantic_oracle])
                semantic_cls = str(semantic_oracle_result.get("classification", "")).strip()
                if semantic_cls in CLASS_LABELS:
                    predicted_outcome_final = semantic_cls
                predicted_reason_final = "semantic_oracle"
                pred_debug["predicted_reason"] = predicted_reason_final
                pred_debug["semantic_oracle_source_reason"] = predicted_reason_before_semantic_oracle
                pred_debug["semantic_oracle_applied"] = True
                pred_debug["semantic_oracle_cache_hit"] = bool(
                    semantic_oracle_result.get("cache_hit", False)
                )
                pred_debug["semantic_oracle_run_log"] = str(
                    semantic_oracle_result.get("run_log", "")
                )
                pred_debug["semantic_oracle_oracle_reason"] = str(
                    semantic_oracle_result.get("oracle_reason", "")
                )
                pred_debug["semantic_oracle_cache_key"] = str(
                    semantic_oracle_result.get("cache_key", "")
                )
                if predicted_outcome_final != predicted_before_semantic_oracle:
                    semantic_oracle_stats["changed"] = int(
                        semantic_oracle_stats.get("changed", 0)
                    ) + 1
                    transition_key = (
                        f"{predicted_reason_before_semantic_oracle}:"
                        f"{predicted_before_semantic_oracle}->{predicted_outcome_final}"
                    )
                    transitions: Counter = semantic_oracle_stats.setdefault(
                        "transition_counts", Counter()
                    )
                    transitions.update([transition_key])
                    samples = semantic_oracle_stats.setdefault("samples", [])
                    if isinstance(samples, list) and len(samples) < 30:
                        samples.append(
                            {
                                "trial": int(trial),
                                "cycle": int(cycle),
                                "reg": str(reg),
                                "bit": int(bit) if bit is not None else -1,
                                "from": predicted_before_semantic_oracle,
                                "to": predicted_outcome_final,
                                "source_reason": predicted_reason_before_semantic_oracle,
                                "oracle_reason": str(
                                    semantic_oracle_result.get("oracle_reason", "")
                                ),
                                "run_log": str(
                                    semantic_oracle_result.get("run_log", "")
                                ),
                                "cache_hit": bool(
                                    semantic_oracle_result.get("cache_hit", False)
                                ),
                            }
                        )
            else:
                pred_debug["semantic_oracle_applied"] = False
                pred_debug["semantic_oracle_infra_error"] = bool(
                    semantic_oracle_result.get("infra_error", False)
                )
                pred_debug["semantic_oracle_error_reason"] = str(
                    semantic_oracle_result.get("error_reason", "")
                )
                pred_debug["semantic_oracle_run_log"] = str(
                    semantic_oracle_result.get("run_log", "")
                )
        fi_outcome = normalize_outcome(fi_info.get("fi_outcome", ""))
        fi_due_reason = str(fi_info.get("due_reason", "")).strip()
        predicted_due_reason = str(pred_debug.get("predicted_due_reason", "")).strip()
        predicted_due_detail = str(pred_debug.get("predicted_due_detail", "")).strip()

        due_reason = fi_due_reason
        due_detail = ""
        if predicted_outcome_base == "DUE":
            if not due_reason:
                due_reason = predicted_due_reason or "predicted_due"
            due_detail = predicted_due_detail or due_reason

        is_match_base: Optional[bool]
        is_match_final: Optional[bool]
        if fi_outcome in CLASS_LABELS:
            is_match_base = fi_outcome == predicted_outcome_base
            is_match_final = fi_outcome == predicted_outcome_final
        else:
            is_match_base = None
            is_match_final = None

        primary_cause = parameter_differences[0] if parameter_differences else "other"

        row = {
            "trial": int(trial),
            "component": "rf",
            "source_component": str(point.get("component", "")).strip(),
            "cycle": int(cycle),
            "active_threads_size": str(point.get("active_threads_size", "")).strip(),
            "thread_rand": int(thread_rand) if thread_rand is not None else -1,
            "seed": seed,
            "reg": reg,
            "reg_uid": str(point.get("reg_uid", "")).strip(),
            "bit": int(bit) if bit is not None else -1,
            "datatype_bits": int(datatype_bits) if datatype_bits is not None else 0,
            "per_warp": str(point.get("per_warp", "")).strip(),
            "kernel": str(point.get("kernel", "")).strip(),
            "warp_rand": str(point.get("warp_rand", "")).strip(),
            "block_rand": str(point.get("block_rand", "")).strip(),
            "local_bits": str(point.get("local_bits", "")).strip(),
            "shared_bits": str(point.get("shared_bits", "")).strip(),
            "l1d_shader": str(point.get("l1d_shader", "")).strip(),
            "l1d_bits": str(point.get("l1d_bits", "")).strip(),
            "l1c_shader": str(point.get("l1c_shader", "")).strip(),
            "l1c_bits": str(point.get("l1c_bits", "")).strip(),
            "l1t_shader": str(point.get("l1t_shader", "")).strip(),
            "l1t_bits": str(point.get("l1t_bits", "")).strip(),
            "l2_bits": str(point.get("l2_bits", "")).strip(),
            "gmem_byte_seed": str(point.get("gmem_byte_seed", "")).strip(),
            "gmem_target_addr": str(point.get("gmem_target_addr", "")).strip(),
            "logged_active_threads_size": int(logged_active_size) if logged_active_size is not None else -1,
            "expected_active_threads_size": int(expected_active_size),
            "active_threads_size_match": active_size_match,
            "chosen_thread_uid": int(chosen_thread_uid_logged) if chosen_thread_uid_logged is not None else -1,
            "expected_chosen_thread_uid": int(expected_chosen_thread_uid),
            "chosen_thread_uid_match": chosen_thread_match,
            "effective_thread_uid": int(effective_thread_uid),
            "reg_uid_logged": ":".join(str(x) for x in provided_reg_uids),
            "reg_uid_mapped": ":".join(str(x) for x in mapped_reg_uids),
            "reg_uid_effective": ":".join(str(x) for x in effective_reg_uids),
            "reg_in_register_domain": reg_in_register_domain,
            "reg_has_analyzer_uid": reg_has_analyzer_uid,
            "reg_uid_match": reg_uid_match,
            "bit_in_range": bit_in_range,
            "fi_outcome": fi_outcome,
            "fi_due_reason": fi_due_reason,
            "due_reason": due_reason,
            "due_detail": due_detail,
            "predicted_due_reason": predicted_due_reason,
            "predicted_due_detail": predicted_due_detail,
            "predicted_outcome": predicted_outcome_base,
            "predicted_reason": predicted_reason_base,
            "predicted_outcome_base": predicted_outcome_base,
            "predicted_outcome_final": predicted_outcome_final,
            "predicted_reason_base": predicted_reason_base,
            "predicted_reason_final": predicted_reason_final,
            "semantic_oracle_applied": bool(pred_debug.get("semantic_oracle_applied", False)),
            "semantic_oracle_source_reason": str(
                pred_debug.get("semantic_oracle_source_reason", "")
            ),
            "semantic_oracle_oracle_reason": str(
                pred_debug.get("semantic_oracle_oracle_reason", "")
            ),
            "semantic_oracle_run_log": str(pred_debug.get("semantic_oracle_run_log", "")),
            "semantic_oracle_error_reason": str(
                pred_debug.get("semantic_oracle_error_reason", "")
            ),
            "consumer_inst_pc": str(pred_debug.get("consumer_inst_pc", "")),
            "consumer_inst_opcode": str(pred_debug.get("consumer_inst_opcode", "")),
            "observed_mask": str(pred_debug.get("observed_mask", "0x0000000000000000")),
            "trace_expanding_mask": str(
                pred_debug.get("trace_expanding_mask", "0x0000000000000000")
            ),
            "semantic_sdc_mask": str(pred_debug.get("semantic_sdc_mask", "0x0000000000000000")),
            "semantic_masked_mask": str(
                pred_debug.get("semantic_masked_mask", "0x0000000000000000")
            ),
            "semantic_due_mask": str(pred_debug.get("semantic_due_mask", "0x0000000000000000")),
            "is_match": is_match_base,
            "is_match_base": is_match_base,
            "is_match_final": is_match_final,
            "parameter_differences": parameter_differences,
            "primary_mismatch_cause": primary_cause,
            "cycle_in_cycles_file": cycle_in_cycles,
            "cycle_in_active_threads_log": cycle_in_active_log,
            "prediction_debug": pred_debug,
        }
        rows.append(row)

    rows.sort(key=lambda r: int(r["trial"]))

    def collect_stats(
        *,
        outcome_key: str,
        reason_key: str,
    ) -> Dict[str, Any]:
        cm: Dict[str, Dict[str, int]] = {
            actual: {pred: 0 for pred in CLASS_LABELS} for actual in CLASS_LABELS
        }
        compared_trials = 0
        mismatch_count = 0
        mismatching_rows: List[Dict[str, Any]] = []
        cause_counter: Counter = Counter()
        reason_counter: Counter = Counter()
        for row in rows:
            actual = row["fi_outcome"]
            pred = str(row.get(outcome_key, "")).strip()
            if actual in CLASS_LABELS and pred in CLASS_LABELS:
                compared_trials += 1
                cm[actual][pred] += 1
                if actual != pred:
                    mismatch_count += 1
                    mismatching_rows.append(row)
                    diffs = row.get("parameter_differences") or []
                    if diffs:
                        cause_counter.update(diffs)
                    else:
                        cause_counter.update(["other"])
                    reason = str(row.get(reason_key, "")).strip() or "unknown"
                    reason_counter.update([reason])

        for key in ("cycle_mapping", "thread_uid_mapping", "reg_naming", "bit_indexing", "other"):
            cause_counter.setdefault(key, 0)
        for key in (
            "observed_path",
            "semantic_oracle",
            "trace_semantic",
            "trace_policy_fallback",
            "due_oracle",
            "due_static",
            "unknown",
        ):
            reason_counter.setdefault(key, 0)
        return {
            "compared_trials": int(compared_trials),
            "mismatch_count": int(mismatch_count),
            "mismatch_rate": (float(mismatch_count) / float(compared_trials))
            if compared_trials
            else 0.0,
            "confusion_matrix": cm,
            "mismatch_parameter_counts": dict(sorted(cause_counter.items())),
            "mismatch_reason_counts": dict(sorted(reason_counter.items())),
            "top_mismatches": mismatching_rows[: int(args.top_k)],
        }

    base_stats = collect_stats(
        outcome_key="predicted_outcome_base",
        reason_key="predicted_reason_base",
    )
    final_stats = collect_stats(
        outcome_key="predicted_outcome_final",
        reason_key="predicted_reason_final",
    )

    semantic_reason_counts = dict(
        sorted(
            {
                str(k): int(v)
                for k, v in (semantic_oracle_stats.get("reason_counts") or {}).items()
            }.items()
        )
    )
    semantic_transition_counts = dict(
        sorted(
            {
                str(k): int(v)
                for k, v in (semantic_oracle_stats.get("transition_counts") or {}).items()
            }.items()
        )
    )
    semantic_infra_error_counts = dict(
        sorted(
            {
                str(k): int(v)
                for k, v in (
                    semantic_oracle_stats.get("infra_error_reason_counts") or {}
                ).items()
            }.items()
        )
    )
    semantic_oracle_meta = {
        "enabled": bool(semantic_oracle_enabled),
        "reasons": sorted(semantic_oracle_reasons),
        "queries": int(semantic_oracle_stats.get("queries", 0)),
        "cache_hits": int(semantic_oracle_stats.get("cache_hits", 0)),
        "cache_misses": int(semantic_oracle_stats.get("cache_misses", 0)),
        "applied": int(semantic_oracle_stats.get("applied", 0)),
        "changed": int(semantic_oracle_stats.get("changed", 0)),
        "infra_errors": int(semantic_oracle_stats.get("infra_errors", 0)),
        "reason_counts": semantic_reason_counts,
        "transition_counts": semantic_transition_counts,
        "infra_error_reason_counts": semantic_infra_error_counts,
        "samples": list(semantic_oracle_stats.get("samples", [])),
        "db_path": str(args.semantic_oracle_db) if args.semantic_oracle_db else None,
        "fi_run_log_prefix": args.fi_run_log_prefix,
        "fi_run_log_root": args.fi_run_log_root,
        "golden_log": str(args.golden_log) if args.golden_log else None,
        "output_spec": str(args.output_spec) if args.output_spec else None,
        "output_spec_count": int(semantic_oracle_stats.get("output_spec_count", 0)),
    }
    save_semantic_oracle_db(
        args.semantic_oracle_db if semantic_oracle_enabled else None,
        semantic_oracle_db,
    )

    primary_stats = final_stats if semantic_oracle_enabled else base_stats
    primary_basis = "final" if semantic_oracle_enabled else "base"

    report = {
        "total_trials": len(rows),
        "compared_trials": int(primary_stats["compared_trials"]),
        "mismatched_trials": int(primary_stats["mismatch_count"]),
        "mismatch_rate": float(primary_stats["mismatch_rate"]),
        "confusion_matrix": dict(primary_stats["confusion_matrix"]),
        "mismatch_parameter_counts": dict(primary_stats["mismatch_parameter_counts"]),
        "mismatch_reason_counts": dict(primary_stats["mismatch_reason_counts"]),
        "top_mismatches": list(primary_stats["top_mismatches"]),
        "compared_trials_base": int(base_stats["compared_trials"]),
        "compared_trials_final": int(final_stats["compared_trials"]),
        "mismatch_count_base": int(base_stats["mismatch_count"]),
        "mismatch_count_final": int(final_stats["mismatch_count"]),
        "mismatched_trials_base": int(base_stats["mismatch_count"]),
        "mismatched_trials_final": int(final_stats["mismatch_count"]),
        "mismatch_rate_base": float(base_stats["mismatch_rate"]),
        "mismatch_rate_final": float(final_stats["mismatch_rate"]),
        "confusion_matrix_base": dict(base_stats["confusion_matrix"]),
        "confusion_matrix_final": dict(final_stats["confusion_matrix"]),
        "mismatch_parameter_counts_base": dict(base_stats["mismatch_parameter_counts"]),
        "mismatch_parameter_counts_final": dict(final_stats["mismatch_parameter_counts"]),
        "mismatch_reason_counts_base": dict(base_stats["mismatch_reason_counts"]),
        "mismatch_reason_counts_final": dict(final_stats["mismatch_reason_counts"]),
        "top_mismatches_base": list(base_stats["top_mismatches"]),
        "top_mismatches_final": list(final_stats["top_mismatches"]),
        "rows": rows,
        "meta": {
            "analyzer_output": str(args.analyzer_output),
            "regfile_trace": str(args.regfile_trace),
            "active_threads_log": str(args.active_threads_log),
            "cycles": str(args.cycles),
            "registers": str(args.registers),
            "fi_injection_points": str(args.fi_injection_points),
            "fi_outcomes": str(args.fi_outcomes) if args.fi_outcomes is not None else None,
            "consumer_compare": esc.CANONICAL_CONSUMER_COMPARE,
            "rf_fault_model": esc.CANONICAL_RF_FAULT_MODEL,
            "trace_expanding_policy": esc.CANONICAL_TRACE_EXPANDING_POLICY,
            "primary_basis": primary_basis,
            "semantic_oracle": semantic_oracle_meta,
        },
    }
    return rows, report


def write_predicted_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "trial",
        "component",
        "source_component",
        "predicted_outcome",
        "predicted_reason",
        "predicted_outcome_base",
        "predicted_outcome_final",
        "predicted_reason_base",
        "predicted_reason_final",
        "semantic_oracle_applied",
        "semantic_oracle_source_reason",
        "semantic_oracle_oracle_reason",
        "semantic_oracle_run_log",
        "semantic_oracle_error_reason",
        "fi_outcome",
        "is_match",
        "is_match_base",
        "is_match_final",
        "primary_mismatch_cause",
        "parameter_differences",
        "cycle",
        "thread_rand",
        "chosen_thread_uid",
        "active_threads_size",
        "expected_chosen_thread_uid",
        "effective_thread_uid",
        "logged_active_threads_size",
        "expected_active_threads_size",
        "reg",
        "reg_uid",
        "reg_uid_logged",
        "reg_uid_mapped",
        "reg_uid_effective",
        "bit",
        "datatype_bits",
        "per_warp",
        "kernel",
        "warp_rand",
        "block_rand",
        "local_bits",
        "shared_bits",
        "l1d_shader",
        "l1d_bits",
        "l1c_shader",
        "l1c_bits",
        "l1t_shader",
        "l1t_bits",
        "l2_bits",
        "gmem_byte_seed",
        "gmem_target_addr",
        "consumer_inst_pc",
        "consumer_inst_opcode",
        "observed_mask",
        "trace_expanding_mask",
        "semantic_sdc_mask",
        "semantic_masked_mask",
        "semantic_due_mask",
        "predicted_due_reason",
        "predicted_due_detail",
        "fi_due_reason",
        "due_reason",
        "due_detail",
        "seed",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            out = {k: row.get(k, "") for k in fieldnames}
            diffs = row.get("parameter_differences", [])
            out["parameter_differences"] = ":".join(str(x) for x in diffs)
            writer.writerow(out)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Classify exact outcomes for sampled FI points")
    p.add_argument("--analyzer-output", type=Path, required=True)
    p.add_argument("--regfile-trace", type=Path, required=True)
    p.add_argument("--active-threads-log", type=Path, required=True)
    p.add_argument("--cycles", type=Path, required=True)
    p.add_argument("--registers", type=Path, required=True)
    p.add_argument("--fi-injection-points", type=Path, required=True)
    p.add_argument(
        "--fi-outcomes",
        type=Path,
        default=None,
        help="FI outcomes CSV (defaults to sibling fi_outcomes.csv if present)",
    )
    p.add_argument("--top-k", type=int, default=50)
    p.add_argument("--output-predicted", type=Path, required=True)
    p.add_argument("--output-report", type=Path, required=True)
    p.add_argument(
        "--semantic-oracle-enable",
        action="store_true",
        help=(
            "In compare_fi mode, confirm selected predicted reasons using FI-log oracle "
            "and cache results into semantic-oracle DB."
        ),
    )
    p.add_argument(
        "--semantic-oracle-reasons",
        type=str,
        default="observed_path",
        help="colon/comma list of predicted reasons to semantic-confirm (default: observed_path)",
    )
    p.add_argument(
        "--semantic-oracle-db",
        type=Path,
        default=None,
        help="JSON DB cache for semantic-oracle confirmations",
    )
    p.add_argument(
        "--fi-run-log-prefix",
        type=str,
        default=None,
        help=(
            "Prefix used by campaign_exec TMP_DIR (run log path is built as "
            "<prefix><run_batch>/<tmp_file>)"
        ),
    )
    p.add_argument(
        "--fi-run-log-root",
        type=str,
        default=None,
        help="Optional root directory fallback to locate run logs by run_batch/tmp_file",
    )
    p.add_argument(
        "--golden-log",
        type=Path,
        default=None,
        help="Golden log used by semantic-oracle output checks",
    )
    p.add_argument(
        "--output-spec",
        type=Path,
        default=None,
        help="Output spec JSON used by semantic-oracle output checks",
    )
    p.add_argument(
        "--output-oracle-timeout-exit-statuses",
        type=str,
        default="124:137",
        help="colon/comma list of timeout-like exit statuses",
    )
    return p


def main() -> int:
    args = build_arg_parser().parse_args()

    if args.fi_outcomes is None:
        candidate = args.fi_injection_points.with_name("fi_outcomes.csv")
        if candidate.exists():
            args.fi_outcomes = candidate

    rows, report = classify_trials(args)
    write_predicted_csv(rows, args.output_predicted)
    args.output_report.parent.mkdir(parents=True, exist_ok=True)
    args.output_report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
