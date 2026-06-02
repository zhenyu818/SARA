#!/usr/bin/env python3
"""Lightweight ctypes bridge for exact C++ storage-analysis helpers."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import List, Optional, Sequence


_SARA_DIR = Path(__file__).resolve().parent
_DEFAULT_LIB = _SARA_DIR / "native" / "libexact_storage_backend.so"
_ENV_LIB = os.environ.get("EXACT_CPP_BACKEND_LIB", "").strip()

_OP_TO_CODE = {
    "ADD": 0,
    "ADD_F32": 1,
    "SUB": 2,
    "SUB_F32": 3,
    "NEG": 4,
    "NEG_F32": 5,
    "MUL_LO": 6,
    "MUL_F32": 7,
    "MUL_WIDE_U32": 8,
    "MUL_WIDE_S32": 9,
    "MAD": 10,
    "FMA_F32": 11,
    "DIV_F32": 12,
    "SQRT_F32": 13,
    "ABS_F32": 14,
    "EX2_APPROX_FTZ_F32": 15,
    "RCP_APPROX_FTZ_F32": 16,
    "MIN_F32": 17,
    "MAX_F32": 18,
    "IDENTITY": 19,
    "NOT": 20,
    "NOT_PRED": 21,
    "AND": 22,
    "OR": 23,
    "XOR": 24,
    "SHL": 25,
    "SHR_U": 26,
    "SHR_S": 27,
    "MIN_U": 28,
    "MIN_S": 29,
    "MAX_U": 30,
    "MAX_S": 31,
    "CVT_U32_U64": 32,
    "CVT_U64_U32": 33,
    "CVT_S32_S64": 34,
    "CVT_S64_S32": 35,
    "CVT_SAT_F32_F32": 36,
    "SETP_EQ": 37,
    "SETP_NE": 38,
    "SETP_LT_U": 39,
    "SETP_LT_S": 40,
    "SETP_LE_U": 41,
    "SETP_LE_S": 42,
    "SETP_GT_U": 43,
    "SETP_GT_S": 44,
    "SETP_GE_U": 45,
    "SETP_GE_S": 46,
    "SELP": 47,
}

_TRACE_POLICY_TO_CODE = {
    "masked": 0,
    "sdc": 1,
}

_TRACE_UNCOVERED_MODE_TO_CODE = {
    "legacy_unknown": 0,
    "policy": 1,
}

_TRACE_SEMANTIC_MASKED_MODE_TO_CODE = {
    "legacy": 0,
    "policy_overrides_masked": 1,
}


class _ExactInfluenceRequest(ctypes.Structure):
    _fields_ = [
        ("op_code", ctypes.c_int),
        ("width_bits", ctypes.c_int),
        ("signed_mode", ctypes.c_int),
        ("src_count", ctypes.c_int),
        ("src_vals", ctypes.c_uint64 * 3),
        ("dst_val", ctypes.c_uint64),
        ("dst_observed_mask", ctypes.c_uint64),
    ]


class _ExactInfluenceResponse(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("src_masks", ctypes.c_uint64 * 3),
    ]


class _ExactMaskClassifyRequest(ctypes.Structure):
    _fields_ = [
        ("width_bits", ctypes.c_int),
        ("trace_policy_code", ctypes.c_int),
        ("trace_uncovered_mode_code", ctypes.c_int),
        ("trace_semantic_masked_mode_code", ctypes.c_int),
        ("observed_mask", ctypes.c_uint64),
        ("due_mask", ctypes.c_uint64),
        ("trace_mask", ctypes.c_uint64),
        ("semantic_masked_mask", ctypes.c_uint64),
        ("semantic_sdc_mask", ctypes.c_uint64),
        ("semantic_due_mask", ctypes.c_uint64),
        ("semantic_infra_mask", ctypes.c_uint64),
        ("semantic_unknown_mask", ctypes.c_uint64),
    ]


class _ExactMaskClassifyResponse(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("due_mask", ctypes.c_uint64),
        ("sdc_mask", ctypes.c_uint64),
        ("unknown_mask", ctypes.c_uint64),
        ("policy_added_sdc_mask", ctypes.c_uint64),
        ("policy_used_mask", ctypes.c_uint64),
        ("trace_mask", ctypes.c_uint64),
        ("policy_override_mask", ctypes.c_uint64),
    ]


class _ExactSiteMaskClassifyResponse(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("due_mask", ctypes.c_uint64),
        ("sdc_mask", ctypes.c_uint64),
        ("unknown_mask", ctypes.c_uint64),
        ("policy_used_mask", ctypes.c_uint64),
        ("policy_override_mask", ctypes.c_uint64),
    ]


class _ExactControlTaintEventDesc(ctypes.Structure):
    _fields_ = [
        ("kind_id", ctypes.c_int64),
        ("opcode_id", ctypes.c_int64),
        ("pc_id", ctypes.c_int64),
        ("dst_reg_id", ctypes.c_int64),
        ("width_bits", ctypes.c_int64),
        ("src_reg_offset", ctypes.c_uint32),
        ("src_reg_count", ctypes.c_uint32),
        ("src_width_offset", ctypes.c_uint32),
        ("src_width_count", ctypes.c_uint32),
        ("src_val_offset", ctypes.c_uint32),
        ("src_val_count", ctypes.c_uint32),
        ("branch_flag", ctypes.c_uint8),
        ("base_taken", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
    ]


class _ExactControlTaintDigest(ctypes.Structure):
    _fields_ = [
        ("lo", ctypes.c_uint64),
        ("hi", ctypes.c_uint64),
    ]


class _ExactControlTaintThreadBatchDesc(ctypes.Structure):
    _fields_ = [
        ("event_offset", ctypes.c_uint32),
        ("event_count", ctypes.c_uint32),
    ]


class _ExactThreadCycleWeightEntry(ctypes.Structure):
    _fields_ = [
        ("thread_id", ctypes.c_int64),
        ("cycle", ctypes.c_int64),
        ("weight", ctypes.c_int64),
    ]


class _ExactToleranceStepDesc(ctypes.Structure):
    _fields_ = [
        ("op_code", ctypes.c_int),
        ("width_bits_default", ctypes.c_int),
        ("tracked_src_index", ctypes.c_int),
        ("src_val_offset", ctypes.c_uint32),
        ("src_val_count", ctypes.c_uint32),
    ]


class _ExactTolerancePathDesc(ctypes.Structure):
    _fields_ = [
        ("final_width_bits", ctypes.c_int),
        ("step_offset", ctypes.c_uint32),
        ("step_count", ctypes.c_uint32),
    ]


class _ExactToleranceEvalRequest(ctypes.Structure):
    _fields_ = [
        ("path_index", ctypes.c_uint32),
        ("current_value", ctypes.c_uint64),
    ]


class _ExactToleranceEvalResponse(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("final_bits", ctypes.c_uint64),
    ]


class _ExactRfIntervalRequest(ctypes.Structure):
    _fields_ = [
        ("mass", ctypes.c_int64),
        ("bit_count", ctypes.c_int32),
        ("legacy_unknown_trace_uncovered", ctypes.c_uint8),
        ("selected_mask", ctypes.c_uint64),
        ("due_mask", ctypes.c_uint64),
        ("sdc_mask", ctypes.c_uint64),
        ("unknown_mask", ctypes.c_uint64),
        ("trace_added_sdc_mask", ctypes.c_uint64),
        ("trace_policy_used_mask", ctypes.c_uint64),
        ("trace_policy_override_mask", ctypes.c_uint64),
        ("trace_mask", ctypes.c_uint64),
        ("semantic_due_mask", ctypes.c_uint64),
        ("addr_due_mask", ctypes.c_uint64),
        ("addr_sdc_mask", ctypes.c_uint64),
        ("addr_unknown_mask", ctypes.c_uint64),
        ("addr_trace_div_mask", ctypes.c_uint64),
    ]


class _ExactRfIntervalAccum(ctypes.Structure):
    _fields_ = [
        ("masked_num", ctypes.c_int64),
        ("sdc_num", ctypes.c_int64),
        ("due_num", ctypes.c_int64),
        ("unknown_num", ctypes.c_int64),
        ("semantic_due_mass", ctypes.c_int64),
        ("addr_due_num", ctypes.c_int64),
        ("addr_sdc_num", ctypes.c_int64),
        ("addr_unknown_num", ctypes.c_int64),
        ("addr_oob_due_mass", ctypes.c_int64),
        ("trace_divergence_due_mass", ctypes.c_int64),
        ("addr_alias_sdc_mass", ctypes.c_int64),
        ("trace_divergence_sdc_mass", ctypes.c_int64),
        ("trace_expanding_sdc_numerator", ctypes.c_int64),
        ("trace_policy_used_bits", ctypes.c_int64),
        ("trace_policy_used_mass", ctypes.c_int64),
        ("trace_policy_override_bits", ctypes.c_int64),
        ("trace_policy_override_mass", ctypes.c_int64),
        ("trace_policy_override_sdc_bits", ctypes.c_int64),
        ("trace_policy_override_due_bits", ctypes.c_int64),
        ("trace_policy_override_unknown_bits", ctypes.c_int64),
        ("trace_policy_override_masked_bits", ctypes.c_int64),
        ("trace_uncovered_unknown_bits", ctypes.c_int64),
        ("trace_uncovered_unknown_mass", ctypes.c_int64),
        ("saw_trace_selected_bits", ctypes.c_uint8),
    ]


class ExactCppBackend:
    def __init__(self, lib_path: Path) -> None:
        self.lib_path = lib_path
        self._lib = ctypes.CDLL(str(lib_path))
        self._has_tolerance_path_eval = hasattr(
            self._lib, "exact_evaluate_tolerance_paths_many"
        )
        self._has_rf_interval_accumulate = hasattr(
            self._lib, "exact_rf_interval_accumulate_many"
        )
        self._lib.exact_backward_influence_one.argtypes = [
            ctypes.POINTER(_ExactInfluenceRequest),
            ctypes.POINTER(_ExactInfluenceResponse),
        ]
        self._lib.exact_backward_influence_one.restype = ctypes.c_int
        self._lib.exact_backward_influence_many.argtypes = [
            ctypes.POINTER(_ExactInfluenceRequest),
            ctypes.c_size_t,
            ctypes.POINTER(_ExactInfluenceResponse),
        ]
        self._lib.exact_backward_influence_many.restype = ctypes.c_size_t
        self._lib.exact_classify_read_masks_one.argtypes = [
            ctypes.POINTER(_ExactMaskClassifyRequest),
            ctypes.POINTER(_ExactMaskClassifyResponse),
        ]
        self._lib.exact_classify_read_masks_one.restype = ctypes.c_int
        self._lib.exact_classify_read_masks_many.argtypes = [
            ctypes.POINTER(_ExactMaskClassifyRequest),
            ctypes.c_size_t,
            ctypes.POINTER(_ExactMaskClassifyResponse),
        ]
        self._lib.exact_classify_read_masks_many.restype = ctypes.c_size_t
        self._lib.exact_classify_site_masks_one.argtypes = [
            ctypes.POINTER(_ExactMaskClassifyRequest),
            ctypes.POINTER(_ExactSiteMaskClassifyResponse),
        ]
        self._lib.exact_classify_site_masks_one.restype = ctypes.c_int
        self._lib.exact_classify_site_masks_many.argtypes = [
            ctypes.POINTER(_ExactMaskClassifyRequest),
            ctypes.c_size_t,
            ctypes.POINTER(_ExactSiteMaskClassifyResponse),
        ]
        self._lib.exact_classify_site_masks_many.restype = ctypes.c_size_t
        self._lib.exact_control_taint_thread_hashes.argtypes = [
            ctypes.POINTER(_ExactControlTaintEventDesc),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
            ctypes.POINTER(_ExactControlTaintDigest),
            ctypes.POINTER(_ExactControlTaintDigest),
        ]
        self._lib.exact_control_taint_thread_hashes.restype = ctypes.c_int
        self._lib.exact_control_taint_thread_hashes_many.argtypes = [
            ctypes.POINTER(_ExactControlTaintThreadBatchDesc),
            ctypes.c_size_t,
            ctypes.POINTER(_ExactControlTaintEventDesc),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
            ctypes.POINTER(_ExactControlTaintDigest),
            ctypes.POINTER(_ExactControlTaintDigest),
        ]
        self._lib.exact_control_taint_thread_hashes_many.restype = ctypes.c_size_t
        self._lib.exact_thread_cycle_weights.argtypes = [
            ctypes.POINTER(ctypes.c_int64),
            ctypes.POINTER(ctypes.c_int64),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_size_t,
            ctypes.c_int64,
            ctypes.POINTER(_ExactThreadCycleWeightEntry),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.POINTER(ctypes.c_int64),
            ctypes.POINTER(ctypes.c_int64),
        ]
        self._lib.exact_thread_cycle_weights.restype = ctypes.c_size_t
        if self._has_tolerance_path_eval:
            self._lib.exact_evaluate_tolerance_paths_many.argtypes = [
                ctypes.POINTER(_ExactToleranceStepDesc),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint64),
                ctypes.c_size_t,
                ctypes.POINTER(_ExactTolerancePathDesc),
                ctypes.c_size_t,
                ctypes.POINTER(_ExactToleranceEvalRequest),
                ctypes.c_size_t,
                ctypes.POINTER(_ExactToleranceEvalResponse),
            ]
            self._lib.exact_evaluate_tolerance_paths_many.restype = ctypes.c_size_t
        if self._has_rf_interval_accumulate:
            self._lib.exact_rf_interval_accumulate_many.argtypes = [
                ctypes.POINTER(_ExactRfIntervalRequest),
                ctypes.c_size_t,
                ctypes.POINTER(_ExactRfIntervalAccum),
            ]
            self._lib.exact_rf_interval_accumulate_many.restype = ctypes.c_int

    def _build_control_taint_arrays(
        self,
        threads: Sequence[Sequence[dict]],
    ) -> tuple[
        ctypes.Array,
        ctypes.Array,
        ctypes.Array,
        ctypes.Array,
        ctypes.Array,
        int,
        int,
        int,
        int,
        int,
    ]:
        total_events = sum(len(thread) for thread in threads)
        thread_arr = (_ExactControlTaintThreadBatchDesc * max(1, len(threads)))()
        ev_arr = (_ExactControlTaintEventDesc * max(1, total_events))()
        flat_src_reg_ids: List[int] = []
        flat_src_width_bits: List[int] = []
        flat_src_vals: List[int] = []
        event_idx = 0
        for thread_idx, thread in enumerate(threads):
            thread_arr[thread_idx].event_offset = event_idx
            thread_arr[thread_idx].event_count = len(thread)
            for payload in thread:
                ev = _ExactControlTaintEventDesc()
                ev.kind_id = int(payload.get("kind_id", 0))
                ev.opcode_id = int(payload.get("opcode_id", 0))
                ev.pc_id = int(payload.get("pc_id", 0))
                ev.dst_reg_id = int(payload.get("dst_reg_id", 0))
                ev.width_bits = int(payload.get("width_bits", 0))
                src_reg_ids = [int(v) for v in payload.get("src_reg_ids", ())]
                src_width_bits = [int(v) for v in payload.get("src_width_bits", ())]
                src_vals = [
                    ctypes.c_uint64(int(v)).value for v in payload.get("src_vals", ())
                ]
                ev.src_reg_offset = len(flat_src_reg_ids)
                ev.src_reg_count = len(src_reg_ids)
                ev.src_width_offset = len(flat_src_width_bits)
                ev.src_width_count = len(src_width_bits)
                ev.src_val_offset = len(flat_src_vals)
                ev.src_val_count = len(src_vals)
                ev.branch_flag = 1 if payload.get("branch_flag") else 0
                ev.base_taken = 1 if payload.get("base_taken") else 0
                ev.reserved = 0
                flat_src_reg_ids.extend(src_reg_ids)
                flat_src_width_bits.extend(src_width_bits)
                flat_src_vals.extend(src_vals)
                ev_arr[event_idx] = ev
                event_idx += 1

        src_reg_arr = (ctypes.c_int64 * max(1, len(flat_src_reg_ids)))()
        for idx, value in enumerate(flat_src_reg_ids):
            src_reg_arr[idx] = int(value)
        src_width_arr = (ctypes.c_int64 * max(1, len(flat_src_width_bits)))()
        for idx, value in enumerate(flat_src_width_bits):
            src_width_arr[idx] = int(value)
        src_val_arr = (ctypes.c_uint64 * max(1, len(flat_src_vals)))()
        for idx, value in enumerate(flat_src_vals):
            src_val_arr[idx] = ctypes.c_uint64(int(value)).value
        return (
            thread_arr,
            ev_arr,
            src_reg_arr,
            src_width_arr,
            src_val_arr,
            len(threads),
            total_events,
            len(flat_src_reg_ids),
            len(flat_src_width_bits),
            len(flat_src_vals),
        )

    def _build_mask_request(
        self,
        *,
        width_bits: int,
        observed_mask: int,
        due_mask: int,
        trace_mask: int,
        semantic_masked_mask: int,
        semantic_sdc_mask: int,
        semantic_due_mask: int,
        semantic_infra_mask: int,
        semantic_unknown_mask: int,
        trace_expanding_policy: str,
        trace_uncovered_mode: str,
        trace_expanding_semantic_masked_mode: str,
    ) -> Optional[_ExactMaskClassifyRequest]:
        req = _ExactMaskClassifyRequest()
        req.width_bits = int(width_bits)
        req.trace_policy_code = _TRACE_POLICY_TO_CODE.get(str(trace_expanding_policy), -1)
        req.trace_uncovered_mode_code = _TRACE_UNCOVERED_MODE_TO_CODE.get(
            str(trace_uncovered_mode), -1
        )
        req.trace_semantic_masked_mode_code = _TRACE_SEMANTIC_MASKED_MODE_TO_CODE.get(
            str(trace_expanding_semantic_masked_mode), -1
        )
        if (
            req.trace_policy_code < 0
            or req.trace_uncovered_mode_code < 0
            or req.trace_semantic_masked_mode_code < 0
        ):
            return None
        req.observed_mask = ctypes.c_uint64(int(observed_mask)).value
        req.due_mask = ctypes.c_uint64(int(due_mask)).value
        req.trace_mask = ctypes.c_uint64(int(trace_mask)).value
        req.semantic_masked_mask = ctypes.c_uint64(int(semantic_masked_mask)).value
        req.semantic_sdc_mask = ctypes.c_uint64(int(semantic_sdc_mask)).value
        req.semantic_due_mask = ctypes.c_uint64(int(semantic_due_mask)).value
        req.semantic_infra_mask = ctypes.c_uint64(int(semantic_infra_mask)).value
        req.semantic_unknown_mask = ctypes.c_uint64(int(semantic_unknown_mask)).value
        return req

    def backward_influence(
        self,
        *,
        op: str,
        src_vals: Sequence[int],
        dst_val: int,
        dst_observed_mask: int,
        width_bits: int,
        signed_mode: bool = False,
    ) -> Optional[List[int]]:
        op_code = _OP_TO_CODE.get(str(op))
        if op_code is None:
            return None
        if len(src_vals) > 3:
            return None

        req = _ExactInfluenceRequest()
        req.op_code = int(op_code)
        req.width_bits = int(width_bits)
        req.signed_mode = 1 if signed_mode else 0
        req.src_count = int(len(src_vals))
        for idx in range(3):
            req.src_vals[idx] = 0
        for idx, value in enumerate(src_vals):
            req.src_vals[idx] = ctypes.c_uint64(int(value)).value
        req.dst_val = ctypes.c_uint64(int(dst_val)).value
        req.dst_observed_mask = ctypes.c_uint64(int(dst_observed_mask)).value

        resp = _ExactInfluenceResponse()
        rc = int(
            self._lib.exact_backward_influence_one(
                ctypes.byref(req), ctypes.byref(resp)
            )
        )
        if rc != 0 or int(resp.status) != 0:
            return None
        return [int(resp.src_masks[i]) for i in range(int(req.src_count))]

    def backward_influence_many(
        self,
        requests: Sequence[dict],
    ) -> Optional[List[List[int]]]:
        if not requests:
            return []
        req_arr = (_ExactInfluenceRequest * len(requests))()
        expected_counts: List[int] = []
        for idx, payload in enumerate(requests):
            op_code = _OP_TO_CODE.get(str(payload.get("op")))
            src_vals = list(payload.get("src_vals", []))
            if op_code is None or len(src_vals) > 3:
                return None
            req = _ExactInfluenceRequest()
            req.op_code = int(op_code)
            req.width_bits = int(payload.get("width_bits", 32))
            req.signed_mode = 1 if bool(payload.get("signed_mode", False)) else 0
            req.src_count = int(len(src_vals))
            for j in range(3):
                req.src_vals[j] = 0
            for j, value in enumerate(src_vals):
                req.src_vals[j] = ctypes.c_uint64(int(value)).value
            req.dst_val = ctypes.c_uint64(int(payload.get("dst_val", 0))).value
            req.dst_observed_mask = ctypes.c_uint64(
                int(payload.get("dst_observed_mask", 0))
            ).value
            req_arr[idx] = req
            expected_counts.append(int(req.src_count))
        resp_arr = (_ExactInfluenceResponse * len(requests))()
        completed = int(
            self._lib.exact_backward_influence_many(
                req_arr, ctypes.c_size_t(len(requests)), resp_arr
            )
        )
        if completed != len(requests):
            return None
        out: List[List[int]] = []
        for idx, expected_count in enumerate(expected_counts):
            if int(resp_arr[idx].status) != 0:
                return None
            out.append([int(resp_arr[idx].src_masks[j]) for j in range(expected_count)])
        return out

    def classify_read_masks(
        self,
        *,
        width_bits: int,
        observed_mask: int,
        due_mask: int,
        trace_mask: int,
        semantic_masked_mask: int,
        semantic_sdc_mask: int,
        semantic_due_mask: int,
        semantic_infra_mask: int,
        semantic_unknown_mask: int,
        trace_expanding_policy: str,
        trace_uncovered_mode: str,
        trace_expanding_semantic_masked_mode: str,
    ) -> Optional[List[int]]:
        req = self._build_mask_request(
            width_bits=width_bits,
            observed_mask=observed_mask,
            due_mask=due_mask,
            trace_mask=trace_mask,
            semantic_masked_mask=semantic_masked_mask,
            semantic_sdc_mask=semantic_sdc_mask,
            semantic_due_mask=semantic_due_mask,
            semantic_infra_mask=semantic_infra_mask,
            semantic_unknown_mask=semantic_unknown_mask,
            trace_expanding_policy=trace_expanding_policy,
            trace_uncovered_mode=trace_uncovered_mode,
            trace_expanding_semantic_masked_mode=trace_expanding_semantic_masked_mode,
        )
        if req is None:
            return None
        resp = _ExactMaskClassifyResponse()
        rc = int(
            self._lib.exact_classify_read_masks_one(
                ctypes.byref(req), ctypes.byref(resp)
            )
        )
        if rc != 0 or int(resp.status) != 0:
            return None
        return [
            int(resp.due_mask),
            int(resp.sdc_mask),
            int(resp.unknown_mask),
            int(resp.policy_added_sdc_mask),
            int(resp.policy_used_mask),
            int(resp.trace_mask),
            int(resp.policy_override_mask),
        ]

    def classify_read_masks_many(
        self,
        requests: Sequence[dict],
    ) -> Optional[List[List[int]]]:
        if not requests:
            return []
        req_arr = (_ExactMaskClassifyRequest * len(requests))()
        for idx, payload in enumerate(requests):
            req = self._build_mask_request(**payload)
            if req is None:
                return None
            req_arr[idx] = req
        resp_arr = (_ExactMaskClassifyResponse * len(requests))()
        completed = int(
            self._lib.exact_classify_read_masks_many(
                req_arr, ctypes.c_size_t(len(requests)), resp_arr
            )
        )
        if completed != len(requests):
            return None
        out: List[List[int]] = []
        for idx in range(len(requests)):
            resp = resp_arr[idx]
            if int(resp.status) != 0:
                return None
            out.append(
                [
                    int(resp.due_mask),
                    int(resp.sdc_mask),
                    int(resp.unknown_mask),
                    int(resp.policy_added_sdc_mask),
                    int(resp.policy_used_mask),
                    int(resp.trace_mask),
                    int(resp.policy_override_mask),
                ]
            )
        return out

    def classify_site_masks(
        self,
        *,
        width_bits: int,
        observed_mask: int,
        due_mask: int,
        trace_mask: int,
        semantic_masked_mask: int,
        semantic_sdc_mask: int,
        semantic_due_mask: int,
        semantic_infra_mask: int,
        semantic_unknown_mask: int,
        trace_expanding_policy: str,
        trace_uncovered_mode: str,
        trace_expanding_semantic_masked_mode: str,
    ) -> Optional[List[int]]:
        req = self._build_mask_request(
            width_bits=width_bits,
            observed_mask=observed_mask,
            due_mask=due_mask,
            trace_mask=trace_mask,
            semantic_masked_mask=semantic_masked_mask,
            semantic_sdc_mask=semantic_sdc_mask,
            semantic_due_mask=semantic_due_mask,
            semantic_infra_mask=semantic_infra_mask,
            semantic_unknown_mask=semantic_unknown_mask,
            trace_expanding_policy=trace_expanding_policy,
            trace_uncovered_mode=trace_uncovered_mode,
            trace_expanding_semantic_masked_mode=trace_expanding_semantic_masked_mode,
        )
        if req is None:
            return None
        resp = _ExactSiteMaskClassifyResponse()
        rc = int(
            self._lib.exact_classify_site_masks_one(
                ctypes.byref(req), ctypes.byref(resp)
            )
        )
        if rc != 0 or int(resp.status) != 0:
            return None
        return [
            int(resp.due_mask),
            int(resp.sdc_mask),
            int(resp.unknown_mask),
            int(resp.policy_used_mask),
            int(resp.policy_override_mask),
        ]

    def classify_site_masks_many(
        self,
        requests: Sequence[dict],
    ) -> Optional[List[List[int]]]:
        if not requests:
            return []
        req_arr = (_ExactMaskClassifyRequest * len(requests))()
        for idx, payload in enumerate(requests):
            req = self._build_mask_request(**payload)
            if req is None:
                return None
            req_arr[idx] = req
        resp_arr = (_ExactSiteMaskClassifyResponse * len(requests))()
        completed = int(
            self._lib.exact_classify_site_masks_many(
                req_arr, ctypes.c_size_t(len(requests)), resp_arr
            )
        )
        if completed != len(requests):
            return None
        out: List[List[int]] = []
        for idx in range(len(requests)):
            resp = resp_arr[idx]
            if int(resp.status) != 0:
                return None
            out.append(
                [
                    int(resp.due_mask),
                    int(resp.sdc_mask),
                    int(resp.unknown_mask),
                    int(resp.policy_used_mask),
                    int(resp.policy_override_mask),
                ]
            )
        return out

    def control_taint_thread_hashes(
        self,
        events: Sequence[dict],
    ) -> Optional[tuple[bytes, bytes]]:
        if not events:
            zero = _ExactControlTaintDigest()
            return (
                int(zero.lo).to_bytes(8, "little")
                + int(zero.hi).to_bytes(8, "little"),
                int(zero.lo).to_bytes(8, "little")
                + int(zero.hi).to_bytes(8, "little"),
            )
        ev_arr = (_ExactControlTaintEventDesc * len(events))()
        flat_src_reg_ids: List[int] = []
        flat_src_width_bits: List[int] = []
        flat_src_vals: List[int] = []
        for idx, payload in enumerate(events):
            ev = _ExactControlTaintEventDesc()
            ev.kind_id = int(payload.get("kind_id", 0))
            ev.opcode_id = int(payload.get("opcode_id", 0))
            ev.pc_id = int(payload.get("pc_id", 0))
            ev.dst_reg_id = int(payload.get("dst_reg_id", 0))
            ev.width_bits = int(payload.get("width_bits", 0))
            src_reg_ids = [int(v) for v in payload.get("src_reg_ids", ())]
            src_width_bits = [int(v) for v in payload.get("src_width_bits", ())]
            src_vals = [ctypes.c_uint64(int(v)).value for v in payload.get("src_vals", ())]
            ev.src_reg_offset = len(flat_src_reg_ids)
            ev.src_reg_count = len(src_reg_ids)
            ev.src_width_offset = len(flat_src_width_bits)
            ev.src_width_count = len(src_width_bits)
            ev.src_val_offset = len(flat_src_vals)
            ev.src_val_count = len(src_vals)
            ev.branch_flag = 1 if payload.get("branch_flag") else 0
            ev.base_taken = 1 if payload.get("base_taken") else 0
            ev.reserved = 0
            flat_src_reg_ids.extend(src_reg_ids)
            flat_src_width_bits.extend(src_width_bits)
            flat_src_vals.extend(src_vals)
            ev_arr[idx] = ev
        src_reg_arr = (ctypes.c_int64 * max(1, len(flat_src_reg_ids)))()
        for idx, value in enumerate(flat_src_reg_ids):
            src_reg_arr[idx] = int(value)
        src_width_arr = (ctypes.c_int64 * max(1, len(flat_src_width_bits)))()
        for idx, value in enumerate(flat_src_width_bits):
            src_width_arr[idx] = int(value)
        src_val_arr = (ctypes.c_uint64 * max(1, len(flat_src_vals)))()
        for idx, value in enumerate(flat_src_vals):
            src_val_arr[idx] = ctypes.c_uint64(int(value)).value
        signature = _ExactControlTaintDigest()
        sketch = _ExactControlTaintDigest()
        rc = int(
            self._lib.exact_control_taint_thread_hashes(
                ev_arr,
                ctypes.c_size_t(len(events)),
                src_reg_arr,
                ctypes.c_size_t(len(flat_src_reg_ids)),
                src_width_arr,
                ctypes.c_size_t(len(flat_src_width_bits)),
                src_val_arr,
                ctypes.c_size_t(len(flat_src_vals)),
                ctypes.byref(signature),
                ctypes.byref(sketch),
            )
        )
        if rc != 0:
            return None
        return (
            int(signature.lo).to_bytes(8, "little")
            + int(signature.hi).to_bytes(8, "little"),
            int(sketch.lo).to_bytes(8, "little")
            + int(sketch.hi).to_bytes(8, "little"),
        )

    def control_taint_thread_hashes_many(
        self,
        threads: Sequence[Sequence[dict]],
    ) -> Optional[List[tuple[bytes, bytes]]]:
        if not threads:
            return []
        (
            thread_arr,
            ev_arr,
            src_reg_arr,
            src_width_arr,
            src_val_arr,
            thread_count,
            total_events,
            src_reg_count,
            src_width_count,
            src_val_count,
        ) = self._build_control_taint_arrays(threads)
        sig_arr = (_ExactControlTaintDigest * max(1, thread_count))()
        sketch_arr = (_ExactControlTaintDigest * max(1, thread_count))()
        completed = int(
            self._lib.exact_control_taint_thread_hashes_many(
                thread_arr,
                ctypes.c_size_t(thread_count),
                ev_arr,
                ctypes.c_size_t(total_events),
                src_reg_arr,
                ctypes.c_size_t(src_reg_count),
                src_width_arr,
                ctypes.c_size_t(src_width_count),
                src_val_arr,
                ctypes.c_size_t(src_val_count),
                sig_arr,
                sketch_arr,
            )
        )
        if completed != thread_count:
            return None
        out: List[tuple[bytes, bytes]] = []
        for idx in range(thread_count):
            out.append(
                (
                    int(sig_arr[idx].lo).to_bytes(8, "little")
                    + int(sig_arr[idx].hi).to_bytes(8, "little"),
                    int(sketch_arr[idx].lo).to_bytes(8, "little")
                    + int(sketch_arr[idx].hi).to_bytes(8, "little"),
                )
            )
        return out

    def control_taint_thread_hashes_many_columnar(
        self,
        *,
        thread_rows: Sequence[tuple[int, int]],
        event_rows: Sequence[tuple[int, int, int, int, int, int, int, int, int, int, int, bool, bool]],
        src_reg_ids: Sequence[int],
        src_width_bits: Sequence[int],
        src_vals: Sequence[int],
    ) -> Optional[List[tuple[bytes, bytes]]]:
        if not thread_rows:
            return []
        thread_arr = (_ExactControlTaintThreadBatchDesc * len(thread_rows))()
        for idx, (event_offset, event_count) in enumerate(thread_rows):
            thread_arr[idx].event_offset = int(event_offset)
            thread_arr[idx].event_count = int(event_count)
        ev_arr = (_ExactControlTaintEventDesc * max(1, len(event_rows)))()
        for idx, row in enumerate(event_rows):
            (
                kind_id,
                opcode_id,
                pc_id,
                dst_reg_id,
                width_bits,
                src_reg_offset,
                src_reg_count,
                src_width_offset,
                src_width_count,
                src_val_offset,
                src_val_count,
                branch_flag,
                base_taken,
            ) = row
            ev = _ExactControlTaintEventDesc()
            ev.kind_id = int(kind_id)
            ev.opcode_id = int(opcode_id)
            ev.pc_id = int(pc_id)
            ev.dst_reg_id = int(dst_reg_id)
            ev.width_bits = int(width_bits)
            ev.src_reg_offset = int(src_reg_offset)
            ev.src_reg_count = int(src_reg_count)
            ev.src_width_offset = int(src_width_offset)
            ev.src_width_count = int(src_width_count)
            ev.src_val_offset = int(src_val_offset)
            ev.src_val_count = int(src_val_count)
            ev.branch_flag = 1 if branch_flag else 0
            ev.base_taken = 1 if base_taken else 0
            ev.reserved = 0
            ev_arr[idx] = ev
        src_reg_arr = (ctypes.c_int64 * max(1, len(src_reg_ids)))()
        for idx, value in enumerate(src_reg_ids):
            src_reg_arr[idx] = int(value)
        src_width_arr = (ctypes.c_int64 * max(1, len(src_width_bits)))()
        for idx, value in enumerate(src_width_bits):
            src_width_arr[idx] = int(value)
        src_val_arr = (ctypes.c_uint64 * max(1, len(src_vals)))()
        for idx, value in enumerate(src_vals):
            src_val_arr[idx] = ctypes.c_uint64(int(value)).value
        sig_arr = (_ExactControlTaintDigest * len(thread_rows))()
        sketch_arr = (_ExactControlTaintDigest * len(thread_rows))()
        completed = int(
            self._lib.exact_control_taint_thread_hashes_many(
                thread_arr,
                ctypes.c_size_t(len(thread_rows)),
                ev_arr,
                ctypes.c_size_t(len(event_rows)),
                src_reg_arr,
                ctypes.c_size_t(len(src_reg_ids)),
                src_width_arr,
                ctypes.c_size_t(len(src_width_bits)),
                src_val_arr,
                ctypes.c_size_t(len(src_vals)),
                sig_arr,
                sketch_arr,
            )
        )
        if completed != len(thread_rows):
            return None
        out: List[tuple[bytes, bytes]] = []
        for idx in range(len(thread_rows)):
            out.append(
                (
                    int(sig_arr[idx].lo).to_bytes(8, "little")
                    + int(sig_arr[idx].hi).to_bytes(8, "little"),
                    int(sketch_arr[idx].lo).to_bytes(8, "little")
                    + int(sketch_arr[idx].hi).to_bytes(8, "little"),
                )
            )
        return out

    def thread_cycle_weights(
        self,
        *,
        cycles: Sequence[int],
        multiplicities: Sequence[int],
        active_thread_ids_by_record: Sequence[Sequence[int]],
        seed_values: Optional[Sequence[int]],
        thread_rand_max: Optional[int],
    ) -> Optional[tuple[List[tuple[int, int, int]], int, int, int]]:
        record_count = len(cycles)
        if len(multiplicities) != record_count or len(active_thread_ids_by_record) != record_count:
            return None
        cycle_arr = (ctypes.c_int64 * max(1, record_count))()
        mult_arr = (ctypes.c_int64 * max(1, record_count))()
        offsets_arr = (ctypes.c_uint32 * max(1, record_count + 1))()
        total_active = 0
        for idx in range(record_count):
            cycle_arr[idx] = int(cycles[idx])
            mult_arr[idx] = int(multiplicities[idx])
            offsets_arr[idx] = total_active
            total_active += len(active_thread_ids_by_record[idx])
        offsets_arr[record_count] = total_active
        active_ids_arr = (ctypes.c_int64 * max(1, total_active))()
        cursor = 0
        for active_ids in active_thread_ids_by_record:
            for tid in active_ids:
                active_ids_arr[cursor] = int(tid)
                cursor += 1
        seed_values = list(seed_values or [])
        seed_arr = (ctypes.c_int64 * max(1, len(seed_values)))()
        for idx, value in enumerate(seed_values):
            seed_arr[idx] = int(value)
        out_entries = (_ExactThreadCycleWeightEntry * max(1, total_active))()
        seed_domain_size = ctypes.c_int64(0)
        inactive_base_mass = ctypes.c_int64(0)
        active_base_mass = ctypes.c_int64(0)
        completed = int(
            self._lib.exact_thread_cycle_weights(
                cycle_arr,
                mult_arr,
                offsets_arr,
                active_ids_arr,
                ctypes.c_size_t(record_count),
                seed_arr,
                ctypes.c_size_t(len(seed_values)),
                ctypes.c_int64(0 if thread_rand_max is None else int(thread_rand_max)),
                out_entries,
                ctypes.c_size_t(total_active),
                ctypes.byref(seed_domain_size),
                ctypes.byref(inactive_base_mass),
                ctypes.byref(active_base_mass),
            )
        )
        if record_count > 0 and total_active > 0 and completed <= 0:
            return None
        out: List[tuple[int, int, int]] = []
        for idx in range(completed):
            out.append(
                (
                    int(out_entries[idx].thread_id),
                    int(out_entries[idx].cycle),
                    int(out_entries[idx].weight),
                )
            )
        return (
            out,
            int(seed_domain_size.value),
            int(inactive_base_mass.value),
            int(active_base_mass.value),
        )

    def rf_interval_accumulate_many(
        self,
        requests: Sequence[dict],
    ) -> Optional[dict]:
        if not self._has_rf_interval_accumulate:
            return None
        if not requests:
            return {
                "masked_num": 0,
                "sdc_num": 0,
                "due_num": 0,
                "unknown_num": 0,
                "saw_trace_selected_bits": 0,
            }
        req_arr = (_ExactRfIntervalRequest * len(requests))()
        for idx, req in enumerate(requests):
            row = req_arr[idx]
            row.mass = int(req.get("mass", 0))
            row.bit_count = int(req.get("bit_count", 0))
            row.legacy_unknown_trace_uncovered = (
                1 if req.get("legacy_unknown_trace_uncovered") else 0
            )
            row.selected_mask = ctypes.c_uint64(int(req.get("selected_mask", 0))).value
            row.due_mask = ctypes.c_uint64(int(req.get("due_mask", 0))).value
            row.sdc_mask = ctypes.c_uint64(int(req.get("sdc_mask", 0))).value
            row.unknown_mask = ctypes.c_uint64(int(req.get("unknown_mask", 0))).value
            row.trace_added_sdc_mask = ctypes.c_uint64(
                int(req.get("trace_added_sdc_mask", 0))
            ).value
            row.trace_policy_used_mask = ctypes.c_uint64(
                int(req.get("trace_policy_used_mask", 0))
            ).value
            row.trace_policy_override_mask = ctypes.c_uint64(
                int(req.get("trace_policy_override_mask", 0))
            ).value
            row.trace_mask = ctypes.c_uint64(int(req.get("trace_mask", 0))).value
            row.semantic_due_mask = ctypes.c_uint64(
                int(req.get("semantic_due_mask", 0))
            ).value
            row.addr_due_mask = ctypes.c_uint64(int(req.get("addr_due_mask", 0))).value
            row.addr_sdc_mask = ctypes.c_uint64(int(req.get("addr_sdc_mask", 0))).value
            row.addr_unknown_mask = ctypes.c_uint64(
                int(req.get("addr_unknown_mask", 0))
            ).value
            row.addr_trace_div_mask = ctypes.c_uint64(
                int(req.get("addr_trace_div_mask", 0))
            ).value
        out = _ExactRfIntervalAccum()
        rc = int(
            self._lib.exact_rf_interval_accumulate_many(
                req_arr,
                ctypes.c_size_t(len(requests)),
                ctypes.byref(out),
            )
        )
        if rc != 0:
            return None
        return {name: int(getattr(out, name)) for name, _typ in out._fields_}

    def evaluate_tolerance_paths_many(
        self,
        *,
        paths: Sequence[dict],
        requests: Sequence[tuple[int, int]],
    ) -> Optional[List[int]]:
        if not self._has_tolerance_path_eval:
            return None
        if not requests:
            return []
        if not paths:
            return None

        step_descs: List[_ExactToleranceStepDesc] = []
        flat_src_vals: List[int] = []
        path_descs = (_ExactTolerancePathDesc * max(1, len(paths)))()
        for path_idx, path in enumerate(paths):
            steps = list(path.get("steps", ()))
            path_desc = _ExactTolerancePathDesc()
            path_desc.final_width_bits = int(path.get("final_width_bits", 0))
            path_desc.step_offset = len(step_descs)
            path_desc.step_count = len(steps)
            for step in steps:
                op_code = _OP_TO_CODE.get(str(step.get("op")))
                src_vals = list(step.get("src_vals", ()))
                if op_code is None:
                    return None
                step_desc = _ExactToleranceStepDesc()
                step_desc.op_code = int(op_code)
                step_desc.width_bits_default = int(step.get("width_bits_default", 0))
                step_desc.tracked_src_index = int(step.get("tracked_src_index", -1))
                step_desc.src_val_offset = len(flat_src_vals)
                step_desc.src_val_count = len(src_vals)
                step_descs.append(step_desc)
                flat_src_vals.extend(ctypes.c_uint64(int(v)).value for v in src_vals)
            path_descs[path_idx] = path_desc

        step_arr = (_ExactToleranceStepDesc * max(1, len(step_descs)))()
        for idx, desc in enumerate(step_descs):
            step_arr[idx] = desc
        src_arr = (ctypes.c_uint64 * max(1, len(flat_src_vals)))()
        for idx, value in enumerate(flat_src_vals):
            src_arr[idx] = ctypes.c_uint64(int(value)).value
        req_arr = (_ExactToleranceEvalRequest * len(requests))()
        for idx, (path_index, current_value) in enumerate(requests):
            if int(path_index) < 0 or int(path_index) >= len(paths):
                return None
            req_arr[idx].path_index = int(path_index)
            req_arr[idx].current_value = ctypes.c_uint64(int(current_value)).value
        resp_arr = (_ExactToleranceEvalResponse * len(requests))()
        completed = int(
            self._lib.exact_evaluate_tolerance_paths_many(
                step_arr,
                ctypes.c_size_t(len(step_descs)),
                src_arr,
                ctypes.c_size_t(len(flat_src_vals)),
                path_descs,
                ctypes.c_size_t(len(paths)),
                req_arr,
                ctypes.c_size_t(len(requests)),
                resp_arr,
            )
        )
        if completed != len(requests):
            return None
        out: List[int] = []
        for idx in range(len(requests)):
            if int(resp_arr[idx].status) != 0:
                return None
            out.append(int(resp_arr[idx].final_bits))
        return out


_BACKEND: Optional[ExactCppBackend] = None
_BACKEND_LOAD_ATTEMPTED = False


def _resolve_library_path() -> Optional[Path]:
    if _ENV_LIB:
        p = Path(_ENV_LIB)
        if p.is_file():
            return p
    if _DEFAULT_LIB.is_file():
        return _DEFAULT_LIB
    return None


def get_backend() -> Optional[ExactCppBackend]:
    global _BACKEND, _BACKEND_LOAD_ATTEMPTED
    if _BACKEND is not None:
        return _BACKEND
    if _BACKEND_LOAD_ATTEMPTED:
        return None
    _BACKEND_LOAD_ATTEMPTED = True
    lib_path = _resolve_library_path()
    if lib_path is None:
        return None
    try:
        _BACKEND = ExactCppBackend(lib_path)
    except Exception:
        _BACKEND = None
    return _BACKEND


def backward_influence(
    *,
    op: str,
    src_vals: Sequence[int],
    dst_val: int,
    dst_observed_mask: int,
    width_bits: int,
    signed_mode: bool = False,
) -> Optional[List[int]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.backward_influence(
        op=op,
        src_vals=src_vals,
        dst_val=dst_val,
        dst_observed_mask=dst_observed_mask,
        width_bits=width_bits,
        signed_mode=signed_mode,
    )


def backward_influence_many(requests: Sequence[dict]) -> Optional[List[List[int]]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.backward_influence_many(requests)


def classify_read_masks(
    *,
    width_bits: int,
    observed_mask: int,
    due_mask: int,
    trace_mask: int,
    semantic_masked_mask: int,
    semantic_sdc_mask: int,
    semantic_due_mask: int,
    semantic_infra_mask: int,
    semantic_unknown_mask: int,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_semantic_masked_mode: str,
) -> Optional[List[int]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.classify_read_masks(
        width_bits=width_bits,
        observed_mask=observed_mask,
        due_mask=due_mask,
        trace_mask=trace_mask,
        semantic_masked_mask=semantic_masked_mask,
        semantic_sdc_mask=semantic_sdc_mask,
        semantic_due_mask=semantic_due_mask,
        semantic_infra_mask=semantic_infra_mask,
        semantic_unknown_mask=semantic_unknown_mask,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
        trace_expanding_semantic_masked_mode=trace_expanding_semantic_masked_mode,
    )


def classify_read_masks_many(requests: Sequence[dict]) -> Optional[List[List[int]]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.classify_read_masks_many(requests)


def classify_site_masks(
    *,
    width_bits: int,
    observed_mask: int,
    due_mask: int,
    trace_mask: int,
    semantic_masked_mask: int,
    semantic_sdc_mask: int,
    semantic_due_mask: int,
    semantic_infra_mask: int,
    semantic_unknown_mask: int,
    trace_expanding_policy: str,
    trace_uncovered_mode: str,
    trace_expanding_semantic_masked_mode: str,
) -> Optional[List[int]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.classify_site_masks(
        width_bits=width_bits,
        observed_mask=observed_mask,
        due_mask=due_mask,
        trace_mask=trace_mask,
        semantic_masked_mask=semantic_masked_mask,
        semantic_sdc_mask=semantic_sdc_mask,
        semantic_due_mask=semantic_due_mask,
        semantic_infra_mask=semantic_infra_mask,
        semantic_unknown_mask=semantic_unknown_mask,
        trace_expanding_policy=trace_expanding_policy,
        trace_uncovered_mode=trace_uncovered_mode,
        trace_expanding_semantic_masked_mode=trace_expanding_semantic_masked_mode,
    )


def classify_site_masks_many(requests: Sequence[dict]) -> Optional[List[List[int]]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.classify_site_masks_many(requests)


def control_taint_thread_hashes(
    events: Sequence[dict],
) -> Optional[tuple[bytes, bytes]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.control_taint_thread_hashes(events)


def control_taint_thread_hashes_many(
    threads: Sequence[Sequence[dict]],
) -> Optional[List[tuple[bytes, bytes]]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.control_taint_thread_hashes_many(threads)


def control_taint_thread_hashes_many_columnar(
    *,
    thread_rows: Sequence[tuple[int, int]],
    event_rows: Sequence[tuple[int, int, int, int, int, int, int, int, int, int, int, bool, bool]],
    src_reg_ids: Sequence[int],
    src_width_bits: Sequence[int],
    src_vals: Sequence[int],
) -> Optional[List[tuple[bytes, bytes]]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.control_taint_thread_hashes_many_columnar(
        thread_rows=thread_rows,
        event_rows=event_rows,
        src_reg_ids=src_reg_ids,
        src_width_bits=src_width_bits,
        src_vals=src_vals,
    )


def thread_cycle_weights(
    *,
    cycles: Sequence[int],
    multiplicities: Sequence[int],
    active_thread_ids_by_record: Sequence[Sequence[int]],
    seed_values: Optional[Sequence[int]],
    thread_rand_max: Optional[int],
) -> Optional[tuple[List[tuple[int, int, int]], int, int, int]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.thread_cycle_weights(
        cycles=cycles,
        multiplicities=multiplicities,
        active_thread_ids_by_record=active_thread_ids_by_record,
        seed_values=seed_values,
        thread_rand_max=thread_rand_max,
    )


def rf_interval_accumulate_many(requests: Sequence[dict]) -> Optional[dict]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.rf_interval_accumulate_many(requests)


def evaluate_tolerance_paths_many(
    *,
    paths: Sequence[dict],
    requests: Sequence[tuple[int, int]],
) -> Optional[List[int]]:
    backend = get_backend()
    if backend is None:
        return None
    return backend.evaluate_tolerance_paths_many(paths=paths, requests=requests)
