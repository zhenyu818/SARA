"""Shared batch-model classifications, with independent rates/query sinks.

The submitted local bit-sensitivity composition is a MODEL, not a proof of a
correlated program outcome. No fault origin is replayed here. The backward
instruction pass is shared with reg_observed_analyzer; this module projects its
read masks onto the actual post-core storage intervals. Rates never require a
query manifest, a site index, or a materialized list of all physical bits.
"""
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import time

from script.execution.campaign import fingerprint
from script.execution.fault_manifest import location_identity

CLASSES = ("Masked", "SDC", "DUE", "Unknown")
MODEL = "sara-batch-backward-serial-opcode44-v4"
SUPPORT = {
    "model": MODEL,
    "classification_is": "model_prediction_not_FI_certified_truth",
    "propagation": "submitted_local_single_input_bit_sensitivity_composition",
    "limitations": ["correlated_multi_bit_changes", "fanout_and_reconvergence_cancellation",
                    "changed_control_decision_SDC_surrogate_may_be_Masked_or_DUE"],
    "unsupported": "Unknown_retained_in_full_population",
    "class_priority": ["DUE", "SDC", "Unknown", "Masked"],
    "uncertainty_precedence": "submitted_model_effect_priority;not_a_guarantee_of_faulted_execution",
    "effect_eligibility": "supported_local_transfer_or_closed_relation_or_submitted_control_sensitivity_surrogate",
    "changed_control_successor": "submitted_local_SDC_surrogate;alternative_execution_not_replayed_or_proved",
    "multi_bit_composition_boundary": "submitted_local_model_prediction;no_blanket_multibit_refusal",
    "same_instruction_repeated_source_UID": "one_joint_physical_input_bit_mutation",
    "tag_support": "invalid_until_full_overwrite_or_terminal_with_no_live_or_unsafe_operational_version",
    "hook_phase": "after_all_core_instruction_events_at_cycle",
    "predicate_register_encoding": "simulator_zero_flag_normalized_to_logical_bit",
    "closed_local_relation": "single_use_pure_32bit_two_operator_relation_to_full_final_output;no_control_address_fanout_or_later_load",
    "per_origin_replay": False,
    "signed32_remainder": "Render03_exact_rem.s32_normal_words_unchanged;pinned_native_trunc_zero_convention;baseline_domain_refusal;specific_excluded_physical_mutation_bits_to_existing_trace_including_dead_outputs;opaque_BB_no_embedded_REM_EA;joint_UID_and_bound_literal_rules;original_class_priority",
    "unsigned32_rzi_conversion": "exact_cvt.rzi.u32.f32_only;pinned_native_raw_binary32_truncation_and_unsigned_clamp;full_register_shape;existing_local_bit_composition",
    "signed32_division": "Render03_exact_trunc_zero_quotient;baseline_golden_refusal;only_native_excluded_mutation_bits_to_existing_uncertainty;joint_UID_and_nonfault_literal_rules",
    "signed32_division_capabilities": "ordinary_scalar_triplet;opaque_basic_block_boundary;no_embedded_DIV_memory_EA;undefined_predicate_activation_to_uncertainty;other_operators_unchanged",
    "signed32_rni_conversion": "exact_cvt.rni.s32.f32_raw_binary32_to_signed32_nearest_ties_even;native_NaN_zero_and_endpoint_clamp;original_local_composition",
    "float32_rzi_conversion": "exact_cvt.rzi.f32.f32_integral_FLOAT_output_toward_zero;signed_zero_and_infinity_preserved;native_canonical_NaN_word;original_local_composition",
    "shuffle_DOWN": "exact_native_full32_unpredicated_snapshot;peer_source_owner_UID;all_reads_before_all_data_and_predicate_writes;physical_control_aliases_joint;changed_membermask_outside_finite_contract_is_uncertainty",
    "native_register_identity": "UID_primary_RF_population_lookup_with_printed_name_crosscheck;trace_local_name_noninterference_admission;no_alpha_renaming_or_new_prediction",
    "initial_global_image": "clean_host_assignment_chronology_on_every_SM_and_storage_component;unwritten_zero_is_simulator_only;no_FI_answers",
    "declaration_only_constant_support": "source_bound_fresh_native_zero_and_actual_symbol_copies;ordinary_scalar_reads_and_literal_MOV_checked;not_a_new_cache_fault_population",
    "deductive_loop_support": "optional_bound_PTX_RF_action_interval_summaries;fixed_existing_watchdog;no_sample_input",
    "extra_zero_loop": "value_identity_certificate_alone_does_not_override_label_without_completion_upper_bound",
}


def masks(width, observed=0, due=0, unknown=0):
    """Submitted MODEL priority, shared by the whole-space and paired sinks.

    The producer supplies local effect evidence, including the original model's
    computable control-decision sensitivity as an SDC surrogate. Unsupported
    storage relations alone supply uncertainty. Overlapping effect and uncertainty
    masks follow DUE > SDC > Unknown > Masked, as in the submitted method.
    In particular, this does NOT prove that a golden-path local effect survives
    changed control flow, correlated deltas or reconvergence. Those remain
    declared model limitations, evaluated without FI-driven relabeling.
    """
    if type(width) is not int or width < 1:
        raise ValueError("positive declared storage width required")
    full = (1 << width) - 1
    d = int(due) & full
    s = int(observed) & full & ~d
    u = int(unknown) & full & ~(d | s)
    return {"Masked": full & ~(d | s | u), "SDC": s, "DUE": d, "Unknown": u}


@dataclass(frozen=True)
class Region:
    component: str
    target: dict
    start: int
    stop: int
    bit_start: int
    width: int
    classes: dict
    unknown_reason: str = "unsupported_batch_model_mechanism"

    def __post_init__(self):
        location_identity(self.component, self.target)
        if (type(self.start) is not int or type(self.stop) is not int
                or self.start < 0 or self.stop <= self.start
                or type(self.bit_start) is not int or self.bit_start < 0
                or type(self.width) is not int or self.width < 1
                or set(self.classes) != set(CLASSES)):
            raise ValueError("invalid compact classified storage interval")
        union = 0
        for key in CLASSES:
            value = self.classes[key]
            if type(value) is not int or value < 0 or union & value:
                raise ValueError("class masks overlap or are malformed")
            union |= value
        if union != (1 << self.width) - 1:
            raise ValueError("class masks must partition every declared bit")

    @property
    def key(self):
        return (self.component, location_identity(self.component, self.target))

    def classify(self, cycle, bit):
        if not self.start <= cycle < self.stop or not self.bit_start <= bit < self.bit_start + self.width:
            raise ValueError("query outside compact classification region")
        selected = 1 << (bit - self.bit_start)
        return next(key for key in CLASSES if self.classes[key] & selected)


class RatesSink:
    """Streaming popcounts only: deliberately no query/index interface."""
    def __init__(self, *, retain_classification_digest=True):
        if type(retain_classification_digest) is not bool:
            raise ValueError('explicit classification digest retention boolean required')
        self.counts = dict.fromkeys(CLASSES, 0)
        self.regions = 0
        # serial-pruned-v3: aggregate-only delivery cannot export a validation
        # capsule and does not consume a per-region classification proof.
        # Preserve the exact original digest path by default for every actual
        # nonaggregate/paired consumer; never forge an omitted digest.
        self.digest = hashlib.sha256() if retain_classification_digest else None

    def consume(self, region):
        ticks = region.stop - region.start
        for key in CLASSES:
            self.counts[key] += ticks * bin(region.classes[key]).count("1")
        self.regions += 1
        # Compact analysis identity, common to both modes. This is not a
        # per-site dump and contains no sampled trial identity.
        if self.digest is not None:
            row = [region.component, region.target, region.start, region.stop,
                   region.bit_start, region.width, [region.classes[key] for key in CLASSES],
                   region.unknown_reason if region.classes["Unknown"] else None]
            self.digest.update(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    def summary(self, expected_mass):
        total = sum(self.counts.values())
        if type(expected_mass) is not int or expected_mass < 1 or total != expected_mass:
            raise ValueError("batch classification lost or duplicated population mass")
        u = self.counts["Unknown"]
        return {"model": MODEL, "support_policy": SUPPORT,
                "support_fingerprint": fingerprint(SUPPORT), "population_mass": total,
                "counts": dict(self.counts),
                "rates": {key: value / total for key, value in self.counts.items()},
                "unknown_identification_bounds": {key: [self.counts[key] / total,
                    (self.counts[key] + u) / total] for key in CLASSES if key != "Unknown"},
                "region_count": self.regions,
                "classification_digest": self.digest.hexdigest() if self.digest is not None else None,
                **({"classification_digest_policy": "omitted_aggregate_only_no_validation_capsule"}
                   if self.digest is None else {}),
                "sampling_confidence_interval": None,
                "uncertainty_note": "full-population MODEL estimate; Unknown bounds are not sampling intervals"}


class PairedSink:
    """Query-only observer of exactly the same stream consumed by RatesSink.

    Index the requested draws rather than materializing a whole-population
    site index. Repeated sites keep separate draw IDs and result records.
    """
    def __init__(self, trials):
        self.rates = RatesSink()
        self.pending = defaultdict(list)
        self.cycles = {}
        self.answers = {}
        self.trials = list(trials)
        self.query_seconds = None
        ids = set()
        for trial in self.trials:
            tid = trial["trial_id"]
            if tid in ids:
                raise ValueError("duplicate trial ID; repeated SITE IDs remain legal")
            ids.add(tid)
            key = (trial["component"], location_identity(trial["component"], trial["target"]))
            self.pending[key].append(trial)
        for key, rows in self.pending.items():
            rows.sort(key=lambda row: (row["cycle"], row["trial_id"]))
            self.cycles[key] = [row["cycle"] for row in rows]

    def consume(self, region):
        self.rates.consume(region)
        rows = self.pending.get(region.key)
        if rows:
            cycles = self.cycles[region.key]
            lo = bisect_right(cycles, region.start - 1)
            hi = bisect_right(cycles, region.stop - 1)
            for trial in rows[lo:hi]:
                if not region.bit_start <= trial["bit"] < region.bit_start + region.width:
                    continue
                tid = trial["trial_id"]
                if tid in self.answers:
                    raise ValueError("draw matches multiple classified regions")
                outcome = region.classify(trial["cycle"], trial["bit"])
                self.answers[tid] = {"trial_id": tid, "site_id": trial["site_id"],
                    "status": "complete",
                    "requested_draw_fingerprint": fingerprint(trial), "outcome": outcome,
                    "reason": region.unknown_reason if outcome == "Unknown" else "batch_backward_model",
                    "evidence": {"region": [region.start, region.stop],
                                 "model": MODEL, "per_origin_replay": False}}

    def summary(self, expected_mass):
        if len(self.answers) != len(self.trials):
            raise ValueError("sample has unmapped draws; never silently drop them")
        return self.rates.summary(expected_mass)

    def records(self):
        if len(self.answers) != len(self.trials):
            raise ValueError("sample has unmapped draws")
        return [self.answers[row["trial_id"]] for row in self.trials]


def reverse_intervals(span, actions):
    """Project read masks through writes once per storage history.

    Actions are (cycle, ordinal, kind, observed, due, unknown, write_mask).
    At the post-core hook, all same-cycle actions have already occurred.
    Reverse writes kill the written bits BEFORE reverse reads of an in-place
    instruction add old-value sensitivity. No physical bit/cycle is enumerated.
    """
    width, start, stop = span["bit_count"], span["cycle_start"], span["cycle_stop"]
    state = [0, 0, 0]
    last = stop
    groups = defaultdict(list)
    for action in actions:
        if action[0] >= start:
            groups[action[0]].append(action)
    for cycle in sorted(groups, reverse=True):
        if cycle < stop and cycle < last:
            yield Region(span["component"], span["target"], max(start, cycle), last,
                span.get("bit_start", 0), width, masks(width, *state))
            last = cycle
        # Ordinal places a destination write after all reads of that event.
        for _, _, kind, obs, due, unknown, write in sorted(groups[cycle], key=lambda row: row[1], reverse=True):
            if kind == "write":
                for index in range(3):
                    state[index] &= ~write
            elif kind == "read":
                for index, value in enumerate((obs, due, unknown)):
                    state[index] |= value
            else:
                raise ValueError("unsupported storage history action")
    if start < last:
        yield Region(span["component"], span["target"], start, last,
            span.get("bit_start", 0), width, masks(width, *state))


def _rf_regions_from_actions(inventory, events, read_records, identity_receipt=None):
    """Batch read/write histories on the injector's actual allocated RF domain."""
    actions = defaultdict(list)
    from script.core.rf_identity_guard import (build_rf_identity_index,
        validate_input_register_name_noninterference)
    identity = build_rf_identity_index(inventory)
    allocated, by_name = identity['members'], identity['by_name']
    name_proof = validate_input_register_name_noninterference(events, rf_inventory=inventory)
    if identity_receipt is not None:
        if type(identity_receipt) is not dict or identity_receipt:
            raise ValueError('Fresh empty RF identity output receipt required')
    for rec in read_records:
        index = rec["event_index"]
        event = events[index]
        uid = rec["src_reg_uid"]
        if event.kernel_uid is None or event.cycle is None:
            raise ValueError("actual kernel and cycle required")
        key = (event.kernel_uid, event.thread_id, uid)
        name = allocated.get(key)
        if name is None:
            if (event.kernel_uid, event.thread_id, rec['src_reg']) in by_name:
                raise ValueError('Allocated read lacks its actual physical RF UID')
            # Builtins and literal operands are not allocated RF members.
            # They still participated in the common instruction analysis.
            continue
        if uid < 0 or rec['src_reg'] != name:
            raise ValueError('Read name differs from its physical UID population member')
        actions[key].append((event.cycle, 2 * index, "read",
            int(rec["observed_mask_this_read"]), int(rec["due_mask_this_read"]),
            int(rec["trace_expanding_mask_this_read"]), 0))
    for event in events:
        if event.pred is not None and not event.pred.val:
            continue
        if getattr(event, 'shuffle44', None) is not None:
            from script.core.ptx_shuffle_down import destination_writes
            writes44 = destination_writes(event)
        elif event.dst_reg is not None:
            writes44 = ((event.dst_reg, event.dst_reg_uid, event.dst_write_mask),)
        else:
            continue
        for name44, uid44, mask44 in writes44:
            key = (event.kernel_uid, event.thread_id, uid44)
            declared_name = allocated.get(key)
            if declared_name is None:
                if (event.kernel_uid, event.thread_id, name44) in by_name:
                    raise ValueError('Allocated write lacks its actual physical RF UID')
                continue
            if uid44 is None or uid44 < 0 or event.cycle is None:
                raise ValueError("actual written register UID/cycle required")
            if name44 != declared_name:
                raise ValueError('Write name differs from its physical UID population member')
            if mask44 is None:
                raise ValueError("actual write mask required; do not guess partial writes")
            key = (event.kernel_uid, event.thread_id, uid44)
            actions[key].append((event.cycle, 2 * event.index + 1, "write", 0, 0, 0, int(mask44)))
    if identity_receipt is not None:
        identity_receipt.update(name_proof, UID_primary_population_lookup=True,
            printed_name_crosscheck=True, missing_allocated_UID_refused=True,
            native_population_members=len(allocated), validation_precedes_all_regions=True)
    for span in inventory["spans"]:
        if span["component"] != "rf":
            raise ValueError("RF core received a different physical component")
        target = span["target"]
        history = actions.get((target["kernel"], target["thread"], target["register_uid"]), ())
        yield from reverse_intervals(span, history)


def rf_regions(inventory, events, read_records, loop_effects=(), loop_statistics=None, *, identity_receipt=None):
    regions = _rf_regions_from_actions(inventory, events, read_records, identity_receipt)
    if loop_effects:
        from script.core.closed_loop_transfer import project
        yield from project(regions, loop_effects,loop_statistics)
    else:
        yield from regions


def normalize_predicate_register_values(raw):
    """GPGPU-Sim stores predicate TRUE as zero in its register bit zero.

    The batch transfer evaluator uses logical Booleans. XORing the bit commutes
    with this one-bit complement, so physical bit identity is unchanged. The
    trace's *effective instruction gate* pred.val is already logical and must
    NOT be inverted a second time. No literal or non-predicate value changes.
    """
    def value(raw_value):
        integer = int(raw_value, 0) if isinstance(raw_value, str) else int(raw_value)
        return 1 ^ (integer & 1)
    for event in raw:
        widths = event.get("src_width_bits", [])
        uids = event.get("src_reg_uids", [])
        sources = event.get("src_vals", [])
        for index in range(min(len(widths), len(uids), len(sources))):
            if widths[index] == 1 and uids[index] >= 0:
                sources[index] = value(sources[index])
        if event.get("width_bits") == 1 and event.get("dst_reg") is not None:
            for field in ("dst_val", "dst_old_val"):
                if event.get(field) is not None:
                    event[field] = value(event[field])
    return raw


_EVENT_MUTABLE_LIST_FIELDS = ('src_vals', 'src_regs', 'src_reg_uids',
                              'ea_base_src_indices')


def _is_json_leaf(value):
    # Exact types exclude user objects with conversion or mutation hooks.
    if type(value) in (type(None), bool, int, str):
        return True
    if type(value) is float:
        from math import isfinite
        return isfinite(value)
    return False


def _frozen_event_tree(events):
    """Prove a recursively frozen, alias-free JSON container TREE.

    Context presence and outer frozen types are not a tree/immutability proof.
    Visit every container identity once across the entire event subtree before
    any row is adapted or normalized. Repeated containers include both aliases
    and cycles; either requires the one-whole-graph legacy deepcopy.
    """
    from script.execution.method_input_context import FrozenDict, FrozenList
    if type(events) is not FrozenList:
        return False
    seen, pending = set(), [events]
    while pending:
        value = pending.pop()
        if type(value) in (FrozenDict, FrozenList):
            # Exact frozen types still have an instance __dict__. User attrs
            # can shadow get/items or deepcopy hooks. Inspect this dictionary
            # before invoking ANY frozen-container operation, and preserve the
            # old whole-copy path for every attributed instance.
            attributes = object.__getattribute__(value, '__dict__')
            if type(attributes) is not dict or dict.__len__(attributes) != 0:
                return False
            identity = id(value)
            if identity in seen:
                return False
            seen.add(identity)
            if type(value) is FrozenDict:
                for key, item in dict.items(value):
                    if type(key) is not str:
                        return False
                    pending.append(item)
            else:
                pending.extend(list.__iter__(value))
        elif not _is_json_leaf(value):
            return False
    # These lists are written or retained by parse_event. Only their flat
    # primitive form has a demonstrated shallow-copy contract. Nested forms
    # retain the legacy copy and its validation/error behavior.
    for row in list.__iter__(events):
        if type(row) is not FrozenDict:
            return False
        for name in _EVENT_MUTABLE_LIST_FIELDS:
            value = dict.get(row, name)
            if type(value) is FrozenList:
                if any(not _is_json_leaf(item) for item in list.__iter__(value)):
                    return False
            elif type(value) is FrozenDict:
                return False
    return True


def _legacy_event_deepcopy(events):
    from copy import deepcopy
    return deepcopy(events)


def _analysis_event_input(events):
    """Adapt only proven own-context immutable trees; preserve the public API."""
    from script.execution.method_input_context import FrozenList, OwnInputContext, current_context
    context = current_context()
    eligible = (type(context) is OwnInputContext and context._token is not None
                and not context._closed and _frozen_event_tree(events))
    if not eligible:
        return _legacy_event_deepcopy(events), {
            'policy': 'legacy_one_whole_event_graph_deepcopy',
            'immutable_borrow_enabled': False,
            'fallback_preserves_container_aliases_and_cycles': True,
        }
    rows = []
    for row in list.__iter__(events):
        adapted = dict.copy(row)
        for name in _EVENT_MUTABLE_LIST_FIELDS:
            if type(dict.get(row, name)) is FrozenList:
                adapted[name] = list.copy(dict.__getitem__(row, name))
        rows.append(adapted)
    return rows, {
        'policy': 'own_context_proven_frozen_alias_free_JSON_tree_row_and_retained_list_copy',
        'immutable_borrow_enabled': True,
        'mutable_list_fields': list(_EVENT_MUTABLE_LIST_FIELDS),
        'whole_event_subtree_identity_proof': True,
        'all_frozen_instance_attribute_dicts_proven_empty': True,
        'file_origin_alone_grants_eligibility': False,
    }


def analyze_rf(trace, inventory, *, output_spec, aggregate_only=False):
    """The ONLY production instruction-analysis call shared by both modes."""
    if type(aggregate_only) is not bool:
        raise ValueError('explicit aggregate-only output policy required')
    from script.core import reg_observed_analyzer as backward
    from script.core.exact_sdc_prepare_input import _mark_output_stores
    raw, copy_policy = _analysis_event_input(trace["events"])
    raw = normalize_predicate_register_values(raw)
    specs = output_spec.get("output_spec", output_spec.get("outputs", output_spec)) if isinstance(output_spec, dict) else output_spec
    if not isinstance(specs, list) or not specs:
        raise ValueError("complete actual output range list required")
    marked_ranges = [dict(row, base=backward.parse_int(row["base"]),
                          size=int(row.get("bytes", row.get("size", 0)))) for row in specs]
    _mark_output_stores(raw, marked_ranges)
    events = [backward.parse_event(row, index) for index, row in enumerate(raw)]
    rf_authority = inventory if inventory['spans'][0]['component'] == 'rf' else None
    initial_image = trace.get('initial_global_image')
    image_support = None
    if initial_image is not None:
        from script.core.sparse_global_image import validate_golden_image
        image_support = validate_golden_image(events, initial_image)
    # serial-pruned-v1: these interval summaries are consumed only by
    # rf_regions().  The SMEM/cache projections never read loop_effects;
    # constructing RF-only proofs for them is unconsumed analysis work.
    # Keep the RF proof and every common instruction transfer unchanged.
    output_component = inventory['spans'][0]['component']
    if output_component == 'rf':
        from script.core.closed_loop_transfer import construct
        loop_effects, loop_support = construct(events, initial_image)
    else:
        loop_effects = []
        loop_support = {
            'status': 'not_requested_for_non_RF_projection',
            'component': output_component,
            'proof_consumer': 'RF_action_intervals_only',
            'executed': False,
            'classification_changed': False,
            'implementation_variant': 'serial-pruned-v5',
        }
    from script.core.closed_fma_transfer import closed_input_effects
    closed_effects, closed_support = closed_input_effects(events, backward.parse_output_ranges(specs),
                                                        include_proof_pairs=not aggregate_only)
    result = backward.analyze(events,
        memory_ranges=backward.parse_memory_ranges(trace.get("memory_ranges", [])),
        output_ranges=backward.parse_output_ranges(specs), lite_output=True,
        lite_output_profile="compat", mask_format="int", assume_sorted_events=True,
        fault_component="rf", emit_cache_sites=True,
        output_component=output_component,
        aggregate_only=aggregate_only,
        control_outcome_policy="submitted_local_sdc",
        initial_global_image=initial_image,
        proved_input_effects=closed_effects, rf_identity_inventory=rf_authority)
    result['initial_global_image_support'] = image_support
    result['input_register_identity_support'] = result['exact_meta']['input_register_identity_support']
    result['copy_policy'] = copy_policy
    result['exact_meta']['serial_pruned_copy_policy'] = dict(copy_policy)
    result['loop_effects'] = loop_effects
    result['deductive_loop_support'] = loop_support
    result["composition_support"] = {
        # Input implementation metadata, exported by the unchanged campaign;
        # this is not an additional scientific composition/support rule.
        "input_copy_policy": dict(copy_policy),
        "policy": "submitted_local_composition_without_blanket_multibit_refusal",
        "blanket_refusal_enabled": False,
        "classification_is": "model_prediction_not_general_correlated_execution_proof",
        "per_origin_replay": False, "FI_answers_used": False}
    result["closed_local_support"] = {k:v for k,v in closed_support.items() if k != "proof_pairs"}
    return events, result
