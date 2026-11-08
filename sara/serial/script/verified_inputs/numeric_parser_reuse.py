"""Reuse certified event identity plus the complete original typed remainder.

Only the closed V8 trace producer can supply the event token. Public or
unsupported calls use the unchanged V6 pool. Constructor admission replaces
the full TREE walk, never the original four retained-list flatness contract,
row/list copies, normalizer, output marking, parser or per-own golden checks.
"""
from script.execution.method_input_context import FrozenDict, FrozenList
from script.core import batch_backward as batch
from script.parsed_inputs.numeric_parser_reuse import (
    _mutable_rows, _parse_rows, _finish, JOIN_ONLY_EVENT_FIELDS,
)
from script.typed_records.typed_identity import equivalent, TypedIdentityUnsupported
from script.readonly_records.numeric_parser_reuse import (
    NumericParserPool as _OriginalPool, _source_constructor,
)
from script.verified_inputs.purefreeze_reuse import event_certificate


POLICY = 'private-producer-events-byte-certificate-flat-lists-and-remainder-typed-equivalence-v1'


def _flat_retained_lists(events):
    # Exactly the final retained-list criterion of batch._frozen_event_tree.
    # Fresh native JSON / exact publication prove the other TREE invariants.
    for row in list.__iter__(events):
        for field in batch._EVENT_MUTABLE_LIST_FIELDS:
            value = dict.get(row, field)
            if type(value) is FrozenList:
                if any(not batch._is_json_leaf(item) for item in list.__iter__(value)):
                    return False
            elif type(value) is FrozenDict:
                return False
    return True


def _remainder(trace, outputs, options):
    return dict(memory_ranges=trace.get('memory_ranges', []), outputs=outputs, numerical_options=options)


def _policy(*, reused, small_checks):
    return dict(policy=POLICY,
        proof_route=('producer_events_certificate_and_remainder_typed_equivalence' if reused
                     else 'producer_constructor_invariants_and_flat_retained_lists'),
        immutable_borrow_enabled=True, fresh_original_JSON_constructor_proven=True,
        actual_cached_document_and_events_proven=True, producer_event_token_proven=True,
        events_byte_certificate_proven=True, whole_numeric_native_bytes_compared=False,
        remainder_typed_equivalence_proven=reused,
        constructor_invariants_proven=True, TREE_executed=False,
        whole_event_subtree_identity_walk_performed=False,
        reference_complete_frozen_tree_guard_proven=False,
        reference_strict_typed_self_guard_proven=False,
        retained_list_flatness_proven=True, retained_list_flatness_check_executed=not reused,
        all_frozen_instance_attribute_dicts_proven_empty=True,
        frozen_attribute_proof='closed_original_JSON_and_corresponding_frozen_publication_constructor',
        file_origin_alone_grants_eligibility=False, exact_sara_GroupOwnInputContext_required=True,
        source_identity_checked_in_live_own_scope=True,
        parser_result_reused=reused, event_row_and_retained_list_copy_performed=not reused,
        mutable_list_fields=list(batch._EVENT_MUTABLE_LIST_FIELDS),
        unchanged_V6_whole_reference_typed_self_gate_retired=True,
        new_small_remainder_typed_self_admission=True,
        small_remainder_typed_self_checks=small_checks,
        public_V6_behavior_unchanged=True)


class NumericParserPool:
    def __init__(self, _proof=None):
        self._proof, self._original = _proof, _OriginalPool(_proof)
        self._groups = []
        self._constructor_invocations = self._constructor_hits = self._constructor_golden = 0
        self._old_mode = False
        self._small_remainder_self_checks = 0

    @property
    def invocations(self):
        return self._constructor_invocations + self._original.invocations

    @property
    def reuse_hits(self):
        return self._constructor_hits + self._original.reuse_hits

    @property
    def golden_validations(self):
        return self._constructor_golden + self._original.golden_validations

    def _fallback(self, trace, outputs, options, *, source_path, component, output_path):
        parsed, policy, evidence = self._original.prepare(trace, outputs, options,
            source_path=source_path, component=component, output_path=output_path)
        # A disjoint accounting namespace, never a change to scientific UIDs.
        evidence = dict(evidence, parse_group=2 * evidence['parse_group'] + 1,
            parser_group_namespace='original_V6_odd', producer_event_certificate_used=False,
            entire_pool_original_V6_mode=self._old_mode,
            small_remainder_typed_self_checks=self._small_remainder_self_checks)
        return parsed, policy, evidence

    def prepare(self, trace, outputs, options, *, source_path, component, output_path=None):
        if self._old_mode:
            return self._fallback(trace, outputs, options, source_path=source_path,
                component=component, output_path=output_path)
        token = event_certificate(self._proof, source_path, trace)
        if token is None or not _source_constructor(self._proof, trace, outputs, source_path, output_path):
            return self._fallback(trace, outputs, options, source_path=source_path,
                component=component, output_path=output_path)
        remainder = _remainder(trace, outputs, options)
        if not self._groups and self._constructor_invocations == 0:
            # A deep/unsupported remainder can still be a legal V6 native
            # hit. Start the ENTIRE original pool at its first input rather
            # than leaving its native reference cold after a constructor
            # parse; wrapper parse-group compatibility must remain intact.
            self._small_remainder_self_checks += 1
            try:
                admitted = equivalent(remainder, remainder)
            except TypedIdentityUnsupported:
                admitted = False
            if not admitted:
                self._old_mode = True
                return self._fallback(trace, outputs, options, source_path=source_path,
                    component=component, output_path=output_path)
        for group in self._groups:
            if group['token'] is not token:
                continue
            try:
                equal = equivalent(group['remainder'], remainder)
            except TypedIdentityUnsupported:
                return self._fallback(trace, outputs, options, source_path=source_path,
                    component=component, output_path=output_path)
            if equal:
                # The successful reference parse established flatness. Same
                # certified events retain those exact corresponding four lists.
                parsed = _finish(dict(group['parsed']), trace, reused=True)
                self._constructor_hits += 1
                self._constructor_golden += int(parsed['own_golden_validation_performed'])
                return parsed, _policy(reused=True, small_checks=self._small_remainder_self_checks), dict(policy=POLICY, reused=True,
                    parse_group=group['index'], parser_group_namespace='constructor_even',
                    source_component=group['component'], complete_numeric_view_equal=True,
                    producer_event_certificate_used=True, events_byte_certificate_proven=True,
                    remainder_typed_equivalence_proven=True, whole_numeric_native_bytes_compared=False,
                    excluded_top_level_event_fields=list(JOIN_ONLY_EVENT_FIELDS),
                    original_raw_event_rows_modified=False, golden_validation_reused=False)
        if not _flat_retained_lists(trace['events']):
            return self._fallback(trace, outputs, options, source_path=source_path,
                component=component, output_path=output_path)
        parsed = _finish(_parse_rows(_mutable_rows(trace['events'], True), trace, outputs), trace, reused=False)
        index = 2 * self._constructor_invocations
        self._constructor_invocations += 1
        self._constructor_golden += int(parsed['own_golden_validation_performed'])
        # Publish only after every original parse/range/golden step succeeded.
        numeric = {name: parsed[name] for name in
            ('events', 'specs', 'marked_ranges', 'memory_ranges', 'output_ranges')}
        self._groups.append(dict(token=token, remainder=remainder, parsed=numeric, index=index, component=component))
        return parsed, _policy(reused=False, small_checks=self._small_remainder_self_checks), dict(policy=POLICY, reused=False,
            parse_group=index, parser_group_namespace='constructor_even', source_component=component,
            complete_numeric_view_equal=False, producer_event_certificate_used=True,
            events_byte_certificate_proven=True, remainder_typed_equivalence_proven=False,
            whole_numeric_native_bytes_compared=False,
            excluded_top_level_event_fields=list(JOIN_ONLY_EVENT_FIELDS),
            original_raw_event_rows_modified=False, golden_validation_reused=False)
