"""Private fresh-JSON identity proof; unchanged V4 parser and retained copies.

Public/unwitnessed use is the qualified V4 pool. The first native reference
retains V4 TREE. Fresh original JSON, strict UTF-8 and complete finite native
encoding replace the private optional typed-self/256-depth admission gate.
Exact byte equality is confined to the closed nonescaping constructor scope.
"""
from pathlib import Path

from script.execution.method_input_context import FrozenDict, FrozenList, current_context
from script.parsed_inputs.numeric_parser_reuse import (
    NumericParserPool as _StrictPool, numeric_view, _finish, JOIN_ONLY_EVENT_FIELDS,
)
from script.readonly_records.private_json_identity import (
    POLICY, current_witness, native_json_bytes, strict_utf8_source,
)

_OPTIONAL = (TypeError, ValueError, OverflowError, RecursionError, UnicodeError)


def _source_constructor(proof, trace, outputs, source_path, output_path):
    context = current_context()
    if proof is None or current_witness(context, 'sara') is not proof or output_path is None or source_path is None:
        return False
    source_path, output_path = Path(source_path).absolute(), Path(output_path).absolute()
    context.key(source_path)
    context.key(output_path)
    document = context._entry(source_path)['derived'].get('trace-document-v1')
    original_outputs = context._entry(output_path)['derived'].get('ordinary-json-v1')
    if (type(document) is not FrozenDict or type(trace) is not dict
            or document.get('events') is not trace.get('events') or original_outputs is not outputs
            or ('memory_ranges' in document and document['memory_ranges'] is not trace.get('memory_ranges'))
            or ('memory_ranges' not in document and 'memory_ranges' in trace)):
        return False
    if not (strict_utf8_source(proof, source_path, decoded_trace=True)
            and strict_utf8_source(proof, output_path)):
        return False
    if type(trace.get('events')) is not FrozenList:
        return False
    for row in trace['events']:
        if type(row) is not FrozenDict:
            return False
        for name in JOIN_ONLY_EVENT_FIELDS:
            if name in row and (type(row[name]) is not int or row[name] < 0):
                return False
    return True


def _native_hit_policy():
    return dict(policy=POLICY, proof_route='private_fresh_JSON_reference_guard_exact_bytes',
        immutable_borrow_enabled=True, fresh_original_JSON_constructor_proven=True,
        reference_complete_frozen_tree_guard_proven=True,
        reference_strict_typed_self_guard_proven=False, exact_native_JSON_bytes_equal=True,
        no_private_typed_self=True, private_optional_depth_256_gate=False,
        public_V4_strict_depth_policy_unchanged=True,
        candidate_complete_frozen_tree_walk_performed=False,
        candidate_general_typed_walk_performed=False,
        all_frozen_instance_attribute_dicts_proven_empty=True,
        frozen_attribute_proof='closed_original_JSON_constructor_not_candidate_graph_walk',
        exact_sara_GroupOwnInputContext_required=True,
        source_identity_checked_in_live_own_scope=True, file_origin_alone_grants_eligibility=False,
        parser_result_reused=True, event_row_and_retained_list_copy_performed=False,
        mutable_list_fields=['src_vals','src_regs','src_reg_uids','ea_base_src_indices'])


class NumericParserPool:
    def __init__(self, _proof=None):
        self._strict, self._proof, self._native = _StrictPool(), _proof, {}

    @property
    def invocations(self):
        return self._strict.invocations

    @property
    def reuse_hits(self):
        return self._strict.reuse_hits

    @property
    def golden_validations(self):
        return self._strict.golden_validations

    def prepare(self, trace, outputs, options, *, source_path, component, output_path=None):
        proof = self._proof
        eligible = _source_constructor(proof, trace, outputs, source_path, output_path)
        encoded = None
        if eligible and self._native:
            try:
                view = numeric_view(trace['events'], trace.get('memory_ranges', []), outputs, options)
                proof.stats['native_json_encodes'] += 1
                encoded = native_json_bytes(view)
            except _OPTIONAL:
                eligible = False
        if eligible and encoded is not None:
            for reference in self._native.values():
                proof.stats['exact_byte_comparisons'] += 1
                if encoded == reference['bytes']:
                    parsed = _finish(dict(reference['parsed']), trace, reused=True)
                    self._strict.reuse_hits += 1
                    self._strict.golden_validations += int(parsed['own_golden_validation_performed'])
                    proof.stats['exact_byte_equalities'] += 1
                    return parsed, _native_hit_policy(), dict(policy=POLICY, reused=True,
                        parse_group=reference['index'], source_component=reference['component'],
                        complete_numeric_view_equal=True,
                        excluded_top_level_event_fields=list(JOIN_ONLY_EVENT_FIELDS),
                        original_raw_event_rows_modified=False, golden_validation_reused=False,
                        proof_route='private_fresh_JSON_reference_guard_exact_bytes')
        result = self._strict.prepare(trace, outputs, options, source_path=source_path, component=component)
        parsed, policy, reuse = result
        if eligible and not reuse['reused'] and policy.get('whole_event_subtree_identity_proof') is True:
            index = reuse['parse_group']
            if index not in self._native:
                group = next((row for row in self._strict._groups if row['index'] == index), None)
                if group is not None:
                    proof.stats['reference_frozen_tree_guards'] += 1
                    # Fresh original JSON + strict UTF-8, the actual reference
                    # TREE and successful complete finite JSON encoding supply
                    # this private proof. No 256-depth/self-reflection gate runs.
                    try:
                        proof.stats['native_json_encodes'] += 1
                        guarded = native_json_bytes(group['view'])
                    except _OPTIONAL:
                        guarded = None
                    if guarded is not None:
                        self._native[index] = dict(bytes=guarded, parsed=group['parsed'],
                            index=index, component=group['component'])
        return result
