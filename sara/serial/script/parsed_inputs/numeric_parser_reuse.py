"""Private, invocation-local reuse of the unchanged numeric parser.

Only two TOP-LEVEL event fields are outside its consumed-input closure:
dynamic_warp_instruction_uid and instruction_issue_cycle. The original raw
rows are retained intact for each cache strict join. Every other field,
including unknown extras and nested occurrences of those names, stays in the
complete typed comparison. No answer, golden check or classifier is cached.
"""
from script.core import batch_backward as batch
from script.core import reg_observed_analyzer as backward
from script.core.exact_sdc_prepare_input import _mark_output_stores
from script.core.sparse_global_image import semantic_image, validate_golden_image
from script.execution.method_input_context import FrozenList
from script.reverse_group_base.group_event_adaptation import _own_group_source
from script.typed_records.typed_identity import equivalent, TypedIdentityUnsupported


JOIN_ONLY_EVENT_FIELDS = ('dynamic_warp_instruction_uid','instruction_issue_cycle')
POLICY = 'complete_numeric_parser_input_equivalence_except_two_top_level_cache_join_fields'


def _copy_policy(eligible, *, reused):
    if not eligible:
        return dict(policy='legacy_one_whole_event_graph_deepcopy',
            immutable_borrow_enabled=False,fallback_preserves_container_aliases_and_cycles=True,
            parser_result_reused=False,event_graph_copy_performed=True)
    return dict(policy=('sara_group_complete_numeric_parser_input_equivalence_reuses_existing_parse'
            if reused else 'sara_group_context_proven_frozen_alias_free_JSON_tree_row_and_retained_list_copy'),
        immutable_borrow_enabled=True,mutable_list_fields=list(batch._EVENT_MUTABLE_LIST_FIELDS),
        whole_event_subtree_identity_proof=True,all_frozen_instance_attribute_dicts_proven_empty=True,
        file_origin_alone_grants_eligibility=False,exact_sara_GroupOwnInputContext_required=True,
        source_identity_checked_in_live_own_scope=True,parser_result_reused=reused,
        event_row_and_retained_list_copy_performed=not reused)


def numeric_view(events, memory_ranges, outputs, options):
    """Call only AFTER the original complete event-tree proof succeeds."""
    return dict(events=[{name:value for name,value in dict.items(row)
                        if name not in JOIN_ONLY_EVENT_FIELDS}
                       for row in list.__iter__(events)],
        memory_ranges=memory_ranges,outputs=outputs,numerical_options=options)


def _mutable_rows(events,eligible):
    if not eligible:
        return batch._legacy_event_deepcopy(events)
    result = []
    for row in list.__iter__(events):
        copied = dict.copy(row)
        for field in batch._EVENT_MUTABLE_LIST_FIELDS:
            if type(dict.get(row,field)) is FrozenList:
                copied[field] = list.copy(dict.__getitem__(row,field))
        result.append(copied)
    return result


def _parse_rows(raw,trace,outputs):
    # Original order and functions. No normalized value or output flag is ever
    # written into the immutable original or the complete comparison view.
    raw = batch.normalize_predicate_register_values(raw)
    specs = outputs.get('output_spec',outputs.get('outputs',outputs)) if isinstance(outputs,dict) else outputs
    if not isinstance(specs,list) or not specs:
        raise ValueError('complete actual output range list required')
    marked = [dict(row,base=backward.parse_int(row['base']),
        size=int(row.get('bytes',row.get('size',0)))) for row in specs]
    _mark_output_stores(raw,marked)
    events = [backward.parse_event(row,index) for index,row in enumerate(raw)]
    return dict(events=events,specs=specs,marked_ranges=marked)


def _finish(parsed,trace,*,reused):
    # Original golden-before-range-parser order, separately for EVERY own
    # image. Neither the image contract nor golden scan is a pooled result.
    image = trace.get('initial_global_image')
    support = validate_golden_image(parsed['events'],image) if image is not None else None
    if not reused:
        parsed['memory_ranges'] = backward.parse_memory_ranges(trace.get('memory_ranges',[]))
        parsed['output_ranges'] = backward.parse_output_ranges(parsed['specs'])
    parsed.update(image=image,image_present='initial_global_image' in trace,
        image_support=support,semantic_image=semantic_image(image) if image is not None else None,
        own_golden_validation_performed=image is not None)
    return parsed


class NumericParserPool:
    """One private SARA preparation; never retain across method invocations.

    Parsed objects are private/read-only consumers' inputs. No caller callback
    or mutable prepared object may escape between admission and projection.
    A miss, unsupported comparison, alias or attributed input always runs the
    original parser and its ordinary validation/refusal behavior.
    """
    def __init__(self):
        self._groups = []
        self.invocations = 0
        self.reuse_hits = 0
        self.golden_validations = 0

    def prepare(self,trace,outputs,options,*,source_path,component):
        original = trace['events']
        # The qualified v2 source guard keeps identity errors outside fallback.
        context = _own_group_source(source_path)
        eligible = context is not None and batch._frozen_event_tree(original)
        view = None
        if eligible and type(trace) is dict:
            view = numeric_view(original,trace.get('memory_ranges',[]),outputs,options)
        reason = None
        if view is not None:
            for group in self._groups:
                try:
                    equal = equivalent(group['view'],view)
                except TypedIdentityUnsupported as error:
                    reason = str(error)
                    break
                if equal:
                    parsed = _finish(dict(group['parsed']),trace,reused=True)
                    self.reuse_hits += 1
                    self.golden_validations += int(parsed['own_golden_validation_performed'])
                    return parsed,_copy_policy(True,reused=True),dict(
                        policy=POLICY,reused=True,parse_group=group['index'],
                        source_component=group['component'],complete_numeric_view_equal=True,
                        excluded_top_level_event_fields=list(JOIN_ONLY_EVENT_FIELDS),
                        original_raw_event_rows_modified=False,golden_validation_reused=False)
        parsed = _finish(_parse_rows(_mutable_rows(original,eligible),trace,outputs),trace,reused=False)
        self.golden_validations += int(parsed['own_golden_validation_performed'])
        index = self.invocations
        self.invocations += 1  # Actual successful original parser invocation.
        if view is not None and reason is None:
            numeric = {name:parsed[name] for name in
                ('events','specs','marked_ranges','memory_ranges','output_ranges')}
            self._groups.append(dict(view=view,parsed=numeric,index=index,component=component))
        return parsed,_copy_policy(eligible,reused=False),dict(policy=POLICY,reused=False,
            parse_group=index,source_component=component,complete_numeric_view_equal=False,
            false_or_uncompared_does_not_claim_full_tree_validation=True,
            excluded_top_level_event_fields=list(JOIN_ONLY_EVENT_FIELDS),
            original_raw_event_rows_modified=False,golden_validation_reused=False,
            optional_reuse_refusal=reason)
