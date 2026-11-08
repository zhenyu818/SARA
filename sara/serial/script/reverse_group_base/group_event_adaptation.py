"""Opt-in event adaptation for one live, exact SARA Group context.

The caller supplies its original own trace path after normal timed preparation.
This module neither loads a trace nor changes normalization/parsing/validation.
It reuses the qualified v7 COMPLETE frozen-tree proof and one-whole-graph
legacy fallback. A Group type or an input SHA alone is never a tree proof.
"""
from pathlib import Path

from script.core import batch_backward as batch
from script.execution.method_input_context import FrozenList, current_context
from script.input_pool.shared_input_pool import GroupOwnInputContext


def _own_group_source(source_path):
    context = current_context()
    if (type(context) is not GroupOwnInputContext or source_path is None
            or context._token is None or context._closed is not False
            or context.method != 'sara'):
        return None
    # An unprovable/out-of-scope source only retains the old copy behavior.
    # root_for excludes Group extra_files: external files are not own traces.
    try:
        path = Path(source_path).absolute()
        root = GroupOwnInputContext.root_for(context, path)
        if current_context(path) is not context or root not in context.own_roots.values():
            return None
    except Exception:
        return None
    # Deliberately OUTSIDE the fallback catch. The original input API checks
    # canonical path/inode/size/timestamps and its stable read/hash. A changed
    # already registered source must fail, never silently become a copy hit.
    context.key(path)
    return context


def analysis_event_input(events, *, source_path=None):
    """Return mutable analysis rows and bounded implementation-only metadata.

    Only an exact, live, SARA GroupOwnInputContext owning source_path can reach
    the unmodified v7 proof. Context/scope ineligibility or a failed tree proof
    uses exactly one original whole-graph deepcopy, preserving aliases,
    cycles, custom deepcopy hooks and the original subsequent error behavior.
    The original own-source identity validator's errors still propagate.
    """
    context = _own_group_source(source_path)
    if context is None or not batch._frozen_event_tree(events):
        return batch._legacy_event_deepcopy(events), {
            'policy': 'legacy_one_whole_event_graph_deepcopy',
            'immutable_borrow_enabled': False,
            'fallback_preserves_container_aliases_and_cycles': True,
        }
    rows = []
    for row in list.__iter__(events):
        adapted = dict.copy(row)
        for name in batch._EVENT_MUTABLE_LIST_FIELDS:
            if type(dict.get(row, name)) is FrozenList:
                adapted[name] = list.copy(dict.__getitem__(row, name))
        rows.append(adapted)
    return rows, {
        'policy': 'sara_group_context_proven_frozen_alias_free_JSON_tree_row_and_retained_list_copy',
        'immutable_borrow_enabled': True,
        'mutable_list_fields': list(batch._EVENT_MUTABLE_LIST_FIELDS),
        'whole_event_subtree_identity_proof': True,
        'all_frozen_instance_attribute_dicts_proven_empty': True,
        'file_origin_alone_grants_eligibility': False,
        'exact_sara_GroupOwnInputContext_required': True,
        'source_identity_checked_in_live_own_scope': True,
    }
