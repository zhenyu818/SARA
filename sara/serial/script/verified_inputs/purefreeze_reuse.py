"""Private publication adapter for fresh original trace JSON only.

The fixed trace_transport overlay calls this immediately after its unchanged
_json(payload).  This is a pinned producer/closed-driver contract, not a Python
security sandbox or a public raw-dict cache API.  No generic freeze algorithm,
JSON codec, numerical parser, or classifier is replaced.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from script.execution.method_input_context import (
    FrozenDict, FrozenList, current_context, freeze,
)
from script.input_pool.shared_input_pool import GroupOwnInputContext
from script.readonly_records.private_json_identity import (
    current_witness, native_json_bytes, strict_utf8_source,
)


POLICY = 'closed-fresh-JSON-corresponding-event-subtree-freeze-reuse-with-producer-token-v2'
JOIN_FIELDS = ('dynamic_warp_instruction_uid', 'instruction_issue_cycle')
_ACTIVE = ContextVar('serial_joint_v8_purefreeze_scope', default=None)
_OPTIONAL = (TypeError, ValueError, OverflowError, RecursionError, UnicodeError)


class _Scope:
    __slots__ = ('context', 'method', 'proof', 'active', 'closed', 'reference', 'encoded',
                 'reference_source', 'reference_sidecar', 'reference_sidecar_present', 'stats',
                 'reference_token', 'publications', 'certificate_counts')

    def __init__(self, context, method, proof):
        self.context, self.method, self.proof = context, method, proof
        self.active, self.closed = True, False
        self.reference, self.encoded = None, None
        self.reference_source = self.reference_sidecar = None
        self.reference_sidecar_present = False
        self.reference_token = object()
        self.publications = {}
        self.certificate_counts = dict(registered_publications=0, certificates_issued=0, certificate_misses=0)
        self.stats = dict(documents_seen=0, eligible_documents=0, reference_full_freezes=0,
            native_json_encodes=0, exact_byte_comparisons=0, event_subtree_reuses=0,
            reused_event_rows=0, original_fallback_publications=0)

    def receipt(self):
        """Safe after exit: scalar work evidence, never a cached input graph."""
        return dict(policy=POLICY, method=self.method, stats=dict(self.stats),
            scope_closed=self.closed, retained_reference_subtrees=self.reference is not None,
            exact_native_bytes_not_hash=True, correspondence='event_index_and_own_field_key',
            excluded_top_level_event_fields=list(JOIN_FIELDS), own_key_order_and_presence_preserved=True,
            whole_document_reuse=False, root_extras_and_memory_ranges_original_freeze=True,
            helper_claims_complete_numeric_input_identity=False, helper_runs_numeric_TREE=False,
            helper_claims_reference_TREE_passed=False, generic_freeze_algorithm_changed=False,
            caller_preloaded_context_accepted=False, cross_method_reuse=False,
            cross_invocation_reuse=False, source='unchanged_original_trace_json_constructor',
            producer_provenance=dict(self.certificate_counts,
                retained_map_entries=len(self.publications), reference_token_retained=self.reference_token is not None,
                actual_cached_document_and_events_identity_required=True,
                live_private_scope_and_reference_token_required=True))


@contextmanager
def purefreeze_scope(context, method, *, _proof):
    """Enable before bindings, inside the existing fresh V6 private witness."""
    if (type(context) is not GroupOwnInputContext or current_context() is not context
            or context.method != method or method not in ('sara', 'gerem')
            or current_witness(context, method) is not _proof or _proof is None
            or context._token is None or context._closed or context._entries or context._paths
            or _ACTIVE.get() is not None):
        raise ValueError('purefreeze scope requires the fresh exact private method Group before any own read')
    state = _Scope(context, method, _proof)
    token = _ACTIVE.set(state)
    try:
        yield state
    finally:
        state.active, state.closed = False, True
        state.reference = state.encoded = state.context = state.proof = None
        state.reference_source = state.reference_sidecar = None
        state.reference_token = None
        state.publications.clear()
        _ACTIVE.reset(token)


def _current():
    state = _ACTIVE.get()
    if (type(state) is _Scope and state.active and not state.closed
            and type(state.context) is GroupOwnInputContext
            and current_context() is state.context
            and current_witness(state.context, state.method) is state.proof):
        return state
    return None


def _verify_reference(state):
    state.context.key(state.reference_source)
    if state.reference_sidecar.exists() != state.reference_sidecar_present:
        raise ValueError('trace_sidecar_presence_or_identity_changed')
    if state.reference_sidecar_present:
        state.context.key(state.reference_sidecar)


def _publish(state, path, document):
    sidecar = Path(str(path) + '.completeness.json')
    present = state.context._entry(path)['derived'].get('trace-sidecar-dependency-v1') is not None
    state.publications[path] = (document, document['events'], state.reference_token, sidecar, present)
    state.certificate_counts['registered_publications'] += 1
    return document


def event_certificate(_proof, source_path, trace):
    """Opaque event-equivalence token from the actual private publication only.

    Public/raw/mismatched cached objects cannot mint a certificate.  A token is
    not a parse result: its consumer must still prove the complete remainder,
    original retained-list flatness and successful original parse/own golden.
    """
    state = _current()
    if state is None or state.proof is not _proof or source_path is None or type(trace) is not dict:
        return None
    path = Path(source_path).absolute()
    state.context.key(path)  # Registered source changes stay hard refusals.
    row = state.publications.get(path)
    document = state.context._entry(path)['derived'].get('trace-document-v1')
    if (row is None or document is not row[0] or dict.get(document, 'events') is not row[1]
            or dict.get(trace, 'events') is not row[1] or row[2] is not state.reference_token):
        state.certificate_counts['certificate_misses'] += 1
        return None
    _verify_reference(state)
    if row[3].exists() != row[4]:
        raise ValueError('trace_sidecar_presence_or_identity_changed')
    if row[4]:
        state.context.key(row[3])
    state.certificate_counts['certificates_issued'] += 1
    return row[2]


def reuse_trace_document(path, payload, document):
    """Called only by the fixed overlay after each own original _json succeeds.

    Inactive/public paths return the original value to the unchanged cached()
    freeze.  Fresh JSON construction supplies native types, empty attributes
    and an alias-free tree; this helper does not walk arbitrary Python objects.
    """
    state = _current()
    if state is None:
        return document
    context = state.context
    path = Path(path).absolute()
    context.key(path)  # Registered inode/content changes must remain refusals.
    state.stats['documents_seen'] += 1
    stored = context._entry(path)['derived'].get('trace-payload-v1')
    if (context.root_for(path) is None or type(stored) is not tuple or len(stored) != 2
            or type(payload) is not bytes or stored[0] is not payload
            or type(document) is not dict or type(document.get('events')) is not list):
        state.stats['original_fallback_publications'] += 1
        return document
    events = document['events']
    if any(type(row) is not dict or any(name in row and
            (type(row[name]) is not int or row[name] < 0) for name in JOIN_FIELDS) for row in events):
        state.stats['original_fallback_publications'] += 1
        return document
    if not strict_utf8_source(state.proof, path, decoded_trace=True):
        state.stats['original_fallback_publications'] += 1
        return document
    # Only these two event-top-level join fields are absent from this complete
    # ordered projection. Nested same-name fields and every unknown field stay.
    view = [{key: value for key, value in row.items() if key not in JOIN_FIELDS}
            for row in events]
    try:
        state.stats['native_json_encodes'] += 1
        encoded = native_json_bytes(view)
    except _OPTIONAL:
        state.stats['original_fallback_publications'] += 1
        return document
    state.stats['eligible_documents'] += 1
    if state.reference is None:
        # First reference is the original full freeze, not a new tree codec.
        frozen = freeze(document)
        state.reference, state.encoded = frozen['events'], encoded
        state.reference_source = path
        state.reference_sidecar = Path(str(path) + '.completeness.json')
        state.reference_sidecar_present = (context._entry(path)['derived'].get(
            'trace-sidecar-dependency-v1') is not None)
        state.stats['reference_full_freezes'] += 1
        return _publish(state, path, frozen)
    # A consumer cannot borrow a stale original producer, including its
    # original transport-sidecar presence/identity. These refusals are not
    # optional cache misses and therefore stay outside the encoding fallback.
    _verify_reference(state)
    state.stats['exact_byte_comparisons'] += 1
    if encoded != state.encoded:
        state.stats['original_fallback_publications'] += 1
        return document
    # Corresponding first-JSON containers are distinct within that document.
    # Borrow each position once; never intern equal values across rows/fields.
    borrowed = FrozenList(FrozenDict((key, freeze(value) if key in JOIN_FIELDS else reference[key])
        for key, value in own.items()) for own, reference in zip(events, state.reference))
    result = FrozenDict((key, borrowed if key == 'events' else freeze(value))
        for key, value in document.items())
    state.stats['event_subtree_reuses'] += 1
    state.stats['reused_event_rows'] += len(events)
    return _publish(state, path, result)
