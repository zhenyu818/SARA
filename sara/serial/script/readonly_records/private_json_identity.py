"""Private constructor witness for one closed, fresh method invocation.

This is a pinned-source entry contract, not a Python security sandbox. Public
wrappers never create a witness. No generic object codec or new type walker is
defined: callers retain the original constructor guards and compare exact
native JSON bytes only for their documented fresh JSON constructor domain.
The extra private typed-self/256-depth cache admission gate is retired in V6.
Public V4 strict identity, depth and malicious-object fallback are unchanged.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import json
from pathlib import Path

from script.execution.method_input_context import current_context
from script.input_pool.shared_input_pool import GroupOwnInputContext


POLICY = 'closed-fresh-JSON-constructor-full-native-bytes-no-private-reference-self-depth-gate-v6'
_ACTIVE = ContextVar('serial_joint_v6_private_json_witness', default=None)


class _Witness:
    __slots__ = ('context', 'method', 'active', 'stats', '_utf8')

    def __init__(self, context, method):
        self.context, self.method, self.active = context, method, True
        self._utf8 = {}
        self.stats = dict(reference_typed_self_guards=0, reference_frozen_tree_guards=0,
            native_json_encodes=0, exact_byte_comparisons=0, exact_byte_equalities=0,
            strict_utf8_source_checks=0)


@contextmanager
def _private_json_scope(context, method):
    """Called immediately after the closed driver's fresh Group.__enter__."""
    if (type(context) is not GroupOwnInputContext or current_context() is not context
            or context.method != method or method not in ('sara', 'gerem')
            or context._token is None or context._closed or context._entries
            or context._paths or _ACTIVE.get() is not None):
        raise ValueError('private JSON proof requires a fresh exact method Group before any own read')
    witness = _Witness(context, method)
    token = _ACTIVE.set(witness)
    try:
        yield witness
    finally:
        witness.active = False
        _ACTIVE.reset(token)


def current_witness(context, method):
    witness = _ACTIVE.get()
    if (type(witness) is _Witness and witness.active and witness.context is context
            and witness.method == method and type(context) is GroupOwnInputContext
            and current_context() is context and context.method == method
            and context._token is not None and not context._closed):
        return witness
    return None


def native_json_bytes(value):
    """Exact bytes, never a digest; domain admission remains the caller's job."""
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=False,
                      separators=(',', ':')).encode('ascii')


def strict_utf8_source(proof, path, *, decoded_trace=False):
    """Encoding-only constructor proof; invalid sources use the old fallback.

    json.loads(bytes) permits raw UTF-8 surrogate code units. Excluding that
    non-Unicode source form prevents ensure_ascii's surrogate-pair collision.
    This adds no JSON parse or new scientific refusal.
    """
    if (type(proof) is not _Witness
            or current_witness(proof.context, proof.method) is not proof):
        return False
    path = Path(path).absolute()
    key = proof.context.key(path)  # Registered identity changes must propagate.
    token = (key, bool(decoded_trace))
    if token not in proof._utf8:
        entry = proof.context._entry(path)
        if decoded_trace:
            payload = entry['derived'].get('trace-payload-v1')
            if type(payload) is not tuple or len(payload) != 2 or type(payload[0]) is not bytes:
                return False
            raw = payload[0]
        else:
            raw = entry['bytes']
        proof.stats['strict_utf8_source_checks'] += 1
        try:
            raw.decode('utf-8', 'strict')
            valid = True
        except UnicodeDecodeError:
            valid = False
        proof._utf8[token] = valid
    return proof._utf8[token]
