"""Complete typed equivalence without generating unused fingerprints.

True requires every field/value/type/order and every declared parsed-object
MRO slot to match. Plain/empty-attribute Frozen JSON containers keep the old
equivalence relation. Tuple/list, bool/int, float.hex including signed zero,
presence and exact parsed classes stay distinct. Aliases compare by value;
active-path cycles refuse. There is deliberately no container-identity fast
path, hash, tagged-tree allocation, serialization, or cross-call result cache.

False may stop at a difference and means only no admission, not that both
remaining subtrees were validated. Encountered malformed data raises the
explicit refusal below. All necessary work remains in the full method clock.
"""
import math
from types import MemberDescriptorType

from script.execution.method_input_context import FrozenDict, FrozenList


POLICY = 'complete-direct-strict-typed-equivalence-v1'
MAX_DEPTH = 256


class TypedIdentityUnsupported(ValueError):
    """An encountered value cannot establish a complete typed equivalence."""


def _need(value, message):
    if not value:
        raise TypedIdentityUnsupported(message)


def _frozen_attributes(value):
    attributes = object.__getattribute__(value, '__dict__')
    _need(type(attributes) is dict and dict.__len__(attributes) == 0,
          'attributed Frozen container cannot grant equivalence')


def _slot_names(cls):
    """Every MRO slot, without foreign iterators/properties/getter callbacks."""
    _need(type.__getattribute__(cls, '__dictoffset__') == 0,
          'parsed instance attribute dictionaries are not admitted')
    names = []
    for base in reversed(type.__getattribute__(cls, '__mro__')):
        namespace = type.__getattribute__(base, '__dict__')
        slots = namespace.get('__slots__', ())
        if type(slots) is str:
            slots = (slots,)
        _need(type(slots) is tuple or type(slots) is list,
              'opaque parsed-object slot declaration')
        iterator = tuple.__iter__(slots) if type(slots) is tuple else list.__iter__(slots)
        for name in iterator:
            _need(type(name) is str and name not in ('__dict__', '__weakref__')
                  and name not in names, 'opaque or ambiguous parsed-object slot')
            _need(type(namespace.get(name)) is MemberDescriptorType,
                  'parsed slot is not an ordinary declared member')
            names.append(name)
    _need(bool(names), 'parsed object has no complete declared slots')
    return tuple(names)


def _kind(value, object_types):
    kind = type(value)
    if value is None: return 'n'
    if kind is bool: return 'b'
    if kind is int: return 'i'
    if kind is float:
        _need(math.isfinite(value), 'nonfinite typed value')
        return 'f'
    if kind is str: return 's'
    if kind is FrozenDict or kind is FrozenList:
        _frozen_attributes(value)
    if kind is dict or kind is FrozenDict: return 'd'
    if kind is list or kind is FrozenList: return 'l'
    if kind is tuple: return 't'
    if any(kind is admitted for admitted in object_types): return 'o'
    # No custom type equality, repr, getters or iteration is invoked.
    raise TypedIdentityUnsupported('opaque/custom typed value')


def _same(left, right, object_types, schemas, left_active, right_active, depth):
    _need(depth <= MAX_DEPTH, 'complete typed equivalence depth bound exceeded')
    tag = _kind(left, object_types)
    if tag != _kind(right, object_types): return False
    if tag == 'n': return True
    if tag in ('b', 'i', 's'): return left == right
    if tag == 'f': return float.hex(left) == float.hex(right)
    if tag == 'o' and type(left) is not type(right): return False
    left_marker, right_marker = id(left), id(right)
    _need(left_marker not in left_active and right_marker not in right_active,
          'cyclic typed value')
    left_active.add(left_marker); right_active.add(right_marker)
    try:
        if tag == 'd':
            if dict.__len__(left) != dict.__len__(right): return False
            left_keys, right_keys = dict.keys(left), dict.keys(right)
            _need(all(type(key) is str for key in left_keys)
                  and all(type(key) is str for key in right_keys),
                  'non-string typed mapping key')
            left_keys, right_keys = sorted(left_keys), sorted(right_keys)
            if left_keys != right_keys: return False
            for key in left_keys:
                if not _same(dict.__getitem__(left,key),dict.__getitem__(right,key),
                             object_types,schemas,left_active,right_active,depth+1): return False
            return True
        if tag == 'l' or tag == 't':
            sequence = tuple if tag == 't' else list
            if sequence.__len__(left) != sequence.__len__(right): return False
            for a,b in zip(sequence.__iter__(left),sequence.__iter__(right)):
                if not _same(a,b,object_types,schemas,left_active,right_active,depth+1): return False
            return True
        cls = type(left)
        if cls not in schemas:
            # Structural declarations only, local to this single proof call.
            schemas[cls] = _slot_names(cls)
        for name in schemas[cls]:
            try:
                a = object.__getattribute__(left,name)
                b = object.__getattribute__(right,name)
            except AttributeError as error:
                raise TypedIdentityUnsupported('missing complete parsed-object slot: '+name) from error
            if not _same(a,b,object_types,schemas,left_active,right_active,depth+1): return False
        return True
    finally:
        left_active.remove(left_marker); right_active.remove(right_marker)


def equivalent(left, right, *, object_types=()):
    """Return True only after complete strict equality; never use is as proof.

    SARA supplies its fixed five actual parsed classes. GEREM leaves the empty
    default, preserving its original stricter JSON/tuple-only admission. This
    module never imports an analyzer for GEREM.
    """
    _need(type(object_types) is tuple and all(type(cls) is type for cls in object_types),
          'fixed exact parsed-object class tuple required')
    return _same(left,right,object_types,{},set(),set(),0)
