"""Actual three/four-component own inputs; no invented N/A capture.

The qualified four-root constructor is retained verbatim by using its original
class. Three-root groups use a separate, explicit type and never gain the old
four-root producer-certificate privilege merely through inheritance.
"""
from pathlib import Path

from script.execution.method_input_context import FrozenDict, OwnInputContext
from script.input_pool.shared_input_pool import GroupOwnInputContext


THREE_COMPONENTS = ('rf', 'l1d', 'l2')
FOUR_COMPONENTS = ('rf', 'smem', 'l1d', 'l2')


class ThreeGroupOwnInputContext(GroupOwnInputContext):
    """Original byte-pool methods, explicit actual three-root constructor."""

    def __init__(self, own_roots, *, method, extra_files=()):
        if type(method) is not str or method not in ('sara', 'gerem'):
            raise ValueError('one explicit sara or gerem method required')
        if type(own_roots) is not dict or set(own_roots) != set(THREE_COMPONENTS):
            raise ValueError('exactly the actual rf/l1d/l2 own roots required')
        roots = []
        for component in THREE_COMPONENTS:
            root = Path(own_roots[component]).absolute()
            if root != root.resolve(strict=True) or not root.is_dir():
                raise ValueError('canonical actual component own directory required')
            if any(root == other or root in other.parents or other in root.parents
                   for _name, other in roots):
                raise ValueError('component own roots must be distinct and disjoint')
            roots.append((component, root))
        if type(extra_files) not in (list, tuple):
            raise ValueError('explicit external file sequence required')
        external = []
        for value in extra_files:
            path = Path(value).absolute()
            if path != path.resolve(strict=True) or not path.is_file() or path in external:
                raise ValueError('unique canonical exact external input file required')
            external.append(path)
        self._root_items, self._external_files = tuple(roots), tuple(external)
        OwnInputContext.__init__(self, roots[0][1])
        self.root = None
        self._method = method
        self.own_roots = FrozenDict(roots)
        self.extra_files = tuple(external)
        self._content_bytes, self._shared_values = {}, {}
        self.stats.update(content_byte_reuses=0, shared_parse_hits=0,
                          shared_derived_hits=0, shared_derived_builds=0)


def components_for(own_roots):
    if type(own_roots) is not dict:
        raise ValueError('explicit component mapping required')
    names = set(own_roots)
    if names == set(FOUR_COMPONENTS):
        return FOUR_COMPONENTS
    if names == set(THREE_COMPONENTS):
        return THREE_COMPONENTS
    raise ValueError('only actual original three/four-component groups admitted')


def make_context(own_roots, *, method, extra_files=()):
    components = components_for(own_roots)
    cls = GroupOwnInputContext if components == FOUR_COMPONENTS else ThreeGroupOwnInputContext
    return cls(own_roots, method=method, extra_files=extra_files)
