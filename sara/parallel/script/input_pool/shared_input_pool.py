"""One method invocation's explicit four-root immutable input pool.

This is an opt-in OwnInputContext subclass, not a replacement or monkeypatch.
Enter it inside the complete method window, before binding the four captures.
Every distinct inode is still opened and hashed; content reuse starts only
after that file's own stable read. No discovery, persistent cache, FI lookup,
cross-method reuse or cross-invocation reuse occurs here.

Only the built-in JSON/UTF-8 readers automatically share pure byte parsing.
The legacy cached()/key() APIs retain their inode-based dependency semantics.
share_derived() is explicit: its caller must enumerate every file dependency
and every effective parameter, preserve required validation, and only return
an immutable data tree. A role name alone never authorizes certificate reuse.
"""
import json
import math
from pathlib import Path

from script.execution.method_input_context import (
    FrozenDict, FrozenList, OwnInputContext, current_context, freeze,
)


COMPONENTS = ('rf', 'smem', 'l1d', 'l2')


def _plain_json(value, active=None):
    """Copy exact JSON types without custom mapping/list callbacks or NaNs."""
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError('finite typed JSON parameters required')
        return value
    if active is None:
        active = set()
    kind = type(value)
    if kind not in (dict, list, FrozenDict, FrozenList):
        raise ValueError('exact typed JSON parameters required')
    if kind in (FrozenDict, FrozenList):
        attrs = object.__getattribute__(value, '__dict__')
        if type(attrs) is not dict or dict.__len__(attrs):
            raise ValueError('unattributed frozen JSON parameter required')
    identity = id(value)
    if identity in active:
        raise ValueError('acyclic JSON parameters required')
    active.add(identity)
    try:
        if kind in (dict, FrozenDict):
            result = {}
            for key, item in dict.items(value):
                if type(key) is not str:
                    raise ValueError('exact string JSON parameter keys required')
                result[key] = _plain_json(item, active)
            return result
        return [_plain_json(item, active) for item in list.__iter__(value)]
    finally:
        active.remove(identity)


def _freeze_shared(value, active=None):
    """Deep-freeze data, including nested values of already Frozen objects.

    Mutable/custom backend instances are deliberately unsupported. Tuples and
    bytes are allowed for the original decoded transport/data-tree shapes.
    """
    if value is None or type(value) in (str, bytes, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError('finite shared data required')
        return value
    kind = type(value)
    if kind not in (dict, list, tuple, FrozenDict, FrozenList):
        raise ValueError('shared derived values must be immutable data trees')
    if kind in (FrozenDict, FrozenList):
        attrs = object.__getattribute__(value, '__dict__')
        if type(attrs) is not dict or dict.__len__(attrs):
            raise ValueError('unattributed frozen shared data required')
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise ValueError('acyclic shared data required')
    active.add(identity)
    try:
        if kind in (dict, FrozenDict):
            rows = []
            for key, item in dict.items(value):
                if type(key) is not str:
                    raise ValueError('shared data tree keys must be exact strings')
                rows.append((key, _freeze_shared(item, active)))
            return FrozenDict(rows)
        items = tuple(_freeze_shared(item, active) for item in
                      (tuple.__iter__(value) if kind is tuple else list.__iter__(value)))
        return items if kind is tuple else FrozenList(items)
    finally:
        active.remove(identity)


class GroupOwnInputContext(OwnInputContext):
    """Four disjoint own roots and exact optional external master files.

    own_roots maps rf/smem/l1d/l2 to their actual original input directories.
    extra_files grants only those exact existing files, never their parents.
    These declarations must come from the reviewed scientific input manifest;
    callers must not admit FI/private/result files as scientific dependencies.
    Ordinary source helpers observe this instance through the original
    ContextVar activation. SARA and GEREM must each create a fresh instance.
    """
    def __init__(self, own_roots, *, method, extra_files=()):
        if type(method) is not str or method not in ('sara', 'gerem'):
            raise ValueError('one explicit sara or gerem method required')
        if type(own_roots) is not dict or set(own_roots) != set(COMPONENTS):
            raise ValueError('exactly four explicit component own roots required')
        roots = []
        for component in COMPONENTS:
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
        super().__init__(roots[0][1])
        self.root = None  # A group is never represented as one ordinary root.
        self._method = method
        self.own_roots = FrozenDict(roots)
        self.extra_files = tuple(external)
        self._content_bytes, self._shared_values = {}, {}
        self.stats.update(content_byte_reuses=0, shared_parse_hits=0,
                          shared_derived_hits=0, shared_derived_builds=0)

    @property
    def method(self):
        return self._method

    def root_for(self, path):
        path = Path(path).absolute()
        for _component, root in self._root_items:
            if path == root or root in path.parents:
                return root
        raise ValueError('path is not inside one declared component own root')

    def owns(self, path):
        try:
            absolute = Path(path).absolute()
            return (absolute in self._external_files or
                    any(absolute == root or root in absolute.parents
                        for _component, root in self._root_items))
        except (TypeError, ValueError):
            return False

    def _entry(self, path):
        if self._token is None or current_context() is not self:
            raise ValueError('group input reads require its live externally activated scope')
        entry = super()._entry(path)
        if 'group_content_key' not in entry:
            signature = (len(entry['bytes']), entry['sha256'])
            if signature in self._content_bytes:
                entry['bytes'] = self._content_bytes[signature]
                self.stats['content_byte_reuses'] += 1
            else:
                self._content_bytes[signature] = entry['bytes']
            entry['group_content_key'] = signature
        return entry

    def _check_shared_sources(self, row):
        # Recheck the original producer/dependency aliases as well as the new
        # consumer's own aliases; a late external write never stays hidden.
        for path in row['sources']:
            self._entry(path)

    def _parsed(self, path, role, loader):
        entry = self._entry(path)
        key = ('builtin-byte-parse', role, entry['group_content_key'])
        if role in entry['derived']:
            row = self._shared_values.get(key)
            if row is not None and entry['derived'][role] is row['value']:
                self._check_shared_sources(row)
                source = Path(path).absolute()
                if source not in row['sources']:
                    row['sources'] += (source,)
            return entry['derived'][role]
        if key in self._shared_values:
            row = self._shared_values[key]
            self._check_shared_sources(row)
            source = Path(path).absolute()
            if source not in row['sources']:
                row['sources'] += (source,)
            self.count(path, 'shared_parse_hits')
        else:
            row = dict(value=freeze(loader()), sources=(Path(path).absolute(),))
            self._shared_values[key] = row
        entry['derived'][role] = row['value']
        return row['value']

    def read_text(self, path):
        return self._parsed(path, 'utf8-text-v1',
                            lambda: self.read_bytes(path).decode('utf-8'))

    def read_json(self, path):
        def load():
            self.count(path, 'json_decodes')
            def pairs(items):
                value = {}
                for key, item in items:
                    if key in value:
                        raise ValueError('duplicate own input JSON key')
                    value[key] = item
                return value
            return json.loads(self.read_bytes(path), object_pairs_hook=pairs,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('nonfinite own input JSON')))
        return self._parsed(path, 'ordinary-json-v1', load)

    def share_derived(self, path, role, loader, *, dependencies, parameters):
        """Explicit full-dependency, full-parameter immutable derived reuse.

        dependencies is an exact mapping of semantic loader roles to actual
        file paths. The primary path is also always keyed. Every consumer's
        own dependency inode is read/hashed and checked before a hit. The
        caller must include all trace/sidecar/config/ledger/source bindings
        consumed by loader, plus complete effective parameters (including
        collection and semantic/native source identity when relevant).
        Absent-file dependencies are not represented by this API: callers
        must retain their original presence/closure validation on every use.
        This API neither validates a scientific model nor supplies old answers.
        """
        if type(role) is not str or not role or not callable(loader):
            raise ValueError('explicit derived loader role and callback required')
        if type(dependencies) is not dict or not dependencies:
            raise ValueError('complete explicit file dependency roles required')
        if any(type(name) is not str or not name for name in dependencies):
            raise ValueError('exact nonempty dependency role names required')
        if type(parameters) not in (dict, FrozenDict):
            raise ValueError('complete typed JSON parameter mapping required')
        parameter_key = json.dumps(_plain_json(parameters), sort_keys=True,
                                   separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        entry = self._entry(path)
        sources = [Path(path).absolute()]
        dependency_keys = []
        for name in sorted(dependencies):
            source = Path(dependencies[name]).absolute()
            dependency = self._entry(source)
            dependency_keys.append((name, dependency['group_content_key']))
            sources.append(source)
        key = ('explicit-derived', role, entry['group_content_key'],
               tuple(dependency_keys), parameter_key)
        if key in self._shared_values:
            row = self._shared_values[key]
            self._check_shared_sources(row)
            row['sources'] += tuple(source for source in sources if source not in row['sources'])
            self.count(path, 'shared_derived_hits')
            return row['value']
        self.count(path, 'shared_derived_builds')
        value = _freeze_shared(loader())
        # A loader cannot publish a value after mutating one of its bindings.
        for source in sources:
            self._entry(source)
        self._shared_values[key] = dict(value=value, sources=tuple(sources))
        return value

    def summary(self):
        if self._closed:
            raise ValueError('closed group input context has no live summary')
        files = []
        for path, identity in sorted(self._paths.items()):
            entry = self._entries[identity]
            component = next((name for name, root in self._root_items
                              if path == root or root in path.parents), None)
            files.append(dict(path=str(path), component=component,
                relative_path=(str(path.relative_to(self.own_roots[component]))
                               if component is not None else None),
                explicit_external_file=path in self._external_files,
                bytes=len(entry['bytes']), sha256=entry['sha256'],
                same_verified_inode_as=str(entry['path']), counters=dict(entry['counters'])))
        payloads = {id(row['derived']['trace-payload-v1'][0]): row['derived']['trace-payload-v1'][0]
                    for row in self._entries.values() if 'trace-payload-v1' in row['derived']}
        return dict(schema='sara-group-own-method-input-reuse-v1', method=self.method,
            own_roots={name: str(root) for name, root in self._root_items},
            explicit_external_files=[str(path) for path in self._external_files],
            **self.stats, cross_method_reuse=False, cross_invocation_reuse=False,
            immutable_parsed_inputs=True, file_identity_checked_on_every_reuse=True,
            automatic_cross_inode_roles=['ordinary-json-v1', 'utf8-text-v1'],
            legacy_cached_roles_remain_per_verified_inode=True,
            explicit_derived_requires_complete_dependencies_and_parameters=True,
            counters_scope='actual work in this live method group; not total process allocations',
            file_counters_are_per_verified_inode_shared_by_aliases=True,
            retained_physical_bytes=sum(len(value) for value in self._content_bytes.values()),
            retained_physical_bytes_scope='distinct verified content bytes retained by this pool',
            retained_trace_payload_bytes=sum(len(value) for value in payloads.values()),
            retained_trace_payload_bytes_scope='distinct legacy trace payload byte objects retained by this pool',
            files=files)

    def __exit__(self, *exc):
        try:
            return super().__exit__(*exc)
        finally:
            self._content_bytes.clear()
            self._shared_values.clear()
