"""One method's immutable input reads, never a cross-method disk cache.

The production caller creates this context only after its own collector exits.
Every byte is opened/hashed once; subsequent consumers check the same regular
inode identity before reusing its bytes or parsed value. Nothing is persisted
or reused by another method, invocation, or validation-only reader.
"""
from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat


_CURRENT = ContextVar('sara_own_method_inputs', default=None)


def _immutable(*_args, **_kwargs):
    raise TypeError('own method parsed inputs are immutable; deepcopy before changing them')


class FrozenDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, memo):
        result = {}
        memo[id(self)] = result
        for key, value in self.items():
            result[deepcopy(key, memo)] = deepcopy(value, memo)
        return result


class FrozenList(list):
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = _immutable
    __iadd__ = __imul__ = _immutable

    def __deepcopy__(self, memo):
        result = []
        memo[id(self)] = result
        result.extend(deepcopy(value, memo) for value in self)
        return result


def freeze(value):
    if isinstance(value, (FrozenDict, FrozenList)):
        return value
    if isinstance(value, dict):
        return FrozenDict((key, freeze(item)) for key, item in value.items())
    if isinstance(value, list):
        return FrozenList(freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(freeze(item) for item in value)
    return value


def _identity(row):
    return (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns,
            row.st_ctime_ns, row.st_nlink)


class OwnInputContext:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if self.root != self.root.resolve(strict=True) or not self.root.is_dir():
            raise ValueError('own input context requires its actual fresh method directory')
        self._paths, self._entries, self._token = {}, {}, None
        self._closed = False
        self.stats = dict(physical_reads=0, physical_bytes=0, hash_reads=0,
            json_decodes=0, trace_transport_decodes=0, ledger_decodes=0,
            trace_decoded_bytes=0, trace_json_decodes=0, ledger_rows_decoded=0,
            ledger_validations=0, residency_builds=0, trusted_hardlinks=0,
            rf_def_use_decodes=0, shared_profile_decodes=0,
            raw_output_summary_decodes=0)

    def __enter__(self):
        if self._token is not None or self._closed or current_context() is not None:
            raise ValueError('one fresh nonnested own input context per method')
        self._token = _CURRENT.set(self)
        return self

    def __exit__(self, *_exc):
        _CURRENT.reset(self._token)
        self._token, self._closed = None, True
        self._entries.clear()

    def owns(self, path):
        try:
            Path(path).absolute().relative_to(self.root)
            return True
        except ValueError:
            return False

    def _stat(self, path):
        path = Path(path).absolute()
        if (self._closed or not self.owns(path)
                or path != path.resolve(strict=True)):
            raise ValueError('own input is outside this method or has a symlink ancestor')
        row = path.lstat()
        if not stat.S_ISREG(row.st_mode):
            raise ValueError('regular own method input required')
        return path, row

    def _entry(self, path):
        path, before = self._stat(path)
        identity = _identity(before)
        previous = self._paths.get(path)
        if previous is not None and previous != identity:
            raise ValueError('own method input changed after its verified read')
        entry = self._entries.get(identity)
        if entry is None:
            digest, parts, count = hashlib.sha256(), [], 0
            descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                if _identity(os.fstat(stream.fileno())) != identity:
                    raise ValueError('own method input changed at open')
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block); parts.append(block); count += len(block)
                if (_identity(os.fstat(stream.fileno())) != identity
                        or _identity(path.lstat()) != identity or path.resolve(strict=True) != path
                        or count != before.st_size):
                    raise ValueError('own method input changed during read')
            entry = dict(bytes=b''.join(parts), sha256=digest.hexdigest(), derived={},
                         counters=dict(physical_reads=1, hash_reads=1), path=path)
            self._entries[identity] = entry
            self.stats['physical_reads'] += 1
            self.stats['hash_reads'] += 1
            self.stats['physical_bytes'] += count
        self._paths[path] = identity
        return entry

    def check_size(self, path, maximum):
        """Apply the consumer's byte bound before a cache miss opens the file."""
        path, row = self._stat(path)
        if type(maximum) is not int or maximum <= 0 or row.st_size > maximum:
            raise ValueError('own input exceeds its declared consumer byte budget')
        previous = self._paths.get(path)
        if previous is not None and previous != _identity(row):
            raise ValueError('own method input changed after its verified read')
        return row.st_size

    def read_bytes(self, path):
        return self._entry(path)['bytes']

    def read_text(self, path):
        return self.cached(path, 'utf8-text-v1',
            lambda: self.read_bytes(path).decode('utf-8'))

    def digest(self, path):
        return self._entry(path)['sha256']

    def key(self, path):
        """Stable within the context, including an explicitly created alias."""
        self._entry(path)
        path = Path(path).absolute()
        return self._paths[path][:2]

    def cached(self, path, role, loader):
        entry = self._entry(path)
        if role not in entry['derived']:
            entry['derived'][role] = freeze(loader())
        return entry['derived'][role]

    def count(self, path, name, amount=1):
        if name not in self.stats or type(amount) is not int or amount < 0:
            raise ValueError('declared own input work counter required')
        entry = self._entry(path)
        self.stats[name] += amount
        entry['counters'][name] = entry['counters'].get(name, 0) + amount

    def read_json(self, path):
        def load():
            self.count(path, 'json_decodes')
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError('duplicate own input JSON key')
                    result[key] = value
                return result
            return json.loads(self.read_bytes(path), object_pairs_hook=pairs,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('nonfinite own input JSON')))
        return self.cached(path, 'ordinary-json-v1', load)

    def link_frozen(self, source, target):
        """Adopt only this explicit os.link ctime/nlink transition, never a write.

        Creating a hardlink changes the inode ctime. Reusing a cached value after
        arbitrary ctime changes is forbidden; this narrowly bracketed operation
        proves that os.link alone added exactly one alias to the same inode.
        """
        source, before = self._stat(source)
        entry = self._entry(source)
        target = Path(target).absolute()
        if not self.owns(target) or target.exists() or target.is_symlink():
            raise ValueError('fresh own companion hardlink required')
        if target.parent != target.parent.resolve(strict=True):
            raise ValueError('companion directory symlink forbidden')
        old = _identity(before)
        # _entry already checked this exact stat snapshot; check immediately
        # before the link as well, to avoid adopting a prior external mutation.
        if _identity(source.lstat()) != old:
            raise ValueError('own input changed before companion link')
        os.link(source, target, follow_symlinks=False)
        after, alias = source.lstat(), target.lstat()
        new = _identity(after)
        if (new[:4] != old[:4] or after.st_nlink != before.st_nlink + 1
                or _identity(alias) != new):
            raise ValueError('unexpected input identity change while creating companion link')
        self._entries.pop(old)
        self._entries[new] = entry
        for path, identity in list(self._paths.items()):
            if identity == old:
                self._paths[path] = new
        self._paths[target] = new
        self.stats['trusted_hardlinks'] += 1

    def verify_unchanged(self):
        for path, expected in self._paths.items():
            _, row = self._stat(path)
            if _identity(row) != expected:
                raise ValueError('own method input changed before aggregate persistence')

    def summary(self):
        return dict(schema='sara-own-method-input-reuse-v1', **self.stats,
            cross_method_reuse=False, cross_invocation_reuse=False,
            immutable_parsed_inputs=True, file_identity_checked_on_every_reuse=True,
            counters_scope='work performed by this live verified input context; not total process allocations',
            file_counters_are_per_verified_inode_shared_by_aliases=True,
            retained_physical_bytes=sum(len(row['bytes']) for row in self._entries.values()),
            retained_trace_payload_bytes=sum(len(row['derived']['trace-payload-v1'][0])
                for row in self._entries.values() if 'trace-payload-v1' in row['derived']),
            files=[dict(path=str(path.relative_to(self.root)), sha256=self._entries[identity]['sha256'],
                        same_verified_inode_as=str(self._entries[identity]['path'].relative_to(self.root)),
                        counters=dict(self._entries[identity]['counters']))
                   for path, identity in sorted(self._paths.items())])


def current_context(path=None):
    context = _CURRENT.get()
    return context if path is None or (context is not None and context.owns(path)) else None


def file_digest(path):
    context = current_context(path)
    if context is not None:
        return context.digest(path)
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read_json(path):
    context = current_context(path)
    return context.read_json(path) if context is not None else json.loads(Path(path).read_text())


def read_text(path):
    context = current_context(path)
    return context.read_text(path) if context is not None else Path(path).read_text()
