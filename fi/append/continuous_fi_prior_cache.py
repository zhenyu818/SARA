"""Administrative sealed-FI summaries; never open an old point chunk or run.log.

The caller owns the uninterrupted original locks and real lifetime change guard.
Production provenance is historical scientific evidence, not a new raw-log audit.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

SCHEMA = 'sara-continuous-FI-sealed-prior-cache-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z')
RANGES = ((0, 1000), (1000, 5000), (5000, 10000))
OUTCOMES = ('Masked', 'SDC', 'DUE')
ORIGINAL_ADAPTERS = {
    '1cd7cd5c424b45180ce18f4adb4c995d38547564be79ac9b6a7a86d28d4d223e':
        '64ab4d5c4f464edc5c8b72cc0cbeb9c5aa137bdd37be489c9b98930c221ea9d7',
    '5b95804546679f169fbc06e4ca6e9bccb70820128ef565dae6b4372477b43d6d':
        'c9f118fa39f3246f09c68e58c55791c74894c44e14a463353d0c4dd20c50a1d6',
    '85867c5ce04daadd05befd73463f7a51e27a7448b3afe818fd6cba9d404736af':
        '55106629a5ffe3fe48dbd93489b35965dbc2daa5dbb187fe54e4fe16c2b28aa3'}
OWNER_KEYS = {'application', 'architecture', 'component', 'source_id',
    'native_manifest_sha256', 'master_sha256', 'master_fingerprint',
    'population_fingerprint', 'descriptor_fingerprint', 'dispatch_inputs_sha256',
    'population_inventory_sha256', 'untimed', 'timeout', 'watchdog_factor', 'jobs'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('utf-8')).hexdigest()


def regular(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(strict=True)
        and stat.S_ISREG(path.lstat().st_mode), 'canonical regular cache input required')
    return path


def pin(path):
    path = regular(path)
    before = path.stat(); raw = path.read_bytes(); after = path.stat()
    need(all(getattr(before, key) == getattr(after, key) for key in
        ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')),
        'cache metadata changed while reading')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def relative(name):
    need(isinstance(name, str) and '\\' not in name and ':' not in name,
        'canonical metadata-relative name required')
    value = PurePosixPath(name)
    need(not value.is_absolute() and value.as_posix() == name
        and all(part not in ('', '.', '..') for part in name.split('/')),
        'unsafe metadata-relative name')
    return value


def _owner(owner):
    need(isinstance(owner, dict) and set(owner) == OWNER_KEYS,
        'exact sealed-cache owner fields required')
    need(owner['source_id'] in ORIGINAL_ADAPTERS and owner['architecture'] in ('SM75', 'SM86')
        and owner['component'] in ('rf', 'smem', 'l1d', 'l2')
        and type(owner['untimed']) is bool and type(owner['jobs']) is int
        and 1 <= owner['jobs'] <= 64 and type(owner['timeout']) is int and owner['timeout'] > 0
        and type(owner['watchdog_factor']) is int and owner['watchdog_factor'] > 0,
        'invalid sealed-cache source/cohort/counter owner')
    for key in ('native_manifest_sha256', 'master_sha256', 'master_fingerprint',
                'population_fingerprint', 'descriptor_fingerprint', 'dispatch_inputs_sha256'):
        need(isinstance(owner[key], str) and HEX.fullmatch(owner[key]), 'invalid owner SHA: ' + key)
    need((owner['population_inventory_sha256'] is None) is (not owner['untimed'])
        and (not owner['untimed'] or (owner['component'] in ('l1d', 'l2')
        and isinstance(owner['population_inventory_sha256'], str)
        and HEX.fullmatch(owner['population_inventory_sha256']))), 'exact resident cohort binding required')


def _sealed(root, expected_files, owner, bounds, adapter, source, preceding, master):
    """Read only fixed committed JSON indices/summary/cost bytes, never records."""
    need(isinstance(expected_files, dict) and expected_files, 'committed metadata byte pins required')
    root = Path(root)
    need(root == root.resolve(strict=True) and root.is_dir() and not root.is_symlink(),
        'canonical prior directory required')
    files = {}
    for name, expected in expected_files.items():
        relative(name)
        allowed = name in {'campaign.json', 'fi_completion.json', 'aggregate.json',
            'cumulative-aggregate.json', 'performance-window.json'} or bool(
            re.fullmatch(r'performance-partial[^/]*\.json', name)) or bool(
            re.fullmatch(r'checkpoints/batch-[0-9]+/index\.json', name)) or bool(
            re.fullmatch(r'dispatch-batches/[^/]+\.(started|settled)\.json', name))
        need(allowed and isinstance(expected, dict) and set(expected) == {'bytes', 'sha256'}
            and type(expected['bytes']) is int and expected['bytes'] >= 0
            and isinstance(expected['sha256'], str) and HEX.fullmatch(expected['sha256']),
            'only exact committed summary/checkpoint-index/cost refs accepted')
        actual = pin(root/name)
        need(actual == expected, 'committed prior metadata SHA differs: ' + name)
        files[name] = actual
    required = {'campaign.json', 'fi_completion.json', 'aggregate.json', 'cumulative-aggregate.json'}
    need(required <= set(files), 'missing required committed prior summary')
    read = lambda name: json.loads(regular(root/name).read_text())
    identity, seal, aggregate, cumulative = (read(name) for name in
        ('campaign.json', 'fi_completion.json', 'aggregate.json', 'cumulative-aggregate.json'))
    prefix = identity.get('prefix', {}); begin, end = bounds
    need(identity.get('schema') == 'sara-FI-aggregate-with-untimed-evidence-v1'
        and identity.get('target_count') == end-begin
        and identity.get('manifest_fingerprint') == owner['master_fingerprint']
        and identity.get('performance_measurement') is (not owner['untimed'])
        and identity.get('dispatch_inputs_sha256') == owner['dispatch_inputs_sha256']
        and identity.get('spec', {}).get('population_fingerprint') == owner['population_fingerprint']
        and identity['spec'].get('input_fingerprint') == owner['descriptor_fingerprint']
        and identity['spec'].get('timeout_seconds') == owner['timeout']
        and identity['spec'].get('validation_only') is owner['untimed']
        and identity['spec'].get('cache_execution_model') == 'functional-snapshot-cache-v3'
        and identity['spec'].get('simulation_cycle_watchdog', {}).get('factor') == owner['watchdog_factor']
        and prefix.get('schema') == 'sara-FI-append-only-range-v1'
        and prefix.get('range') == [begin, end] and prefix.get('cumulative_prefix') == end
        and prefix.get('full_master_fingerprint') == owner['master_fingerprint']
        and prefix.get('segment_manifest_fingerprint') == fingerprint(master['trials'][begin:end])
        and prefix.get('FI_workers') == owner['jobs']
        and prefix.get('population_inventory_sha256') == owner['population_inventory_sha256']
        and prefix.get('source_id') == source
        and prefix.get('adapter_sha256') == adapter and prefix.get('preceding_seals') == preceding
        and prefix.get('parent_master_sha256') == owner['master_sha256']
        and prefix.get('native_manifest_sha256') == owner['native_manifest_sha256']
        and all(prefix.get(key) == owner[key] for key in ('application', 'architecture', 'component')),
        'prior owner/range/adapter/master/preceding summary differs')
    counts = aggregate.get('counts')
    need(isinstance(counts, dict) and set(counts) == set(OUTCOMES)
        and all(type(counts[key]) is int and counts[key] >= 0 for key in OUTCOMES)
        and sum(counts.values()) == end-begin and aggregate.get('count') == end-begin
        and aggregate.get('complete') is True and seal.get('status') == 'complete'
        and seal.get('aggregate') == aggregate
        and aggregate.get('identity_fingerprint') == fingerprint(identity),
        'sealed prior count/counts/identity differs')
    cumulative_counts = {key: counts[key] + sum(row['counts'][key] for row in preceding)
        for key in OUTCOMES}
    need(seal.get('cumulative_file') == 'cumulative-aggregate.json'
        and seal.get('cumulative_sha256') == files['cumulative-aggregate.json']['sha256']
        and cumulative.get('schema') == 'sara-FI-prefix-cumulative-aggregate-v1'
        and cumulative.get('count') == end and cumulative.get('counts') == cumulative_counts
        and cumulative.get('latest_segment_range') == [begin, end]
        and cumulative.get('parent_master_sha256') == owner['master_sha256']
        and cumulative.get('identity_fingerprint') == fingerprint(identity)
        and cumulative.get('complete') is True, 'sealed prior cumulative counters differ')
    actual_indices = {p.relative_to(root).as_posix() for p in (root/'checkpoints').glob('batch-*/index.json')}
    indices = {name for name in files if name.startswith('checkpoints/')}
    need(indices and indices == actual_indices, 'complete exact committed checkpoint-index set required')
    need(all(folder.is_dir() and (folder/'index.json').is_file()
        for folder in (root/'checkpoints').glob('batch-*')), 'unsealed old checkpoint retained')
    committed_count = 0
    for name in sorted(indices):
        index = read(name)
        need(index.get('schema') == 'sara-validation-point-chunks-v1' and index.get('method') == 'FI'
            and index.get('identity') == identity and index.get('identity_fingerprint') == fingerprint(identity)
            and index.get('chunk_size') == 64 and index.get('performance_measurement') is False
            and type(index.get('records')) is int and 0 < index['records'] <= 64
            and isinstance(index.get('chunks'), list) and index['chunks']
            and all(item.get('path') == 'points-%06d.json' % number
                and type(item.get('records')) is int and 0 < item['records'] <= 64
                and isinstance(item.get('sha256'), str) and HEX.fullmatch(item['sha256'])
                for number, item in enumerate(index['chunks']))
            and sum(item['records'] for item in index['chunks']) == index['records'],
            'committed checkpoint-index identity/count differs')
        committed_count += index['records']
    need(committed_count == end-begin, 'committed checkpoint count differs from original sealed aggregate')
    costs = {p.name for p in root.glob('performance-partial*.json')}
    if not owner['untimed']:
        costs.add('performance-window.json')
    else:
        need(not costs and not (root/'performance-window.json').exists(), 'untimed parent has measured clock')
    need(costs == {name for name in files if name.startswith('performance-')},
        'exact original prior cost receipt set required')
    attempts = set()
    for name in costs:
        receipt = read(name); task = receipt.get('task', {})
        attempt = task.get('performance_attempt_id')
        need(receipt.get('method') == 'FI' and receipt.get('performance_measurement') is True
            and task.get('campaign_identity') == fingerprint(identity) and isinstance(attempt, str)
            and attempt not in attempts, 'foreign or duplicate original FI cost attempt')
        attempts.add(attempt)
        if name == 'performance-window.json':
            need(receipt.get('aggregate_fsynced') is True and receipt.get('complete') is True
                and receipt.get('partial') is False and receipt.get('aggregate_file') == 'aggregate.json'
                and receipt.get('component') == owner['component'],
                'original final FI timing receipt is incomplete')
    actual_journals = {p.relative_to(root).as_posix() for p in (root/'dispatch-batches').glob('*.json')}
    journals = {name for name in files if name.startswith('dispatch-batches/')}
    need(actual_journals == journals and journals, 'exact original settled batch journals required')
    for name in sorted(n for n in journals if n.endswith('.started.json')):
        settled = name.replace('.started.json', '.settled.json')
        need(settled in journals, 'unsettled original FI batch retained')
        started, ended = read(name), read(settled)
        planned, submitted, completed = (started.get('trial_ids'), ended.get('submitted_trial_ids'),
            ended.get('completed_trial_ids'))
        need(started.get('campaign_identity') == fingerprint(identity)
            and ended.get('started_fingerprint') == fingerprint(started)
            and ended.get('status') in ('complete_batch', 'unfinished')
            and all(isinstance(ids, list) for ids in (planned, submitted, completed))
            and 1 <= len(planned) <= 64 and all(isinstance(tid, str) for ids in
                (planned, submitted, completed) for tid in ids)
            and all(re.fullmatch(r'trial-[0-9]{8}', tid) and begin <= int(tid[6:]) < end for tid in planned)
            and len(set(planned)) == len(planned) and len(set(submitted)) == len(submitted)
            and len(set(completed)) == len(completed) and set(completed) <= set(submitted) <= set(planned)
            and (ended['status'] != 'complete_batch' or submitted == completed == planned)
            and (started.get('performance_attempt_id') is None or started['performance_attempt_id'] in attempts),
            'original committed batch journal identity/counter differs')
    summary = dict(range=[begin, end], parent_master_sha256=owner['master_sha256'],
        campaign_sha256=files['campaign.json']['sha256'], seal_sha256=files['fi_completion.json']['sha256'],
        aggregate_sha256=files['aggregate.json']['sha256'], cumulative_sha256=files['cumulative-aggregate.json']['sha256'],
        count=end-begin, counts=dict(counts), identity_fingerprint=fingerprint(identity),
        cost_receipts={name: files[name]['sha256'] for name in sorted(costs)},
        complete_raw_logs_and_checkpoints_verified=True, previous_draws_executed_again=False)
    return summary, files, committed_count


def build_prior_cache(*, segments, owner, master, baseline_sha256, run_id, freeze_binding_sha256,
                      current_adapter_sha256, source_context):
    """Caller supplies actual published/newly-sealed metadata pins, not raw logs.

    segments: exact earlier order, each {root,container_root,source_id,adapter_sha256,
    expected_files,production_provenance}. No write, import or scientific API.
    """
    _owner(owner)
    need(isinstance(master, dict) and fingerprint(master) == owner['master_fingerprint']
        and master.get('population_fingerprint') == owner['population_fingerprint']
        and isinstance(master.get('trials'), list) and len(master['trials']) == 10000,
        'actual original full10K master data required; never synthesize trials')
    _source_context(source_context, owner['source_id'], baseline_sha256, run_id, freeze_binding_sha256)
    need(all(isinstance(value, str) and HEX.fullmatch(value) for value in
        (baseline_sha256, freeze_binding_sha256, current_adapter_sha256))
        and isinstance(run_id, str) and RUN.fullmatch(run_id), 'actual baseline/run/freeze/adapter binding required')
    need(isinstance(segments, list) and len(segments) in (1, 2), 'one or two actual prior segments required')
    rows, summaries, roots = [], [], set()
    for number, row in enumerate(segments):
        need(isinstance(row, dict) and set(row) == {'root', 'container_root', 'source_id',
            'adapter_sha256', 'expected_files', 'production_provenance'}, 'exact prior input descriptor required')
        bounds = RANGES[number]
        root = Path(row['root']); alias = row['container_root']
        need(root.is_absolute() and str(root) not in roots and isinstance(alias, str)
            and alias.startswith('/') and '\\' not in alias and PurePosixPath(alias).as_posix() == alias
            and '..' not in PurePosixPath(alias).parts, 'distinct canonical prior root and container alias required')
        roots.add(str(root))
        legacy = (owner['application'], owner['architecture'], owner['component'], owner['untimed'], number) == (
            'GELU', 'SM75', 'rf', False, 0)
        source = row['source_id']; adapter = row['adapter_sha256']
        need(source == owner['source_id'] or (legacy and source == next(iter(ORIGINAL_ADAPTERS))),
            'only fixed GELU source07 first1K ownership exception allowed')
        need(adapter == ORIGINAL_ADAPTERS[source] or (number > 0 and source == owner['source_id']
            and adapter == current_adapter_sha256), 'actual original or current prior adapter identity required')
        provenance = row['production_provenance']
        need(isinstance(provenance, dict) and set(provenance) == {'path', 'bytes', 'sha256'}
            and pin(provenance['path']) == {key: provenance[key] for key in ('bytes', 'sha256')},
            'actual closed scientific production metadata provenance required')
        summary, files, count = _sealed(root, row['expected_files'], owner, bounds, adapter, source, summaries, master)
        rows.append(dict(range=list(bounds), original_root=str(root), container_root=alias,
            source_id=source, adapter_sha256=adapter, files=files, committed_count=count,
            counts=summary['counts'], summary=summary, production_provenance=provenance))
        summaries.append(summary)
    return dict(schema=SCHEMA, baseline_sha256=baseline_sha256, run_id=run_id,
        freeze_binding_sha256=freeze_binding_sha256, current_adapter_sha256=current_adapter_sha256,
        owner=dict(owner), segments=rows, source_context=source_context, historical_raw_verified_at_production=True,
        raw_logs_or_point_records_reopened_by_cache_builder=False,
        validity_requires_uninterrupted_original_locks_and_live_change_guard=True)


def load_verified_prior_cache(args, master, descriptor, *, source_id, native_sha, fingerprint_fn):
    path = regular(args.verified_prior_cache)
    need(os.statvfs(path).f_flag & os.ST_RDONLY, 'prior cache must be mounted actually read-only')
    need(pin(path)['sha256'] == args.verified_prior_cache_sha256, 'externally pinned prior cache SHA differs')
    cache = json.loads(path.read_text())
    need(set(cache) == {'schema', 'baseline_sha256', 'run_id', 'freeze_binding_sha256',
        'current_adapter_sha256', 'owner', 'segments', 'source_context', 'historical_raw_verified_at_production',
        'raw_logs_or_point_records_reopened_by_cache_builder',
        'validity_requires_uninterrupted_original_locks_and_live_change_guard'}
        and cache['schema'] == SCHEMA and cache['baseline_sha256'] == args.continuous_baseline_sha256
        and cache['run_id'] == args.continuous_run_id and cache['freeze_binding_sha256'] == args.continuous_freeze_sha256
        and cache['current_adapter_sha256'] == args.adapter_sha256
        and cache['historical_raw_verified_at_production'] is True
        and cache['raw_logs_or_point_records_reopened_by_cache_builder'] is False
        and cache['validity_requires_uninterrupted_original_locks_and_live_change_guard'] is True,
        'prior cache schema/run/baseline/freeze/adapter binding differs')
    owner = dict(application=args.application, architecture=args.architecture, component=args.component,
        source_id=source_id, native_manifest_sha256=native_sha, master_sha256=args.master_sha256,
        master_fingerprint=fingerprint_fn(master), population_fingerprint=master['population_fingerprint'],
        descriptor_fingerprint=fingerprint_fn(descriptor), dispatch_inputs_sha256=args.dispatch_inputs_sha256,
        population_inventory_sha256=args.population_inventory_sha256, untimed=args.untimed,
        timeout=args.timeout, watchdog_factor=args.watchdog_factor, jobs=args.jobs)
    _owner(owner); need(cache['owner'] == owner, 'prior cache master/source/cohort/owner differs')
    expected = RANGES[:RANGES.index((args.begin, args.end))]
    need(len(cache['segments']) == len(expected) == len(args.prior_segment), 'cached earlier range count differs')
    summaries = []
    for row, root, seal_sha, bounds in zip(cache['segments'], args.prior_segment, args.prior_seal_sha256, expected):
        root = Path(root)
        need(str(root) == row['container_root'] and row['range'] == list(bounds)
            and row['files']['fi_completion.json']['sha256'] == seal_sha, 'cached range/root/seal differs')
        summary, files, count = _sealed(root, row['files'], owner, bounds,
            row['adapter_sha256'], row['source_id'], summaries, master)
        need(row['summary'] == summary and row['files'] == files and row['committed_count'] == count
            and row['counts'] == summary['counts'], 'cached committed summary/counters differ')
        summaries.append(summary)
    return cache


def cached_counts(cache, number, root, identity):
    row = cache['segments'][number]
    need(str(root) == row['container_root'] and fingerprint(identity) == row['summary']['identity_fingerprint'],
        'cached current prior identity differs')
    return row['committed_count'], dict(row['counts'])


def _source_context(value, source_id, baseline, run_id, freeze):
    need(isinstance(value, dict) and set(value) == {'schema', 'source_id', 'scientific_files',
        'baseline_sha256', 'run_id', 'freeze_binding_sha256', 'owned_adoption'}
        and value['schema'] == 'sara-continuous-frozen-source-context-v1'
        and value['source_id'] == source_id and value['baseline_sha256'] == baseline
        and value['run_id'] == run_id and value['freeze_binding_sha256'] == freeze
        and source_id in ORIGINAL_ADAPTERS and isinstance(baseline, str) and HEX.fullmatch(baseline)
        and isinstance(freeze, str) and HEX.fullmatch(freeze)
        and isinstance(run_id, str) and RUN.fullmatch(run_id),
        'exact actual frozen-source context scope required')
    files = value['scientific_files']
    need(isinstance(files, dict) and len(files) == 850
        and all(isinstance(name, str) and isinstance(sha, str) and HEX.fullmatch(sha)
            for name, sha in files.items())
        and hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest() == source_id,
        'complete frozen850 source map identity differs')
    return files


def make_source_context(*, source_id, scientific_files, baseline_sha256, run_id,
                        freeze_binding_sha256, owned_adoption=None):
    value = dict(schema='sara-continuous-frozen-source-context-v1', source_id=source_id,
        scientific_files=dict(scientific_files), baseline_sha256=baseline_sha256,
        run_id=run_id, freeze_binding_sha256=freeze_binding_sha256, owned_adoption=owned_adoption)
    _source_context(value, source_id, baseline_sha256, run_id, freeze_binding_sha256)
    return value


def source_context(args, source_id):
    path = regular(args.verified_prior_cache)
    need(os.statvfs(path).f_flag & os.ST_RDONLY and pin(path)['sha256'] == args.verified_prior_cache_sha256,
        'externally pinned read-only source/prior cache required')
    value = json.loads(path.read_text())
    need(value.get('schema') == SCHEMA and value.get('baseline_sha256') == args.continuous_baseline_sha256
        and value.get('run_id') == args.continuous_run_id
        and value.get('freeze_binding_sha256') == args.continuous_freeze_sha256
        and value.get('current_adapter_sha256') == args.adapter_sha256,
        'frozen-source cache baseline/run/freeze/current adapter differs')
    files = _source_context(value['source_context'], source_id, args.continuous_baseline_sha256,
        args.continuous_run_id, args.continuous_freeze_sha256)
    return value['source_context'], files


def cached_source_files(args, source_id, code_root):
    need(os.statvfs(code_root).f_flag & os.ST_RDONLY, 'frozen scientific code must be mounted read-only')
    return source_context(args, source_id)[1]


class FrozenOwnedAdoption:
    """Exact already completed GELU07 FI/G fact, protected by the live host freeze.

    This is a new administrative cache consumer, not the old full-tree reader.
    Only the old small provenance/campaign/master are reopened; old raw trees are not.
    """
    def __init__(self, args):
        from owned_adoption import (OLD_SOURCE, NEW_SOURCE, NATIVE_SHA, IMAGE, OLD_ADAPTER,
            MASTER_SHA, PACKET_SHA, PREPARED_SHA, EXECUTION, CHANGES, SCOPE)
        need((args.application, args.architecture, args.component, args.untimed) ==
            ('GELU', 'SM75', 'rf', False), 'frozen owned context is only GELU SM75 RF')
        context, new = source_context(args, NEW_SOURCE)
        cached = context['owned_adoption']
        need(isinstance(cached, dict) and set(cached) == {'provenance_sha256',
            'old_source_files', 'original_fi_identity', 'metadata_files'}, 'exact historical GELU fact cache required')
        self.args = args; self.path = regular(args.owned_provenance); self.root = self.path.parent
        self.sha256 = args.owned_provenance_sha256
        need(self.sha256 == cached['provenance_sha256'] ==
            '81914533c3e19c3e5c1a58c98e5a2b6c3516ffbb821b948e5c83366d10611ec8'
            and pin(self.path)['sha256'] == self.sha256, 'actual original GELU provenance byte pin differs')
        self.value = json.loads(self.path.read_text()); p = self.value; old = cached['old_source_files']
        need(p.get('schema') == 'sara-GELU-source08-owned-method-adoption-v1' and p.get('status') == 'complete'
            and p.get('scope') == SCOPE and p.get('original_source_id') == OLD_SOURCE
            and p.get('current_source_id') == NEW_SOURCE and p.get('native_manifest_sha256') == NATIVE_SHA
            and p.get('image') == IMAGE and p.get('old_clocks_modified') is False
            and p.get('old_jobs_executed_again') is False and p.get('failed_rates_scientific_inputs_reused') is False,
            'original GELU adoption source/master/clock facts differ')
        need(isinstance(old, dict) and len(old) == len(new) == 850 and set(old) == set(new)
            and hashlib.sha256(json.dumps(old, sort_keys=True).encode()).hexdigest() == OLD_SOURCE
            and {name: (old[name], new[name]) for name in old if old[name] != new[name]} == CHANGES
            and all(old.get(name) == new.get(name) == sha for name, sha in EXECUTION.items()),
            'fixed GELU old/current source execution relation differs')
        self.trees = {method: self.root/('00001000/'+method) for method in ('FI', 'GEREM')}
        need(set(p.get('trees', {})) == set(self.trees)
            and all(p['trees'][method].get('path') == '00001000/'+method for method in self.trees),
            'original GELU method roots differ')
        self.fi_identity = cached['original_fi_identity']
        need(self.fi_identity.get('prefix', {}).get('source_id') == OLD_SOURCE
            and self.fi_identity['prefix'].get('adapter_sha256') == OLD_ADAPTER
            and self.fi_identity['prefix'].get('parent_master_sha256') == MASTER_SHA
            and self.fi_identity.get('dispatch_inputs_sha256') == PACKET_SHA
            and self.fi_identity.get('spec', {}).get('execution_code') == EXECUTION,
            'original GELU FI execution/master identity differs')
        self.metadata_files = cached['metadata_files']
        need(isinstance(self.metadata_files, dict) and self.metadata_files,
            'original GELU named metadata facts required')
        roles = p.get('roles', {})
        need(set(roles) == {'old_source_files', 'new_source_files', 'native_manifest', 'old_prepared',
            'compatibility', 'old_failed_terminal', 'old_failed_guard', 'old_FI_adapter', 'full_master',
            'dispatch_packet', 'failed_rates_partial', 'failed_rates_resource', 'failed_rates_container',
            'failed_rates_request'}, 'original GELU named evidence roles differ')
        for role, sha in (('full_master', MASTER_SHA), ('dispatch_packet', PACKET_SHA), ('old_prepared', PREPARED_SHA)):
            need(p.get('files', {}).get(roles[role], {}).get('sha256') == sha,
                'original GELU role pin differs: '+role)
        self.verify_unchanged()

    def fi_owner(self, root, begin, end, *, untimed=False):
        from owned_adoption import OLD_SOURCE, NEW_SOURCE, OLD_ADAPTER
        old = Path(root).resolve(strict=True) == self.trees['FI']/'output/path/fi'
        if old:
            need(not untimed and [begin, end] == [0, 1000], 'owned source07 applies only to original FI interval')
            return OLD_SOURCE, OLD_ADAPTER
        return NEW_SOURCE, None

    def bind_master(self, path):
        from owned_adoption import MASTER_SHA
        need(pin(path)['sha256'] == MASTER_SHA, 'owned current master differs')

    def verify_unchanged(self):
        context, _ = source_context(self.args, self.value['current_source_id'])
        need(pin(self.path)['sha256'] == self.sha256
            and context['owned_adoption']['original_fi_identity'] == self.fi_identity,
            'frozen GELU provenance/cache changed')
        for name, expected in self.metadata_files.items():
            relative(name)
            need(not name.endswith('/run.log') and '/checkpoints/' not in name
                and pin(self.root/name) == expected, 'original GELU named metadata bytes changed')
        need(json.loads(regular(self.trees['FI']/'output/path/fi/campaign.json').read_text()) == self.fi_identity,
            'original GELU FI campaign bytes differ')


def cached_owned(args):
    need((args.owned_provenance is None) == (args.owned_provenance_sha256 is None),
        'owned provenance path and SHA required together')
    return None if args.owned_provenance is None else FrozenOwnedAdoption(args)
