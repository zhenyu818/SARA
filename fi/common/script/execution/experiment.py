#!/usr/bin/env python3
"""Public server-side CPU-only Docker runner. No private control paths.

Every scientific command, including preparation, comparison and plotting, is
executed in a separate bounded container. Prediction jobs cannot mount FI
records. This host program only checks identities and orchestrates files/jobs.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import threading
import time
import uuid

SOURCE = Path(__file__).resolve().parents[2]
PROFILE = Path('/etc/sara-execution.json')
APPLICATIONS = [
    ('GE-SpMM', 'spmm-empty-and-tail'), ('LayerNorm', 'layernorm-full-gpu'),
    ('Attention', 'attention-full-gpu'), ('Stencil1D', 'stencil-boundary'),
    ('Convolution1D', 'convolution-boundary'), ('Softmax', 'softmax-stable'),
    ('GELU', 'gelu-bias'), ('GEMM', 'gemm-nonsquare'),
    ('MatrixMultiplication', 'matrixmul-edge-tiles'), ('AdamW', 'adamw-independent-state'),
    ('Pathfinder', 'pathfinder-multilaunch'), ('Dijkstra', 'dijkstra-diamond'),
    ('MatrixFactorization', 'mf-colliding-ratings'), ('Render', 'render-ray-casting')]
ARCHITECTURES = {
    'SM75': ('sm_75', 'configs/study/SM75',
             'fc3b02fe010b93a5aa87ac33a9e5e1394a274ba6fea767c3328e51a319beb5c7'),
    'SM86': ('sm_86', 'configs/study/SM86',
             '27ff9ac5add8ea2242560a6ed96e20adab55af0fd4bdc9f4055e95b492b56ac1')}
PREFIXES = {1000: (0, 1000), 5000: (1000, 5000), 10000: (5000, 10000)}
COMPLETED_COLLECTOR_CHANGES = {
    'src/cuda-sim/host_copy_observer.h': 'standalone storage profile omits unused numeric copy snapshots',
    'src/cuda-sim/cuda-sim.cc': 'standalone storage profile omits unused numeric launch parameters',
    'libcuda/cuda_runtime_api.cc': 'standalone storage profile omits unused numeric static initializers',
    'script/execution/experiment.py': 'verified preservation of complete original conditions only',
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def immutable_members(directory):
    """All original files, including actual outputs, clocks and source receipts."""
    members = {}
    for path in sorted(Path(directory).rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise RuntimeError('completed evidence must contain only regular files/directories')
        if path.is_file():
            members[str(path.relative_to(directory))] = sha(path)
    if not members:
        raise RuntimeError('empty completed evidence cannot be adopted')
    return members


def completed_code_contract(original, current, analysis_code, gerem_code, fi_code):
    """Admit only the declared collector/runner delta, not a new model."""
    if not original or set(original) != set(current):
        raise RuntimeError('completed condition scientific file set changed')
    changed = {name: {'original_sha256': old, 'current_sha256': current[name],
                      'declared_role': COMPLETED_COLLECTOR_CHANGES.get(name)}
        for name, old in original.items() if old != current[name]}
    if set(changed) - set(COMPLETED_COLLECTOR_CHANGES):
        raise RuntimeError('completed condition has an undeclared scientific source change')
    required_sara = {'script/core/batch_backward.py', 'script/core/reg_observed_analyzer.py',
        'script/core/sparse_global_image.py', 'script/core/closed_loop_transfer.py',
        'script/execution/compact_population.py', 'script/execution/population_inventory.py'}
    required_gerem = {'script/execution/batch_gerem.py', 'script/execution/gerem_campaign.py',
        'script/GEREM/gerem_storage_rf_smem.py', 'script/GEREM/gerem_storage_common.py',
        'script/execution/compact_population.py', 'script/execution/sara_batch_campaign.py'}
    required_fi = {'script/execution/batch_fi.py', 'script/execution/fi_campaign.py',
                   'script/common/outcome_oracle.py', 'script/execution/batch_workload.py'}
    maps = {'SARA_analysis': (analysis_code, required_sara), 'GEREM_rules': (gerem_code, required_gerem),
            'FI_execution': (fi_code, required_fi)}
    equal = {}
    for role, (observed, required) in maps.items():
        if not isinstance(observed, dict) or not required <= observed.keys():
            raise RuntimeError('missing actual completed model-code identity: ' + role)
        if any(original.get(name) != digest or current.get(name) != digest
               or name in COMPLETED_COLLECTOR_CHANGES for name, digest in observed.items()):
            raise RuntimeError('completed model rules differ from current bytes: ' + role)
        equal[role] = dict(observed)
    return {'equal_actual_model_code': equal, 'reviewed_collector_and_runner_changes': changed}


def completed_job_evidence(directory, *, image, profile, inspect_container=None):
    """Read terminal receipts without updating any original attempt file."""
    directory = Path(directory)
    request = read(directory / 'request.json')
    if request.get('image') != image or not isinstance(request.get('source'), str):
        raise RuntimeError('completed job source/image receipt differs')
    successes, receipts = [], []
    for attempt in sorted(directory.glob('attempt-*')):
        retained = read(attempt / 'container.json')
        actual = inspect_container(attempt) if inspect_container is not None else None
        for container in (retained, actual):
            if container is None:
                continue
            state, limits = container['State'], container['HostConfig']
            if (state.get('Running') is not False or state.get('Paused') is True
                    or state.get('Status') not in ('exited', 'dead') or container.get('Image') != image):
                raise RuntimeError('completed job has a live, unknown or foreign container')
            if (limits.get('Runtime') != 'runc' or limits.get('Devices') or limits.get('DeviceRequests')
                    or limits.get('Privileged') is not False or limits.get('Memory') != profile['memory_bytes']
                    or limits.get('MemorySwap') != profile['memory_bytes']
                    or limits.get('NanoCpus') != profile['cpus'] * 1000000000):
                raise RuntimeError('completed Docker resource/device boundary differs')
        record = read(attempt / 'job-resource.json')
        success = retained['State'].get('ExitCode') == 0 and retained['State'].get('OOMKilled') is False
        if actual is not None and actual['State'].get('ExitCode') != retained['State'].get('ExitCode'):
            raise RuntimeError('actual terminal state differs from retained receipt')
        if success:
            descriptor = record.get('execution_profile', {})
            if (record.get('schema_version') != 2 or record.get('exit_status') != 0
                    or record.get('child_exit_status') != 0 or record.get('limits_verified') is not True
                    or record.get('completion_resources_verified') is not True
                    or record.get('window_interrupted') is not False or record.get('interrupted_signals') != []
                    or any(descriptor.get(key) != value for key, value in profile.items())):
                raise RuntimeError('completed method lacks the identical uninterrupted server profile')
            for stage in ('cgroup_before', 'cgroup_after'):
                counters = record.get(stage, {})
                try:
                    quota, period = map(int, counters['cpu.max'].split())
                    events = dict(row.split() for row in counters['memory.events'].splitlines())
                    valid = (counters['version'] == 2 and period > 0 and quota == profile['cpus'] * period
                        and int(counters['memory.max']) == profile['memory_bytes']
                        and int(counters['memory.swap.max']) == 0
                        and {'oom', 'oom_kill'} <= events.keys()
                        and all(int(events.get(key, 0)) == 0 for key in ('oom', 'oom_kill', 'oom_group_kill')))
                except (KeyError, TypeError, ValueError):
                    valid = False
                if not valid:
                    raise RuntimeError('completed cgroup counters do not prove matching limits and zero OOM')
            successes.append(attempt.name)
        receipts.append({'attempt': attempt.name, 'successful': success,
            'container_sha256': sha(attempt / 'container.json'),
            'resource_sha256': sha(attempt / 'job-resource.json')})
    if len(successes) != 1:
        raise RuntimeError('exactly one successful original job receipt is required')
    return {'request_sha256': sha(directory / 'request.json'), 'attempts': receipts,
            'original_successful_attempt': successes[0]}


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    with tmp.open('w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def scientific_files(source):
    names = {}
    for folder in ('script', 'src', 'libcuda', 'libopencl', 'configs', 'test_apps'):
        for path in sorted((source / folder).rglob('*')):
            if (path.is_file() and '__pycache__' not in path.parts and
                    not any(part in ('result', 'results', 'build') for part in path.relative_to(source).parts)
                    and path.suffix not in ('.pyc', '.o', '.so', '.log')):
                names[str(path.relative_to(source))] = sha(path)
    for name in ('Dockerfile', 'Makefile', 'setup_environment', 'version'):
        names[name] = sha(source / name)
    return names


class StorageSampler:
    """Same external file-allocation sampler for every method, never a predictor."""
    interval = 2.0

    def __init__(self, roots):
        self.roots = roots
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.samples = 0
        self.maximum = 0
        self.final = 0
        self.cpu_seconds = 0.0
        self.scan_seconds = 0.0
        self.errors = []

    def sample(self):
        wall, cpu = time.perf_counter(), time.thread_time()
        seen, total = set(), 0
        for root in self.roots:
            for directory, _, names in os.walk(root, onerror=lambda error: self.errors.append(
                    type(error).__name__ + ': ' + str(error.errno) + ' ' + str(error.strerror))):
                for name in names:
                    try:
                        info = os.stat(Path(directory) / name, follow_symlinks=False)
                        inode = (info.st_dev, info.st_ino)
                        if stat.S_ISREG(info.st_mode) and inode not in seen:
                            seen.add(inode)
                            total += info.st_blocks * 512
                    except FileNotFoundError:
                        pass  # temporary files may disappear during a scan
                    except OSError as error:
                        self.errors.append(type(error).__name__ + ': ' + str(error.errno) + ' ' + str(error.strerror))
        self.final = total
        self.maximum = max(self.maximum, total)
        self.samples += 1
        self.cpu_seconds += time.thread_time() - cpu
        self.scan_seconds += time.perf_counter() - wall

    def loop(self):
        self.sample()
        while not self.stop.wait(self.interval):
            self.sample()
        self.sample()

    def finish(self):
        self.stop.set()
        self.thread.join()
        return {'sample_interval_seconds': self.interval, 'samples': self.samples,
                'sampled_peak_temporary_bytes': self.maximum,
                'final_owned_allocated_bytes': self.final,
                'external_monitor_CPU_seconds': self.cpu_seconds,
                'external_monitor_scan_wall_seconds': self.scan_seconds,
                'measurement_errors': self.errors,
                'scope': 'allocated file blocks (st_blocks*512), owned output plus attempt receipts; read-only input/native/source mounts excluded; includes retained result bytes as well as disposable scratch',
                'limitation': 'sampled lower bound, not exact instantaneous peak; transient files between scans and filesystem metadata/cache are not counted; scans are not atomic',
                'monitor_is_external_to_method_cgroup': True}


class Runner:
    def __init__(self, a):
        self.a = a
        info = PROFILE.stat()
        if (info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not stat.S_ISREG(info.st_mode) or PROFILE.is_symlink()):
            raise RuntimeError('root-owned read-only server execution marker required')
        self.profile = json.loads(PROFILE.read_text())
        if (set(self.profile) != {'schema', 'role', 'cpus', 'memory_bytes', 'swap_bytes', 'schedule'}
                or self.profile['schema'] != 'sara-execution-host-v1'
                or self.profile['role'] != 'bounded_primary' or self.profile['swap_bytes'] != 0
                or self.profile['schedule'] != 'always_open'):
            raise RuntimeError('a CPU-only bounded execution profile is required')
        self.cpus = self.profile['cpus']
        self.memory = self.profile['memory_bytes']
        physical = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        if not (1 <= self.cpus <= os.cpu_count() and self.memory <= physical * .9):
            raise RuntimeError('server profile must leave the host a memory reserve')
        self.storage = a.storage_root.resolve(strict=True)
        mounted = subprocess.check_output(['findmnt', '-rn', '-T', str(self.storage), '-o', 'UUID'], text=True).strip()
        target = subprocess.check_output(['findmnt', '-rn', '-T', str(self.storage), '-o', 'TARGET'], text=True).strip()
        if not a.mount_uuid or mounted != a.mount_uuid or Path(target).resolve() != self.storage:
            raise RuntimeError('the declared data filesystem is not actually mounted')
        self.work = a.work_root.resolve()
        self.work.relative_to(self.storage)
        self.work.mkdir(parents=True, exist_ok=True)
        self.code = a.source.resolve(strict=True)
        self.native = (a.native_root or self.work / 'native-build' / 'output' / 'runtime').resolve()
        self.reference_native = (a.reference_native_root or self.native).resolve()
        self.reference_campaign = a.reference_campaign.resolve(strict=True) if a.reference_campaign else None
        completed = getattr(a, 'completed_campaign', None)
        self.completed_campaign = completed.resolve(strict=True) if completed else None
        if self.completed_campaign == self.work:
            raise RuntimeError('completed preservation requires a distinct new campaign root')
        self.image = None
        self.source_files = scientific_files(self.code)
        self.source_id = hashlib.sha256(json.dumps(self.source_files, sort_keys=True).encode()).hexdigest()
        self.locks = []
        for path in (a.lock_file or [self.storage / '.sara-experiment.lock']):
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open('a+')
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.locks.append(handle)

    def guard(self):
        if (self.work / 'stop-dispatch').exists():
            raise RuntimeError('stop-dispatch exists; no new scientific job started')
        mounted = subprocess.check_output(['findmnt', '-rn', '-T', str(self.storage), '-o', 'UUID'], text=True).strip()
        target = subprocess.check_output(['findmnt', '-rn', '-T', str(self.storage), '-o', 'TARGET'], text=True).strip()
        if (mounted != self.a.mount_uuid or Path(target).resolve() != self.storage
                or shutil.disk_usage(self.storage).free < 10 * 1024**3):
            raise RuntimeError('data mount missing or less than 10 GiB free; no system-disk fallback')
        if scientific_files(self.code) != self.source_files:
            raise RuntimeError('scientific source changed while a campaign was running')
        if self.image is None:
            self.image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', self.a.image], text=True))[0]['Id']

    def check_native(self):
        sources = json.loads((self.native / 'compiled-source-files.json').read_text())
        if not sources or any(self.source_files.get(name) != value for name, value in sources.items()):
            raise RuntimeError('native runtime was not built from these current scientific sources')

    def adopt_reference(self, original, destination, *, kind, master=None):
        """Reuse immutable FI evidence/preparation; never rerun or re-time it."""
        self.guard()
        original, destination = Path(original), Path(destination)
        marker = destination / 'reference-adoption.json'
        if marker.exists():
            receipt = json.loads(marker.read_text())
            if receipt['original_directory'] != str(original) or receipt['kind'] != kind:
                raise RuntimeError('reference adoption changed')
            return True
        if not original.is_dir() or destination.exists():
            return False
        if not self.previous_success(original):
            return False
        if kind == 'FI':
            candidates = list((original / 'output/path/records').glob('*/campaign.json'))
            if len(candidates) != 1 or not any(candidates[0].parent.rglob('fi_completion.json')):
                raise RuntimeError('reference FI is not sealed')
            ref_master = original.parents[1] / 'identity.json'
            if not ref_master.is_file() or json.loads(ref_master.read_text())['master_sha256'] != sha(master):
                raise RuntimeError('reference FI uses another immutable master')
        members = {str(p.relative_to(original)): sha(p) for p in original.rglob('*') if p.is_file()}
        # Hard links preserve the original bytes/clocks without duplicate
        # cloud storage. No adopted input or FI file is subsequently modified.
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(original, destination, copy_function=os.link)
        save(marker, {'schema': 'sara-immutable-reference-adoption-v1', 'kind': kind,
            'original_directory': str(original), 'member_sha256': members,
            'new_experiment_or_new_timing': False, 'original_bytes_preserved': True})
        return True

    def inspect_completed_container(self, attempt):
        running, launch = attempt / 'running-container.json', attempt / 'launch.json'
        name = read(running).get('name') if running.is_file() else None
        if name is None and launch.is_file():
            command = read(launch)
            if '--name' in command:
                name = command[command.index('--name')+1]
        if name is None:
            raise RuntimeError('completed attempt lacks an actual named-container receipt')
        result = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True)
        if result.returncode == 0:
            value = json.loads(result.stdout)[0]
            return {key: value[key] for key in ('State', 'HostConfig', 'Image')}
        if 'No such' not in result.stderr:
            raise RuntimeError('cannot determine original completed container state')
        return None

    def adopt_completed_condition(self, app, case, arch, component, prepared, budget):
        """Preserve an entire already validated condition under its OLD identity.

        This narrowly supports the reviewed standalone-collector correction.
        It does not transfer old timings into a newly labelled method cohort.
        Unfinished conditions continue through ordinary FI/reference handling.
        """
        if self.completed_campaign is None:
            return False
        if budget != 1000:
            raise RuntimeError('completed-condition preservation is limited to sealed 1K conditions')
        self.guard()
        original = self.completed_campaign / 'applications' / app / arch / component
        segment = original / '00001000'
        report_path = segment / 'report/output/report.json'
        if not report_path.is_file():
            return False
        destination = self.work / 'applications' / app / arch / component
        marker = self.work / '.completed-adoptions' / app / arch / (component+'-00001000.json')
        if marker.is_file():
            receipt = read(marker)
            if (receipt.get('schema') != 'sara-whole-condition-adoption-v1'
                    or receipt.get('original_directory') != str(original)
                    or receipt.get('current_runner_source') != self.source_id
                    or receipt.get('member_sha256') != immutable_members(destination)):
                raise RuntimeError('preserved completed condition or its adoption receipt changed')
            return True
        if {p.name for p in original.iterdir() if p.is_dir()} != {'00001000'}:
            raise RuntimeError('only an original completed 1K condition can be adopted')
        identity, report = read(original / 'identity.json'), read(report_path)
        scope_path = self.completed_campaign / 'scope-00001000.json'
        scope = read(scope_path)
        contract = read(segment / 'method-contract.json')
        old_code = contract.get('expected_code', {})
        old_source = hashlib.sha256(json.dumps(old_code, sort_keys=True).encode()).hexdigest()
        shared_name = 'common-cache' if component in ('l1d', 'l2') else 'common-rf-smem'
        master_name = 'manifest-'+component+'-10000.json'
        master_path = prepared / shared_name / master_name
        original_prepare = original.parent / 'prepare'
        old_prepared = original_prepare / 'output/prepared'
        master = read(master_path)
        if (master.get('seed') != 2026 or master.get('sampling') != 'with_replacement'
                or len(master.get('trials', [])) != 10000
                or any(row.get('draw_index') != i or row.get('trial_id') != 'trial-%08d'%i
                       for i, row in enumerate(master['trials']))):
            raise RuntimeError('completed adoption needs the unchanged seed2026 10K master')
        master_sha = sha(master_path)
        expected = dict(case=case, architecture=arch, component=component, seed=2026,
            master_sha256=master_sha, source=old_source,
            baseline_config_directory=ARCHITECTURES[arch][1], baseline_config_sha256=ARCHITECTURES[arch][2],
            fault_model=master['population_contract']['fault_model'],
            population_model=master['population_contract']['fault_model'],
            cache_execution_model='functional-snapshot-cache-v3')
        if (any(identity.get(key) != value for key, value in expected.items())
                or contract.get('master_sha256') != master_sha
                or sha(old_prepared / shared_name / master_name) != master_sha
                or scope.get('budget') != 1000 or scope.get('source_fingerprint') != old_source
                or app not in scope.get('applications', []) or arch not in scope.get('architectures', [])):
            raise RuntimeError('completed case/architecture/component/master/source/scope identity changed')
        if (report.get('schema') != 'sara-public-fresh-condition-v1' or report.get('identity') != identity
                or report.get('source_fingerprint') != old_source or report.get('budget') != 1000
                or report.get('rates_paired_consistency') is not True
                or report.get('paired_performance_measurement') is not False
                or report.get('prediction_containers_received_FI_labels_ACKs_or_fault_outputs') is not False
                or report.get('population_equality', {}).get('complete_independent_domains_equal') is not True
                or report.get('FI', {}).get('denominator') != 1000
                or report.get('FI', {}).get('counts', {}).get('Unknown') != 0
                or report.get('SARA_sample', {}).get('denominator') != 1000
                or report.get('SARA_sample', {}).get('counts', {}).get('Unknown') == 1000
                or report.get('GEREM', {}).get('denominator') != 1000):
            raise RuntimeError('original full condition comparison is incomplete or invalid')
        rates_root, paired_root, gerem_root = (segment / name / 'output/path' for name in ('rates', 'paired', 'GEREM'))
        rates, point = read(rates_root / 'analysis.json'), read(paired_root / 'analysis.json')
        if rates.get('mode') != 'rates' or rates.get('sampled_draws') is not None:
            raise RuntimeError('original rates path is not an independent whole-space analysis')
        if (point.get('validation_only') is not True or point.get('process_resources') is not None
                or point.get('timings') != {'participates_in_performance_measurement': False}):
            raise RuntimeError('original paired validation was not untimed')
        for key in ('population_mass', 'population_fingerprint', 'counts', 'rates', 'classification_digest',
                    'normalized_analysis_input_fingerprint', 'analysis_code', 'support_fingerprint'):
            if rates[key] != point[key]:
                raise RuntimeError('original rates/paired core identity changed: '+key)
        population = report['population_equality']
        if (rates['population_fingerprint'] != population['semantic_fingerprint']
                or rates['population_mass'] != population['full_bit_cycle_mass']
                or report['SARA_full_space']['counts'] != rates['counts']):
            raise RuntimeError('original complete population mass/summary changed')
        fi_candidates = list((segment / 'FI/output/path/records').glob('*/campaign.json'))
        if len(fi_candidates) != 1:
            raise RuntimeError('one original sealed FI ledger required')
        fi_meta = read(fi_candidates[0])
        campaign = fi_candidates[0].parent.name
        if not (fi_candidates[0].parent / 'checkpoints/00001000/fi_completion.json').is_file():
            raise RuntimeError('original FI has no completion seal')
        for path in (fi_candidates[0].parent / 'trials').glob('*.json'):
            record = read(path)
            relative = Path(record['attempt']) / 'run.log'
            if (relative.is_absolute() or '..' in relative.parts
                    or sha(fi_candidates[0].parent / relative) != record.get('log_sha256')):
                raise RuntimeError('original FI full output/injection log bytes changed')
        sara_meta = read(paired_root / campaign / 'campaign.json')
        sara_seal = read(paired_root / campaign / 'checkpoints/00001000/method_completion.json')
        if sara_seal.get('analysis_summary_sha256') != sha(paired_root / 'analysis.json'):
            raise RuntimeError('original SARA summary is not sealed')
        gerem = gerem_root / campaign
        g_meta, g_seal = read(gerem / 'campaign.json'), read(gerem / 'completion-00001000.json')
        if (g_meta.get('manifest_sha256') != master_sha or g_seal.get('planned') != 1000
                or g_seal.get('completed') != 1000 or g_seal.get('FI_answers_read') is not False
                or g_seal.get('own_population', {}).get('semantic_fingerprint') != population['semantic_fingerprint']
                or g_seal.get('own_population', {}).get('mass') != rates['population_mass']):
            raise RuntimeError('original GEREM probabilities/population are not completely sealed')
        compatibility = completed_code_contract(old_code, self.source_files,
            rates['analysis_code'], g_meta['code'], fi_meta['spec']['execution_code'])
        if sara_meta['spec']['analysis_code'] != rates['analysis_code']:
            raise RuntimeError('original prediction ledger uses another analysis core')
        golden = read(old_prepared / 'CPU-reference/capture.json')
        if golden.get('base_config_sha256') != expected['baseline_config_sha256']:
            raise RuntimeError('original complete golden used another study configuration')
        for name, root in (('SARA_rates', rates_root), ('GEREM', gerem_root)):
            capture = read(root / 'capture/capture.json')
            if (capture.get('minimal_population') is not True or capture.get('component') != component
                    or any(capture[key] != golden[key] for key in
                           ('output', 'gpu_cycles', 'actual_binary_sha256', 'base_config_sha256'))):
                raise RuntimeError('original own capture changed its clean computation')
            source_map = read(root / 'capture/native-source-files.json')
            if (fingerprint(source_map) != capture['native_source_fingerprint']
                    or any(old_code.get(key) != value for key, value in source_map.items())):
                raise RuntimeError('original capture native source identity changed')
            endpoint = read(root / 'end-to-end.json')
            if (endpoint.get('exit_status') != 0 or endpoint.get('own_population_and_collection') is not True
                    or endpoint.get('borrowed_collection_inputs') is not False
                    or endpoint.get('paired_validation_included') is not False
                    or endpoint.get('FI_answers_read') is not False):
                raise RuntimeError('original method is not a complete independent timed path')
        validation = read(paired_root / 'validation-only.json')
        if validation.get('performance_measurement') is not False or validation.get('same_batch_core') is not True:
            raise RuntimeError('original paired validation provenance is incomplete')
        job_names = {path.name for path in segment.iterdir() if path.is_dir() and (path / 'request.json').is_file()}
        if not {'FI', 'FI-check', 'GEREM', 'rates', 'paired', 'report'} <= job_names:
            raise RuntimeError('a completed condition lacks a required original job receipt')
        receipts = {name: completed_job_evidence(segment / name, image=self.image,
            profile=dict(self.profile, config_sha256=sha(PROFILE)), inspect_container=self.inspect_completed_container)
            for name in sorted(job_names)}
        receipts['preparation'] = completed_job_evidence(original_prepare, image=self.image,
            profile=dict(self.profile, config_sha256=sha(PROFILE)), inspect_container=self.inspect_completed_container)
        for name in ('GEREM', 'rates', 'paired', 'report'):
            if read(segment / name / 'request.json').get('source') != old_source:
                raise RuntimeError('original prediction/report job came from another source cohort')
        # Full trial, probability, population and metric validation stays in a
        # bounded Docker report job. The host only orchestrates its read-only
        # mounts and verifies byte identity; no predictor or simulator runs.
        check_directory = self.work / '.completed-adoption-checks' / app / arch / component
        checked = self.job(check_directory, ['python3', '-m', 'script.execution.experiment_report',
            'condition', '--condition', '/condition', '--preparation-job', '/preparation-job',
            '--budget', '1000', '--output', '/out/report.json'],
            {'/condition': original, '/preparation-job': original_prepare}, maximum=3600)
        if sha(checked / 'report.json') != sha(report_path):
            raise RuntimeError('bounded public recheck differs from original sealed report')
        members = immutable_members(original)
        temporary = destination.with_name('.'+component+'-completed-'+uuid.uuid4().hex)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            if destination.exists():
                # Recover only an exact prior copy interrupted before its
                # external receipt was committed. Never replace new results.
                if immutable_members(destination) != members:
                    raise RuntimeError('cannot overwrite a new or partially adopted condition')
            else:
                shutil.copytree(original, temporary, copy_function=os.link)
                if immutable_members(temporary) != members or immutable_members(original) != members:
                    raise RuntimeError('completed evidence changed while being preserved')
                os.replace(temporary, destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        save(marker, {'schema': 'sara-whole-condition-adoption-v1', 'original_directory': str(original),
            'original_condition_identity': identity, 'original_scope': scope,
            'original_scope_sha256': sha(scope_path), 'original_report_sha256': sha(report_path),
            'original_scientific_source_files': old_code, 'current_runner_source': self.source_id,
            'member_sha256': members, 'model_compatibility': compatibility, 'terminal_job_receipts': receipts,
            'bounded_public_recheck_report_sha256': sha(checked / 'report.json'),
            'bounded_public_recheck_job': str(check_directory),
            'image': self.image, 'execution_profile': self.profile,
            'old_source_native_predictions_and_clocks_preserved': True,
            'new_method_execution_or_new_timing': False,
            'public_report_recheck_required': True})
        return True

    def configuration(self, architecture):
        _, relative, expected = ARCHITECTURES[architecture]
        path = self.code / relative
        if sha(path / 'gpgpusim.config') != expected:
            raise RuntimeError('fixed study baseline changed: ' + architecture)
        return path

    def previous_success(self, directory):
        """Check actual named containers before adopting or restarting any job.

        A created, running or paused container is not a terminal attempt. If a
        host controller died, its lock may be free while that container lives.
        This routine never kills/restarts such a container automatically.
        """
        for attempt in sorted(directory.glob('attempt-*')):
            launch = attempt / 'launch.json'
            running = attempt / 'running-container.json'
            retained = attempt / 'container.json'
            name = None
            if running.is_file():
                name = json.loads(running.read_text())['name']
            elif launch.is_file():
                command = json.loads(launch.read_text())
                if '--name' in command:
                    name = command[command.index('--name') + 1]
            actual = None
            if name:
                checked = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True)
                if checked.returncode == 0:
                    actual = json.loads(checked.stdout)[0]
                    state = actual['State']
                    if state['Running'] or state.get('Paused') or state.get('Status') not in ('exited', 'dead'):
                        raise RuntimeError('previous container is not terminal (%s, %s); inspect it before resuming'
                                           % (name, state.get('Status')))
                    if actual['Image'] != self.image:
                        raise RuntimeError('previous named container has another image; do not adopt or remove it')
                    observed = {'State': state, 'HostConfig': actual['HostConfig'], 'Image': actual['Image']}
                    save(attempt / 'recovered-container.json', observed)
                    if not retained.exists():
                        save(retained, observed)
                elif 'No such' not in checked.stderr:
                    raise RuntimeError('cannot determine actual previous container state: ' + checked.stderr.strip())
            state = actual['State'] if actual is not None else (
                json.loads(retained.read_text())['State'] if retained.is_file() else None)
            resource_file = attempt / 'job-resource.json'
            receipt = json.loads(resource_file.read_text()) if resource_file.is_file() else None
            successful_receipt = (receipt is not None and receipt.get('exit_status') == 0
                and receipt.get('child_exit_status') == 0 and receipt.get('limits_verified') is True
                and receipt.get('completion_resources_verified') is True
                and receipt.get('window_interrupted') is False)
            if state is not None and state['Running']:
                raise RuntimeError('retained running state has no inspectable live container; resolve the attempt before resuming')
            if state is None and successful_receipt:
                raise RuntimeError('wrapper completed but final Docker state is missing; verify the sealed attempt before resuming')
            if state is not None and state['ExitCode'] == 0 and not state['OOMKilled']:
                if not successful_receipt:
                    raise RuntimeError('zero Docker exit without a valid completion-resource receipt is not reusable')
                return True
            # A confirmed terminal failure, or an absent container with no
            # successful wrapper receipt, is safe to preserve and restart.
        return False

    def job(self, directory, argv, mounts=None, output=None, maximum=14400):
        """Append job attempts; never replace a successful receipt or timing."""
        self.guard()
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        output = output or directory / 'output'
        output.mkdir(parents=True, exist_ok=True)
        request = dict(argv=[v for v in argv if v != '--resume'], source=self.source_id, image=self.image,
                       mounts={k: str(v) for k, v in (mounts or {}).items()})
        frozen = directory / 'request.json'
        if frozen.exists():
            if json.loads(frozen.read_text()) != request:
                raise RuntimeError('job identity changed; use a fresh work root')
        else:
            save(frozen, request)
        if self.previous_success(directory):
            if ('script.execution.batch_method_run' in argv and
                    not (output / 'path/analysis.json').is_file() and
                    argv[argv.index('--method') + 1] in ('rates', 'paired')):
                raise RuntimeError('successful timing has deleted analysis outputs; use a fresh cohort rather than reuse it')
            return output
        attempt = directory / ('attempt-%04d' % (len(list(directory.glob('attempt-*'))) + 1))
        attempt.mkdir()
        # Complete predictive paths have no mutable in-place capture restart.
        # Keep an interrupted attempt's unique files and restart that unfinished
        # path; sealed successful paths above are never run a second time. FI
        # keeps its ledger in place and resumes only missing trials.
        if ('script.execution.batch_method_run' in argv and (output / 'path').exists()):
            shutil.move(str(output / 'path'), str(attempt / 'previous-unsealed-path'))
        if (any(module in argv for module in ('script.execution.reference_application_prepare',
                'script.execution.fair_prepare')) and (output / 'prepared').exists()):
            shutil.move(str(output / 'prepared'), str(attempt / 'previous-unsealed-prepared'))
        if ('script.execution.experiment_segment' in argv and 'native' in argv):
            for name in ('runtime', 'native-build.json'):
                if (output / name).exists():
                    shutil.move(str(output / name), str(attempt / ('previous-unsealed-' + name)))
        name = 'sara-public-' + uuid.uuid4().hex[:16]
        env = {'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': '/code:/code/script/core:/code/script/common',
               'NVIDIA_VISIBLE_DEVICES': 'void', 'NVIDIA_DRIVER_CAPABILITIES': '',
               'CUDA_INSTALL_PATH': '/usr/local/cuda', 'SARA_IMAGE_ID': self.image,
               'SARA_EXECUTION_ROLE': self.profile['role'],
               'SARA_EXECUTION_PROFILE_SHA256': sha(PROFILE)}
        command = ['docker', 'create', '--name', name, '--runtime', 'runc', '--network', 'none',
                   '--annotation', 'org.systemd.property.MemorySwapMax=uint64 0',
                   '--cpus', str(self.cpus), '--memory', str(self.memory), '--memory-swap', str(self.memory),
                   '--pids-limit', '4096', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=1g',
                   '--user', '%d:%d' % (os.getuid(), os.getgid()),
                   '-v', str(PROFILE) + ':' + str(PROFILE) + ':ro',
                   '-v', str(self.code) + ':/code:ro', '-v', str(output) + ':/out',
                   '-v', str(attempt) + ':/receipt']
        for key, value in env.items():
            command += ['-e', key + '=' + value]
        for target, source in (mounts or {}).items():
            if not Path(source).exists():
                raise FileNotFoundError(source)
            command += ['-v', str(Path(source).resolve()) + ':' + target + ':ro']
        command += ['-w', '/code', '--entrypoint', 'python3', self.image, '-m',
                    'script.execution.job_wrapper', '--output', '/receipt/job-resource.json',
                    '--max-seconds', str(maximum), '--', *argv]
        save(attempt / 'launch.json', command)
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        before = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True))[0]
        h = before['HostConfig']
        if (h['Runtime'] != 'runc' or h.get('Devices') or h.get('DeviceRequests') or h['Privileged']
                or h['Memory'] != self.memory or h['MemorySwap'] != self.memory
                or h['NanoCpus'] != self.cpus * 1000000000):
            raise RuntimeError('Docker did not apply the declared resource/device isolation')
        save(attempt / 'running-container.json', dict(name=name, started_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat()))
        # Kernel/cgroup I/O counters replace recursive disk scans. Optional
        # validation inventories are generated only after method performance.
        try:
            subprocess.run(['docker', 'start', name], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(['docker', 'wait', name], check=True, timeout=maximum + 60, stdout=subprocess.DEVNULL)
        except BaseException:
            subprocess.run(['docker', 'stop', '--time', '3', name], check=False, stdout=subprocess.DEVNULL)
            raise
        finally:
            save(attempt / 'storage-sampling.json', dict(enabled=False,
                reason='fair-aggregate-v1 forbids recursive sampling during method execution',
                storage_peak_bytes=None))
            final = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True))[0]
            save(attempt / 'container.json', {'State': final['State'], 'HostConfig': final['HostConfig'], 'Image': final['Image']})
            with (attempt / 'execution.log').open('wb') as stream:
                subprocess.run(['docker', 'logs', name], stdout=stream, stderr=subprocess.STDOUT, check=False)
            if not final['State']['Running']:
                subprocess.run(['docker', 'rm', name], check=True, stdout=subprocess.DEVNULL)
        if final['State']['ExitCode'] != 0 or final['State']['OOMKilled']:
            raise RuntimeError('job incomplete; inspect the attempt receipt (not an application DUE)')
        return output

    def prepare(self, app, case, arch):
        self.check_native()
        target = ARCHITECTURES[arch][0]
        config = self.configuration(arch)
        out = self.work / 'applications' / app / arch / 'prepare'
        if self.reference_campaign:
            original = self.reference_campaign / 'applications' / app / arch / 'prepare'
            if self.adopt_reference(original, out, kind='preparation'):
                prepared = out / 'output/prepared'
                preflight = json.loads((prepared / 'preflight.json').read_text())
                if preflight['case'] != case or preflight['target'] != target:
                    raise RuntimeError('reference preparation belongs to another input or architecture')
                return prepared
        result = self.job(out, ['python3', '-m', 'script.execution.reference_application_prepare',
            '--case', case, '--target', target, '--simulator-root', '/native',
            '--base-config', '/config/gpgpusim.config', '--output', '/out/prepared'],
            {'/native': self.reference_native, '/config': config}, maximum=14400)
        return result / 'prepared'

    def condition(self, app, case, arch, component, prepared, budget):
        if self.adopt_completed_condition(app, case, arch, component, prepared, budget):
            return
        begin, end = PREFIXES[budget]
        config = self.configuration(arch)
        base = self.work / 'applications' / app / arch / component
        shared = prepared / ('common-cache' if component in ('l1d', 'l2') else 'common-rf-smem')
        master = shared / ('manifest-' + component + '-10000.json')
        manifest = json.loads(master.read_text())
        if manifest['seed'] != 2026 or len(manifest['trials']) != 10000:
            raise ValueError('immutable seed2026 10K with-replacement master required')
        identity = dict(source=self.source_id, native=sha(self.native / 'compiled-source-files.json'),
                        FI_native=sha(self.reference_native / 'compiled-source-files.json'),
                        master_sha256=sha(master), fault_model=manifest['population_contract']['fault_model'],
                        population_model=manifest['population_contract']['fault_model'],
                        cache_execution_model='functional-snapshot-cache-v3',
                        baseline_config_directory=ARCHITECTURES[arch][1],
                        baseline_config_sha256=ARCHITECTURES[arch][2],
                        case=case, architecture=arch, component=component, seed=2026)
        if (base / 'identity.json').exists():
            if json.loads((base / 'identity.json').read_text()) != identity:
                raise RuntimeError('condition changed; prior prefixes cannot be mixed')
        else:
            save(base / 'identity.json', identity)
        if begin and not (base / ('%08d' % begin) / 'report' / 'output' / 'report.json').is_file():
            raise RuntimeError('finish, preserve and report the preceding prefix before extending')
        segment = base / ('%08d' % budget)
        clean = {'/native': self.native, '/config': config,
                 '/application': prepared / 'build' / json.loads((prepared / 'preflight.json').read_text())['application']}
        identifier = 'matched-' + app + '-' + arch + '-' + component
        contract_file = segment / 'method-contract.json'
        save(contract_file, {'expected_code': self.source_files, 'master_sha256': sha(master)})
        reference_arguments = ['--begin', str(begin), '--end', str(end), '--site-manifest', '/master.json',
            '--inputs', '/common/inputs-' + component + '.json', '--component', component,
            '--campaign-id', identifier, '--code-contract', '/contract.json']
        # FI sees neutral preparation and its own output only.
        fi_output = segment / 'FI' / 'output'
        fi_arguments = ['python3', '-m', 'script.execution.reference_prefix_campaign', '--method', 'FI',
            *reference_arguments, '--capture', '/common', '--simulator-root', '/native',
            '--output', '/out/path', '--jobs', str(min(64, self.cpus)), '--watchdog-factor', '10']
        if (fi_output / 'path/records' / identifier / 'campaign.json').exists():
            fi_arguments.append('--resume')
        adopted = False
        if self.reference_campaign:
            original = self.reference_campaign / 'applications' / app / arch / component / ('%08d' % budget) / 'FI'
            adopted = self.adopt_reference(original, segment / 'FI', kind='FI', master=master)
        if not adopted:
            self.job(segment / 'FI', fi_arguments, {'/native': self.reference_native, '/common': shared,
                '/master.json': master, '/contract.json': contract_file}, maximum=86400)
        self.job(segment / 'FI-check', ['python3', '-m', 'script.execution.experiment_segment',
            'verify-fi', '--output', '/fi/path/records/' + identifier, '--begin', str(begin), '--end', str(end)],
            {'/fi': fi_output}, maximum=600)
        # Prediction mounts deliberately omit /fi, the parent segment, and any fault output.
        if begin == 0:
            gerem_command = ['python3', '-m', 'script.execution.batch_method_run', '--method', 'gerem',
                '--case', case, '--component', component, '--simulator-root', '/native',
                '--executable', '/application', '--base-config', '/config/gpgpusim.config',
                '--output', '/out/path',
                '--site-manifest', '/master.json', '--campaign-id', identifier, '--seed', '2026', '--target-count', '1000']
            self.job(segment / 'GEREM', gerem_command, dict(clean, **{'/master.json': master}))
            if self.reference_campaign:
                previous = self.reference_campaign / 'applications' / app / arch / component / '00001000/GEREM'
                preserved = segment / 'previous-GEREM'
                if self.adopt_reference(previous, preserved, kind='GEREM-preservation'):
                    self.job(segment / 'GEREM-equivalence', ['python3', '-m',
                        'script.execution.experiment_segment', 'compare-gerem',
                        '--previous-gerem', '/previous', '--current-gerem', '/current',
                        '--site-manifest', '/master.json', '--campaign-id', identifier,
                        '--output', '/out/equivalence.json'],
                        {'/previous': preserved / 'output/path', '/current': segment / 'GEREM/output/path',
                         '/master.json': master}, maximum=600)
        else:
            own_capture = base / '00001000/GEREM/output/path/capture'
            g_output = segment / 'GEREM/output/path/records' / identifier
            own_arguments = list(reference_arguments)
            own_arguments[own_arguments.index('--inputs') + 1] = '/own-capture/inputs-' + component + '.json'
            command = ['python3', '-m', 'script.execution.reference_prefix_campaign', '--method', 'GEREM',
                *own_arguments, '--capture', '/own-capture', '--output', '/out/path']
            if (g_output / 'campaign.json').exists():
                command.append('--resume')
            self.job(segment / 'GEREM', command, {'/own-capture': own_capture,
                '/master.json': master, '/contract.json': contract_file})
        rates_directory = base / '00001000/rates'
        self.job(rates_directory, ['python3', '-m', 'script.execution.batch_method_run', '--method', 'rates',
            '--case', case, '--component', component, '--simulator-root', '/native',
            '--executable', '/application', '--base-config', '/config/gpgpusim.config', '--output', '/out/path'], clean)
        if not begin:
            command = ['python3', '-m', 'script.execution.batch_method_run', '--method', 'paired',
                '--case', case, '--component', component,
                '--analysis-inputs', '/rates-inputs/inputs-' + component + '.json',
                '--output', '/out/path', '--site-manifest', '/master.json', '--campaign-id', identifier,
                '--seed', '2026', '--target-count', '1000']
        else:
            command = ['python3', '-m', 'script.execution.experiment_segment', 'paired',
                '--case', case, '--component', component,
                '--analysis-inputs', '/rates-inputs/inputs-' + component + '.json',
                '--output', '/out/path', '--site-manifest', '/master.json', '--campaign-id', identifier,
                '--begin', str(begin), '--end', str(end)]
        self.job(segment / 'paired', command, {'/master.json': master,
            '/rates-inputs': rates_directory / 'output/path/initial-state'})
        self.report_condition(app, arch, component, budget)

    def report_condition(self, app, arch, component, budget):
        base = self.work / 'applications' / app / arch / component
        # This is the only job permitted to see all sealed prediction/reference outputs.
        return self.job(base / ('%08d' % budget) / 'report', ['python3', '-m',
            'script.execution.experiment_report', 'condition', '--condition', '/condition',
            '--preparation-job', '/preparation-job', '--budget', str(budget), '--output', '/out/report.json'],
            {'/condition': base, '/preparation-job': base.parent / 'prepare'}, maximum=3600)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('image-build', 'build-native', 'validate-minimal', 'quickstart', 'run', 'report', 'figures', 'export'))
    p.add_argument('--source', type=Path, default=SOURCE)
    p.add_argument('--storage-root', type=Path, default=Path('/work'))
    p.add_argument('--mount-uuid', required=True, help='UUID independently checked for the already mounted data disk')
    p.add_argument('--work-root', type=Path, required=True)
    p.add_argument('--image', default='sara-cpu:cache-v3')
    p.add_argument('--native-root', type=Path)
    p.add_argument('--reference-native-root', type=Path,
        help='unchanged FI simulator for preserved references; predictor collection uses --native-root independently')
    p.add_argument('--reference-campaign', type=Path,
        help='reuse only sealed FI and neutral FI preparation; never borrow prediction inputs or timings')
    p.add_argument('--completed-campaign', type=Path,
        help='preserve verified complete 1K conditions under their original source/native/clocks after the declared collector-only correction')
    p.add_argument('--lock-file', type=Path, action='append')
    p.add_argument('--applications', nargs='+', choices=['all'] + [x[0] for x in APPLICATIONS], default=['Pathfinder'])
    p.add_argument('--architectures', nargs='+', choices=ARCHITECTURES, default=list(ARCHITECTURES))
    p.add_argument('--component', choices=('rf', 'smem', 'l1d', 'l2'), default='rf', help='quickstart component only')
    p.add_argument('--budget', type=int, choices=PREFIXES, default=1000)
    p.add_argument('--allow-method-matrix', action='store_true', help='explicit opt-in to future all14 and/or 5K/10K dispatch; not enabled in the current pilot')
    a = p.parse_args(argv)
    if 'all' in a.applications and len(a.applications) != 1:
        p.error('use all alone, or an explicit application selection')
    if a.action == 'run' and ('all' in a.applications or a.budget != 1000) and not a.allow_method_matrix:
        p.error('all14 or larger budgets need explicit --allow-method-matrix')
    if a.completed_campaign is not None and a.budget != 1000:
        p.error('--completed-campaign preserves only complete original 1K conditions')
    runner = Runner(a)
    if a.action == 'image-build':
        command = ['docker', 'build', '--cpu-period', '100000', '--cpu-quota', str(runner.cpus * 100000),
                   '--memory', str(runner.memory), '--memory-swap', str(runner.memory),
                   '-t', a.image, '-f', str(runner.code / 'Dockerfile'), str(runner.code)]
        subprocess.run(command, env=dict(os.environ, DOCKER_BUILDKIT='0'), check=True)
        return 0
    if a.action == 'build-native':
        runner.job(runner.work / 'native-build', ['python3', '-m', 'script.execution.experiment_segment', 'native',
            '--source', '/code', '--output', '/out', '--jobs', str(runner.cpus)], maximum=14400)
        return 0
    if a.action == 'validate-minimal':
        runner.job(runner.work / 'minimal-collection-checks',
            ['python3', '-m', 'script.execution.minimal_collection_checks', '--output', '/out/checks'],
            maximum=1800)
        return 0
    if a.action in ('report', 'figures'):
        runner.job(runner.work / 'derived' / (a.action + '-%08d' % a.budget),
            ['python3', '-m', 'script.execution.experiment_report', 'recheck' if a.action == 'report' else a.action,
             '--campaign', '/campaign', '--budget', str(a.budget), '--output', '/out'],
            {'/campaign': runner.work}, maximum=3600)
        return 0
    if a.action == 'export':
        destination = runner.work / ('export-%08d' % a.budget)
        if destination.exists():
            raise FileExistsError('exports are immutable; choose a fresh work root for a new model')
        destination.mkdir()
        members = {}
        for path in sorted(runner.work.rglob('*')):
            if not path.is_file() or destination in path.parents or 'native-build' in path.parts:
                continue
            if any(part in ('.completed-adoptions', '.completed-adoption-checks') for part in path.parts):
                continue  # private origin paths and operational recheck receipts
            if path.name in ('request.json', 'launch.json', 'container.json', 'running-container.json'):
                continue  # host mount paths are private operations, not scientific evidence
            if (any(part.startswith('attempt-') for part in path.parts)
                    and path.name not in ('job-resource.json', 'storage-sampling.json')):
                continue
            relative = path.relative_to(runner.work)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            members[str(relative)] = sha(target)
        save(destination / 'source-files.json', runner.source_files)
        members['source-files.json'] = sha(destination / 'source-files.json')
        save(destination / 'SHA256SUMS.json', members)
        return 0
    selected = APPLICATIONS if 'all' in a.applications else [(app, case) for app, case in APPLICATIONS if app in a.applications]
    if a.action == 'quickstart' and (len(selected) != 1 or len(a.architectures) != 1):
        p.error('quickstart requires exactly one application and one architecture')
    if a.action == 'run':
        scope = {'applications': [app for app, _ in selected], 'architectures': a.architectures,
                 'budget': a.budget, 'source_fingerprint': runner.source_id}
        scope_path = runner.work / ('scope-%08d.json' % a.budget)
        if scope_path.exists() and json.loads(scope_path.read_text()) != scope:
            raise RuntimeError('prefix run scope changed; use the same explicit selection to resume')
        if not scope_path.exists():
            save(scope_path, scope)
    for app, case in selected:
        for arch in a.architectures:
            prepared = runner.prepare(app, case, arch)
            preflight = json.loads((prepared / 'preflight.json').read_text())
            components = preflight['actual_components']
            if a.action == 'quickstart':
                if a.component not in components:
                    raise ValueError('requested storage is N/A for the actual compiled workload')
                config = runner.configuration(arch)
                runner.job(runner.work / 'quickstart' / app / arch / a.component,
                    ['python3', '-m', 'script.execution.batch_method_run', '--method', 'rates', '--case', case,
                     '--component', a.component, '--simulator-root', '/native', '--executable', '/application',
                     '--base-config', '/config/gpgpusim.config', '--output', '/out/path'],
                    {'/native': runner.native, '/config': config, '/application': prepared / 'build' / preflight['application']})
            else:
                for component in components:
                    runner.condition(app, case, arch, component, prepared, a.budget)
        # The next application starts only after its predecessor's complete report exists.
        if a.action == 'run':
            runner.job(runner.work / 'applications' / app / ('summary-%08d' % a.budget),
                ['python3', '-m', 'script.execution.experiment_report', 'report', '--campaign', '/campaign',
                 '--budget', str(a.budget), '--application', app, '--output', '/out'],
                {'/campaign': runner.work}, maximum=3600)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
