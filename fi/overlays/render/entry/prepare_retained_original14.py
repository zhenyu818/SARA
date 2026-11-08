#!/usr/bin/env python3
"""B-container-only derivation from retained original14 neutral populations.

No compilation, simulator, FI, GEREM or SARA invocation occurs here. The retained
preparation is read only. Fresh canonical inventories, immutable seed2026 10K
masters and compact FI dispatch packets are written beneath --derived-output.
Public validation preparation participates in neither performance nor storage
comparison. This receipt alone does not authorize a scientific campaign.

FI callers mount the original common capture at /common, and separately mount
the generated master/packet. A packet's execution output specification remains
the original typed smoke specification. Its embedded population descriptor has
a separate new canonical output specification; neither old file is replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


SOURCE_ID = '85867c5ce04daadd05befd73463f7a51e27a7448b3afe818fd6cba9d404736af'
NATIVE_SHA = 'e306a1ee85eda5fa42888f20224133eb30170da753e3a3bcf82d75ad88918f10'
IMAGE = 'sha256:6f88c35052e8db66eb00c44700c180c57c69fdcd4569578e5730582ee93c54be'
ARCHITECTURES = {
    'SM75': ('sm_75', 'fc3b02fe010b93a5aa87ac33a9e5e1394a274ba6fea767c3328e51a319beb5c7'),
    'SM86': ('sm_86', '27ff9ac5add8ea2242560a6ed96e20adab55af0fd4bdc9f4055e95b492b56ac1'),
}
GROUPS = ('rf', 'smem', 'l1d', 'l2', 'valid_l1d', 'valid_l2')


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b''):
            result.update(block)
    return result.hexdigest()


def regular(path):
    path = Path(path)
    if (path != path.resolve(strict=True) or path.is_symlink()
            or not stat.S_ISREG(path.lstat().st_mode)):
        raise ValueError('exact existing regular retained input required: ' + str(path))
    return path


def file_identity(path):
    value = regular(path).stat()
    return dict(device=value.st_dev, inode=value.st_ino, bytes=value.st_size,
                mtime_ns=value.st_mtime_ns, ctime_ns=value.st_ctime_ns,
                nlink=value.st_nlink, uid=value.st_uid, gid=value.st_gid)


def bound_file(path):
    before = file_identity(path)
    result = dict(before, sha256=digest(path))
    if file_identity(path) != before:
        raise ValueError('retained input changed during hashing: ' + str(path))
    return result


def fresh_output(path, retained, native):
    path = Path(path).absolute()
    if (path != path.resolve(strict=False) or os.path.lexists(str(path))
            or not path.parent.is_dir()):
        raise ValueError('fresh derived root with an existing parent required')
    for old in (retained, native, Path('/code')):
        if path == old or old in path.parents or path in old.parents:
            raise ValueError('derived root must be separate from source/native/retained input')
    path.mkdir()
    return path


def main(argv=None):
    # Container and server-role admission precede scientific helper imports.
    from script.execution.policy import require_container_execution
    profile = require_container_execution()
    if (profile.role != 'bounded_primary' or profile.cpus != 64
            or profile.memory_bytes != 448 * 1024 ** 3
            or os.environ.get('SARA_IMAGE_ID') != IMAGE):
        raise ValueError('exact B CPU-only profile and frozen image required')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('retained-prepared', 'native-root', 'derived-output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case', choices=('render-ray-casting',), required=True)
    parser.add_argument('--architecture', choices=tuple(ARCHITECTURES), required=True)
    parser.add_argument('--target', choices=('sm_75', 'sm_86'), required=True)
    parser.add_argument('--expected-preflight-sha256', required=True)
    args = parser.parse_args(argv)
    target, config_sha = ARCHITECTURES[args.architecture]
    if args.target != target:
        parser.error('architecture and emitted PTX target must agree')
    if (len(args.expected_preflight_sha256) != 64
            or any(c not in '0123456789abcdef' for c in args.expected_preflight_sha256)):
        parser.error('actual accepted retained preflight SHA required')

    from script.execution import fi_smoke
    from script.execution.batch_workload import DEFAULT_CASE, contract, output_regions
    from script.execution.campaign import atomic_json
    from script.execution.cache_valid_resident import cache_populations, attach_valid_resident_contracts
    from script.execution.experiment import scientific_files
    from script.execution.fault_manifest import FaultPopulation
    from script.execution.fi_dispatch_inputs import build_dispatch_inputs
    from script.execution.fi_smoke_prepare import register_populations
    from script.execution.method_input_context import OwnInputContext, file_digest

    source = Path(fi_smoke.__file__).resolve().parents[2]
    if source != Path('/code'):
        raise ValueError('helpers must come from the frozen read-only /code mount')
    sources = scientific_files(source)
    # Runner source identity deliberately uses default JSON separators.
    if hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest() != SOURCE_ID:
        raise ValueError('complete frozen Render v13 identity differs')
    workload = contract(args.case)  # Rejects LLM and any non-original14 case.
    retained, native = args.retained_prepared.absolute(), args.native_root.absolute()
    for directory in (retained, native):
        if directory != directory.resolve(strict=True) or not directory.is_dir():
            raise ValueError('exact retained/native directory required')
    if digest(regular(native / 'compiled-source-files.json')) != NATIVE_SHA:
        raise ValueError('compiled frozen native03 source manifest differs')
    preflight_path = regular(retained / 'preflight.json')
    if digest(preflight_path) != args.expected_preflight_sha256:
        raise ValueError('retained preflight differs from actual accepted workflow')

    # Pin every input path this operation will touch, without walking the old
    # tree or changing link counts. The population decoder also checks its open
    # file identity; the context checks the complete cache ledger once.
    watched = {preflight_path: file_identity(preflight_path)}
    def watch(path):
        path = regular(path)
        watched[path] = file_identity(path)
        return path
    raw_rf = watch(retained / 'common-rf-smem/population.jsonl.gz')
    watch(Path(str(raw_rf) + '.storage.json'))
    raw_cache = watch(retained / 'common-cache/memory.jsonl')
    for dirname in ('golden', 'common-rf-smem', 'common-cache'):
        capture = retained / dirname
        for name in ('capture.json', 'run.log', 'gpgpusim.config', 'output-spec.json'):
            watch(capture / name)
        for path in capture.iterdir():
            if path.name in (workload['app'],) or path.suffix in ('.xml', '.icnt'):
                watch(path)
    preflight, captures = fi_smoke._check_preparation(retained, args.case, args.architecture, native)
    for dirname, metadata in captures.items():
        if (metadata.get('arguments') != workload['arguments']
                or metadata.get('base_config_sha256') != config_sha
                or metadata.get('classification_uses_FI_answers') is not False
                or metadata.get('predictor_executed') is not False
                or metadata.get('formal_campaign_admission') is not False):
            raise ValueError('retained capture profile/input differs: ' + dirname)
        for name in preflight['asset_sha256']:
            watch(retained / dirname / name)
    binary = watch(retained / 'build' / workload['app'])
    if digest(binary) != preflight['binary_sha256']:
        raise ValueError('retained actual build differs from neutral captures')
    for name, expected in preflight['PTX'].items():
        if Path(name).name != name or digest(watch(retained / 'build' / name)) != expected:
            raise ValueError('retained emitted PTX differs')
    canonical_outputs = {name: output_regions(retained / name / 'run.log', args.case)
                         for name in ('common-rf-smem', 'common-cache')}
    output = fresh_output(args.derived_output, retained, native)
    receipt = dict(schema='sara-retained-original14-derived-preparation-v1', status='running',
        case=args.case, application=workload['app'], architecture=args.architecture, target=args.target,
        source_id=SOURCE_ID, native_source_manifest_sha256=NATIVE_SHA, image=IMAGE,
        execution_profile=profile.descriptor(), architecture_config_sha256=config_sha,
        retained_prepared=str(retained), preflight_sha256=args.expected_preflight_sha256,
        driver_sha256=digest(regular(Path(__file__).absolute())), groups={},
        performance_measurement=False, storage_comparison_measurement=False,
        new_build=False, new_golden=False, new_simulation=False, FI_executed=False,
        GEREM_executed=False, SARA_executed=False, old_tree_modified=False,
        large_raw_copy_or_hardlink=False, formal_campaign_admission=False,
        automation='PAUSED', next_dispatch=None)
    atomic_json(output / 'prepared.json', receipt)
    try:
        registered, rf_audit = register_populations(retained / 'common-rf-smem')
        transport = rf_audit['transport']
        if (transport.get('stream_complete') is not True
                or transport.get('codec') != 'gzip' or transport.get('gzip_CRC_checked') is not True):
            raise ValueError('complete retained RF/SMEM gzip transport and CRC required')
        atomic_json(output / 'register-population-audit.json', rf_audit)
        with OwnInputContext(retained) as context:
            caches = cache_populations(retained / 'common-cache')
            cache_sha = file_digest(raw_cache)
            context.verify_unchanged()
        receipt['raw_input_bindings'] = {
            'common-rf-smem/population.jsonl.gz': dict(watched[raw_rf],
                sha256=transport['physical_sha256'], decoded_sha256=transport['decoded_sha256'],
                complete_footer_checked=True, gzip_CRC_checked=True),
            'common-cache/memory.jsonl': dict(watched[raw_cache], sha256=cache_sha,
                complete_closed_ledger_prefix_SHA_checked=True,
                actual_owner_geometry_residency_checked=True)}
        original = {}
        for component in ('rf', 'smem'):
            entry = registered[component]
            if entry is not None:
                label = 'GE-SpMM' if component == 'rf' and args.case == DEFAULT_CASE else workload['app']
                inventory = dict(entry['inventory'], population_id=label +
                    '-actual-allocated-' + component.upper() + '-v1')
                original[component] = dict(inventory=inventory, population=FaultPopulation(inventory))
            else:
                original[component] = None
        original.update({component: caches[component] for component in ('l1d', 'l2')})

        # Each descriptor is portable within its new small group directory.
        # Its canonical output file is a derived description only. The packet
        # pins original typed output-spec.json for actual FI raw-byte checks.
        for group in GROUPS:
            selected = group.startswith('valid_')
            component = group.replace('valid_', '')
            entry = caches[group] if selected else original[component]
            if entry is None or entry['population'] is None:
                receipt['groups'][group] = dict(status='N/A', population_mass=0)
                if selected:
                    if entry is None or entry['inventory'].get('spans') != []:
                        raise ValueError('empty resident group requires its actual empty inventory')
                    directory = output / 'valid' / component
                    directory.mkdir(parents=True)
                    inventory_path = directory / 'inventory.json'
                    atomic_json(inventory_path, entry['inventory'])
                    receipt['groups'][group].update(component=component, untimed_only=True,
                        inventory=str(inventory_path.relative_to(output)),
                        inventory_sha256=digest(inventory_path))
                continue
            directory = output / ('valid' if selected else 'original') / component
            directory.mkdir(parents=True)
            population, inventory = entry['population'], entry['inventory']
            inventory_path = directory / 'inventory.json'
            capture_name = 'common-cache' if component in ('l1d', 'l2') else 'common-rf-smem'
            capture = retained / capture_name
            atomic_json(inventory_path, inventory)
            atomic_json(directory / 'output-spec.json', canonical_outputs[capture_name])
            label = ('GE-SpMM' if args.case == DEFAULT_CASE and component != 'smem'
                     else workload['app'])
            stream = ('matched-' + label + '-' + args.target + '-valid-' + component
                      if selected else 'matched-' + label + '-' + component)
            manifest = population.sample(10000, 2026, stream)
            if selected:
                manifest = attach_valid_resident_contracts(manifest, entry['residencies'])
            master = directory / 'manifest-10000.json'
            atomic_json(master, manifest)
            master_sha = digest(master)
            segments = []
            segment_directory = directory / 'segments'
            segment_directory.mkdir()
            for begin, end in ((1000, 5000), (5000, 10000)):
                segment_path = segment_directory / ('%08d-%08d.json' % (begin, end))
                segment = dict(manifest, trials=manifest['trials'][begin:end],
                    parent_draw_range=[begin, end], parent_master_sha256=master_sha)
                atomic_json(segment_path, segment)
                segments.append(dict(draw_range=[begin, end],
                    path=str(segment_path.relative_to(output)), sha256=digest(segment_path),
                    parent_master_sha256=master_sha, original_draw_indices_preserved=True))
            parent = original[component]
            parent_directory = output / 'original' / component
            if selected and parent is None:
                raise ValueError('resident group has no original physical population')
            if selected:
                descriptor_path = parent_directory / ('inputs-' + component + '.json')
                descriptor = json.loads(descriptor_path.read_text())
            else:
                descriptor = dict(schema='sara-population-inputs-v1', case=args.case,
                    arguments=workload['arguments'], binary_sha256=preflight['binary_sha256'],
                    simulator_libraries=captures['golden']['simulator_libraries'],
                    population_mass=population.mass, population_fingerprint=population.identity,
                    files={role: dict(path=name, sha256=digest(directory / name)) for role, name in
                        (('inventory', 'inventory.json'), ('output_spec', 'output-spec.json'))},
                    scope='retained source-bound common FI population; no predictor inputs')
                descriptor_path = directory / ('inputs-' + component + '.json')
                atomic_json(descriptor_path, descriptor)
            packet_path = directory / 'FI-dispatch.json'
            packet = build_dispatch_inputs(capture, component, master, packet_path,
                descriptor=descriptor, descriptor_path=descriptor_path, population=population,
                original_inventory=parent['inventory'] if selected else None,
                selected_inventory_path=inventory_path if selected else None)
            receipt['groups'][group] = dict(status='ready', component=component,
                population_mass=population.mass, population_fingerprint=population.identity,
                original_capture=str(capture), descriptor=str(descriptor_path.relative_to(output)),
                inventory=str(inventory_path.relative_to(output)), inventory_sha256=digest(inventory_path),
                master=str(master.relative_to(output)), master_sha256=master_sha, segments=segments,
                dispatch_inputs=str(packet_path.relative_to(output)), dispatch_inputs_sha256=digest(packet_path),
                manifest_draws=10000, seed=2026, sampling='with_replacement',
                prefixes=[1000, 5000, 10000], resident_selection=packet['resident_selection'],
                untimed_only=selected,
                original_typed_execution_output_spec_sha256=packet['files']['outputs']['sha256'],
                derived_canonical_output_spec_sha256=digest(directory / 'output-spec.json'))
        for path, expected in watched.items():
            if file_identity(path) != expected:
                raise ValueError('retained input changed during derivation: ' + str(path))
        receipt.update(status='complete', actual_groups=[name for name in GROUPS
            if receipt['groups'][name]['status'] == 'ready'],
            N_A_groups=[name for name in GROUPS if receipt['groups'][name]['status'] == 'N/A'],
            retained_small_bindings={str(path.relative_to(retained)): bound_file(path)
                for path in watched if path not in (raw_rf, raw_cache)},
            scientific_result_or_performance_claim=False,
            next_action='stop; separate reviewed host admission and explicit dispatch required')
        atomic_json(output / 'prepared.json', receipt)
    except BaseException as error:
        receipt.update(status='failed_evidence_preserved', error=type(error).__name__ + ': ' + str(error))
        atomic_json(output / 'prepared.json', receipt)
        raise
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
