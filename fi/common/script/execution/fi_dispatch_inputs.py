"""Small FI execution packets produced once by the common study preparation.

The population is checked when its immutable master is created. An FI worker
loads the unchanged master and execution bytes, not a second full population.
These packets are neither predictor inputs nor a substitute for native ACKs.
"""
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

from script.execution.campaign import atomic_json, fingerprint, requested_prefix
from script.execution.batch_workload import contract, fixture_assets
from script.execution.fi_campaign import validate_site_binding

SCHEMA = 'sara-FI-dispatch-inputs-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
PRODUCER_FILES = (
    'script/execution/fi_dispatch_inputs.py', 'script/execution/fair_prepare.py',
    'script/execution/reference_application_prepare.py', 'script/execution/fault_manifest.py',
    'script/execution/compact_population.py', 'script/execution/cache_valid_resident.py',
    'script/execution/projection_population.py', 'script/execution/batch_workload.py')


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def _file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular immutable common input required')
    return dict(bytes=path.stat().st_size, sha256=sha(path))


def producer_identity():
    root = Path(__file__).resolve().parents[2]
    return {name: sha(root / name) for name in PRODUCER_FILES}


def build_dispatch_inputs(capture, component, manifest_path, destination, *,
                          descriptor, population=None, original_inventory=None,
                          selected_inventory_path=None, diagnostic_only=False,
                          descriptor_path=None):
    """Shared setup only: validate every frozen draw, then pin compact inputs."""
    capture, manifest_path, destination = map(Path, (capture, manifest_path, destination))
    if destination.exists():
        raise FileExistsError('never overwrite an FI dispatch packet')
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if population is None:
        if selected_inventory_path is not None:
            raise ValueError('resident preparation must use its already generated population')
        # The original source-owned sampler has just generated this master
        # from the frozen descriptor/inventory. Do not parse that potentially
        # hundreds-of-MiB inventory again to re-prove the same construction.
        population = SimpleNamespace(identity=descriptor['population_fingerprint'],
            mass=descriptor['population_mass'], inventory=manifest['population_contract'])
    if (manifest.get('seed') != 2026 or manifest.get('sampling') != 'with_replacement'
            or manifest.get('population_fingerprint') != population.identity
            or manifest.get('population_size') != population.mass):
        raise ValueError('shared FI master differs from its complete checked population')
    count = len(manifest['trials'])
    requested_prefix(manifest['trials'], count, dispatch_limit=10000)
    if (diagnostic_only and not 1 <= count <= 8) or (not diagnostic_only and count != 10000):
        raise ValueError('the current formal master must contain exactly ten thousand draws')
    identifiers = set()
    for draw, trial in enumerate(manifest['trials']):
        if (trial.get('draw_index') != draw or not isinstance(trial.get('trial_id'), str)
                or not trial['trial_id'] or trial['trial_id'] in identifiers):
            raise ValueError('shared FI draw identity changed')
        identifiers.add(trial['trial_id'])
        if hasattr(population, 'resolve'):
            expected = population.resolve(trial['population_rank'])
            if any(trial.get(key) != value for key, value in expected.items()):
                raise ValueError('shared FI master differs from its original resolved physical coordinates')
        site = {key: trial[key] for key in ('population_fingerprint', 'component', 'target', 'cycle', 'bit')}
        if (trial.get('population_fingerprint') != population.identity
                or trial.get('site_id') != fingerprint(site)
                or type(trial.get('population_rank')) is not int
                or not 0 <= trial['population_rank'] < population.mass):
            raise ValueError('shared FI master changed a canonical point or rank')
        if trial.get('component') != component:
            raise ValueError('one actual component required per FI packet')
        validate_site_binding(trial)
    selection = None
    if selected_inventory_path is not None:
        if component not in ('l1d', 'l2') or original_inventory is None:
            raise ValueError('resident FI packet needs its original Cache domain')
        from script.execution.projection_population import validate_projection
        _, selection = validate_projection(manifest, selected_inventory_path, original_inventory,
            seed=2026, target_count=count)
    metadata = json.loads((capture / 'capture.json').read_text())
    workload = contract(descriptor['case'])
    files = {'golden': dict(path='run.log', **_file(capture / 'run.log')),
             'outputs': dict(path='output-spec.json', **_file(capture / 'output-spec.json')),
             'config': dict(path='gpgpusim.config', **_file(capture / 'gpgpusim.config')),
             'capture_metadata': dict(path='capture.json', **_file(capture / 'capture.json')),
             'descriptor': dict(path='inputs-' + component + '.json',
                 **_file(descriptor_path if descriptor_path is not None else
                         capture / ('inputs-' + component + '.json')))}
    names = {workload['app'], *fixture_assets(descriptor['case'])}
    names.update(path.name for path in capture.iterdir() if path.suffix in ('.xml', '.icnt'))
    assets = {name: _file(capture / name) for name in sorted(names)}
    if (assets[workload['app']]['sha256'] != descriptor['binary_sha256']
            or metadata.get('actual_binary_sha256') != descriptor['binary_sha256']
            or metadata.get('simulator_libraries') != descriptor['simulator_libraries']):
        raise ValueError('shared executable/native bytes differ from the original complete golden')
    packet = dict(schema=SCHEMA, component=component, case=descriptor['case'],
        descriptor=descriptor, descriptor_fingerprint=fingerprint(descriptor),
        population=dict(fingerprint=population.identity, bit_cycles=population.mass,
            fault_model=population.inventory['fault_model'],
            coordinate_system=population.inventory['coordinate_system'],
            time_basis=population.inventory['time_basis']),
        manifest=dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
            fingerprint=fingerprint(manifest), draws=count, seed=2026,
            sampling='with_replacement', all_draw_coordinates_checked=True),
        diagnostic_only=diagnostic_only,
        original_inventory_binding=descriptor['files']['inventory'],
        files=files, assets=assets, resident_selection=selection,
        source_owned_preparation=producer_identity(),
        creation_cost='common per-application per-SM study setup only',
        FI_rebuilds_population=False, prediction_inputs_borrowed=False)
    atomic_json(destination, packet)
    return packet


def load_dispatch_inputs(path, expected_sha256, *, component, untimed, diagnostic=False):
    """Read one frozen packet; its SHA is pinned by the host job request."""
    if not isinstance(expected_sha256, str) or HEX.fullmatch(expected_sha256) is None:
        raise ValueError('explicit host-pinned FI dispatch-packet SHA required')
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('FI dispatch packet changed after common preparation')
    packet = json.loads(raw)
    if (packet.get('schema') != SCHEMA or packet.get('component') != component
            or packet.get('FI_rebuilds_population') is not False
            or packet.get('prediction_inputs_borrowed') is not False
            or packet.get('source_owned_preparation') != producer_identity()
            or fingerprint(packet.get('descriptor')) != packet.get('descriptor_fingerprint')):
        raise ValueError('FI packet is not bound to the actual current shared producer')
    if (type(packet.get('diagnostic_only')) is not bool
            or (packet['diagnostic_only'] and not diagnostic)):
        raise ValueError('diagnostic dispatch packet cannot admit formal work')
    selected = packet.get('resident_selection')
    if selected is not None and (not untimed or component not in ('l1d', 'l2')
            or selected.get('entire_selected_domain_contained') is not True
            or selected.get('outcome_filter') is not False):
        raise ValueError('resident packet is restricted to verified untimed Cache cohorts')
    population = packet.get('population', {})
    master = packet.get('manifest', {})
    if (not isinstance(population.get('fingerprint'), str)
            or HEX.fullmatch(population['fingerprint']) is None
            or type(population.get('bit_cycles')) is not int or population['bit_cycles'] <= 0
            or not isinstance(population.get('fault_model'), str)
            or not population['fault_model'] or population.get('time_basis') != 'simulator_global_cycle'
            or type(master.get('draws')) is not int
            or (not packet['diagnostic_only'] and master['draws'] != 10000)
            or (packet['diagnostic_only'] and not 1 <= master['draws'] <= 8)
            or master.get('seed') != 2026
            or master.get('sampling') != 'with_replacement'
            or master.get('all_draw_coordinates_checked') is not True
            or not isinstance(master.get('sha256'), str) or HEX.fullmatch(master['sha256']) is None):
        raise ValueError('FI packet lacks its exact checked population/master identity')
    if (set(packet.get('files', {})) != {'golden', 'outputs', 'config', 'capture_metadata', 'descriptor'}
            or not isinstance(packet.get('assets'), dict) or not packet['assets']):
        raise ValueError('FI packet lacks exact complete execution input bindings')
    for name, item in packet['files'].items():
        relative = Path(item['path'])
        if (relative.is_absolute() or '..' in relative.parts or relative.name != str(relative)
                or type(item.get('bytes')) is not int or item['bytes'] < 0
                or not isinstance(item.get('sha256'), str) or HEX.fullmatch(item['sha256']) is None):
            raise ValueError('FI packet input must be local to its frozen capture')
    for name, item in packet['assets'].items():
        relative = Path(name)
        if (relative.is_absolute() or '..' in relative.parts or relative.name != name
                or type(item.get('bytes')) is not int or item['bytes'] < 0
                or not isinstance(item.get('sha256'), str) or HEX.fullmatch(item['sha256']) is None):
            raise ValueError('FI packet assets need exact relative-name byte bindings')
    proxy = SimpleNamespace(identity=population['fingerprint'], mass=population['bit_cycles'],
        inventory={key: population[key] for key in ('fault_model', 'coordinate_system', 'time_basis')})
    return packet, packet['descriptor'], proxy


def read_bound_bytes(path, item):
    """Hash and load one actual execution input in one file read."""
    raw = Path(path).read_bytes()
    if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
        raise ValueError('FI execution input changed after shared preparation')
    return raw


def load_bound_json(path, item):
    return json.loads(read_bound_bytes(path, item))
