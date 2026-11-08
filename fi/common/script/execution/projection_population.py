"""Untimed exact subset membership checks against one method's own population."""
import json
from pathlib import Path

from script.execution.campaign import fingerprint, requested_prefix
from script.execution.compact_population import semantic_population
from script.execution.fault_manifest import FaultPopulation


def validate_projection(manifest, selected_path, original_inventory, *, seed, target_count):
    selected = json.loads(Path(selected_path).read_text())
    original = semantic_population(original_inventory)
    selection = selected.get('selection', {})
    if (original.component not in ('l1d', 'l2') or seed != 2026
            or selection.get('schema') != 'sara-cache-current-valid-selection-v1'
            or selection.get('original_population_fingerprint') != original.identity
            or selection.get('original_component_population_mass') != original.mass
            or selection.get('phase') != 'after_all_core_instruction_events_at_cycle'
            or selection.get('data_sector_statuses') != [2, 3]
            or selection.get('readable_filter') is not False
            or selection.get('future_consumer_filter') is not False
            or selection.get('outcome_filter') is not False
            or any(selected.get(key) != original_inventory[key] for key in
                   ('fault_model', 'coordinate_system', 'time_basis'))):
        raise ValueError('subset is not bound to the method own original component domain')
    subset = FaultPopulation(selected)
    semantic_subset = semantic_population(selected)
    # Prove every selected rectangle, not only the sampled points, is inside
    # the original domain. Canonical rectangles are disjoint, so summed
    # intersection area is an exact containment test without per-bit replay.
    groups = {}
    for row in original.document['spans']:
        groups.setdefault(fingerprint(row['target']), []).append(row)
    for row in semantic_subset.document['spans']:
        covered = 0
        for parent in groups.get(fingerprint(row['target']), ()):
            cycles = max(0, min(row['cycle_stop'], parent['cycle_stop']) -
                         max(row['cycle_start'], parent['cycle_start']))
            bits = max(0, min(row['bit_start'] + row['bit_count'],
                             parent['bit_start'] + parent['bit_count']) -
                       max(row['bit_start'], parent['bit_start']))
            covered += cycles * bits
        if covered != (row['cycle_stop'] - row['cycle_start']) * row['bit_count']:
            raise ValueError('selected rectangle is outside own original population')
    if (semantic_subset.component != original.component
            or manifest.get('population_fingerprint') != subset.identity
            or manifest.get('population_size') != subset.mass
            or manifest.get('sampling') != 'with_replacement' or manifest.get('seed') != seed
            or manifest.get('population_contract') != {key: selected[key] for key in
                ('population_id', 'fault_model', 'coordinate_system', 'time_basis')}):
        raise ValueError('subset manifest identity, geometry or sampling changed')
    count = requested_prefix(manifest['trials'], target_count, dispatch_limit=10000)
    identifiers = set()
    from script.execution.cache_valid_resident import validate_site_contract
    for draw, trial in enumerate(manifest['trials']):
        if (not isinstance(trial.get('trial_id'), str) or not trial['trial_id']
                or trial['trial_id'] in identifiers or trial.get('draw_index') != draw):
            raise ValueError('subset draw identity changed')
        identifiers.add(trial['trial_id'])
        expected = subset.resolve(trial['population_rank'])
        if any(trial.get(key) != value for key, value in expected.items()):
            raise ValueError('subset point is not its unchanged resolved physical coordinate')
        contract = validate_site_contract(trial.get('valid_resident_contract'))
        scope = trial['target']['sm'] if original.component == 'l1d' else trial['target']['bank']
        if (contract['population_fingerprint'] != subset.identity
                or contract['component'] != original.component or contract['cycle'] != trial['cycle']
                or contract['bit'] != trial['bit'] + 1 or contract['scope'] != scope
                or contract['line'] != trial['target']['line']):
            raise ValueError('subset occupancy contract names another point')
        if not original.contains(trial):
            raise ValueError('subset draw is outside own original physical domain')
    return manifest['trials'][:count], dict(schema=selection['schema'],
        selected_population_fingerprint=subset.identity, selected_population_mass=subset.mass,
        original_population_fingerprint=original.identity, original_population_mass=original.mass,
        selected_inventory_fingerprint=fingerprint(selected), entire_selected_domain_contained=True,
        original_physical_coordinates_preserved=True, outcome_filter=False)
