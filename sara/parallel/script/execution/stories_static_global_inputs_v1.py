"""Source-bound Stories .global initialization, not a new SARA analysis model.

Only top-level .global .align A .b8 name[N] (optional byte initializer) is
added. Existing .const admission and all numeric/propagation functions remain
the fixed implementations. Every initialized byte must have a matching actual
native write/readback record. Uninitialized bytes retain the pinned simulator's
fresh backing zero, not a CUDA hardware guarantee. No trace is filtered.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

from script.core import sparse_global_image as fixed
from script.execution.method_input_context import FrozenDict, FrozenList

SCHEMA = 'stories-static-global-inputs-v1'
CASE = 'stories260k-prefix1'
FIXED_IMAGE_SHA256 = 'a23875f64cd067267f6523f89ca59dfb7852bca330f249728f3224b4e1990478'
MAX_STATIC_BYTES = 65536
GLOBAL = re.compile(r'(?:(?:\.visible)\s+)?\.global\s+\.align\s+([1-9][0-9]*)\s+'
    r'\.b8\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*([1-9][0-9]*)\s*\]'
    r'\s*(?:=\s*\{([^{}]*)\}\s*)?;\Z', re.S)
BYTE = re.compile(r'(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)\Z')
_ORIGINAL = {name: getattr(fixed, name) for name in
    ('prepare', 'host_assignments', 'validate_golden_image', 'image_bytes', 'host_writes', 'semantic_image')}
_STACK = []


def _need(value, message):
    if not value:
        raise ValueError(message)


def _integer(value, minimum=0):
    _need(type(value) is int and minimum <= value, 'typed nonnegative integer required')
    return value


def _list_container(value):
    # OwnInputContext.cached freezes the same list values. Accept only its
    # standard wrapper and the original list, never tuples/arbitrary sequences.
    return type(value) in (list, FrozenList)


def _dict_container(value):
    return type(value) in (dict, FrozenDict)


def declaration(text, *, filename, sha256):
    match = GLOBAL.fullmatch(text)
    _need(match is not None, 'reviewed top-level global byte-array declaration required')
    alignment, name, size = int(match[1]), match[2], int(match[3])
    _need(alignment <= 16 and not alignment & (alignment - 1) and size <= MAX_STATIC_BYTES,
          'bounded aligned static global required')
    data = None
    if match[4] is not None:
        tokens = [value.strip() for value in match[4].split(',')]
        _need(tokens and all(BYTE.fullmatch(value) for value in tokens),
              'explicit integer byte initializer required')
        values = [int(value, 16 if value.lower().startswith('0x') else 10) for value in tokens]
        _need(len(values) <= size and all(0 <= value <= 255 for value in values),
              'initializer exceeds its byte-array extent or byte range')
        data = bytes(values).hex()
    return dict(symbol_name=name, size=size, alignment=alignment, declaration=text,
                ptx_file=filename, ptx_sha256=sha256, initializer_hexbytes=data,
                is_const=False, is_global=True)


def declarations(paths):
    """Read every original PTX declaration; reject every unreviewed spelling."""
    rows, names = [], set()
    for path in paths:
        path = Path(path)
        text, digest = path.read_text(), fixed._sha(path)
        _need(text.count('/*') == text.count('*/'), 'complete PTX comments required')
        clean = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
        clean = re.sub(r'//[^\n]*', '', clean)
        depth, pending = 0, []
        for raw in clean.splitlines():
            line = raw.strip()
            starts = re.match(r'(?:(?:\.visible|\.extern|\.weak)\s+)*\.(?:global|const)\b', line)
            if pending or starts:
                _need(depth == 0, 'top-level static declarations required')
                pending.append(line)
                if ';' not in line:
                    continue
                statement = '\n'.join(pending)
                pending = []
                if GLOBAL.fullmatch(statement):
                    row = declaration(statement, filename=path.name, sha256=digest)
                else:
                    match = fixed.CONSTANT_DECLARATION.fullmatch(statement)
                    _need(match is not None, 'unreviewed static declaration or initializer')
                    alignment, name, size = int(match[1]), match[2], int(match[3])
                    _need(alignment <= 16 and not alignment & (alignment - 1)
                          and size <= MAX_STATIC_BYTES, 'bounded constant declaration required')
                    row = dict(symbol_name=name, size=size, alignment=alignment,
                        declaration=statement, ptx_file=path.name, ptx_sha256=digest,
                        is_const=True, is_global=False)
                _need(row['symbol_name'] not in names, 'duplicate static symbol declaration')
                names.add(row['symbol_name']); rows.append(row)
                continue
            depth += line.count('{') - line.count('}')
            _need(depth >= 0, 'complete PTX scope required')
        _need(not pending and depth == 0, 'complete PTX scope/declaration required')
    _need(sum(row['size'] for row in rows) <= MAX_STATIC_BYTES, 'bounded complete static image required')
    return rows


def bind_global_records(rows, checked, *, source, ptx_sha256):
    """Associate PTX bytes with actual symbol definitions and observed writes.

    This pure structural function does not certify a prefix as a closed ledger.
    prepare() separately requires the unchanged complete read_closed_ledger.
    """
    _need(all(source.get(key) == value for key, value in fixed.CONSTANT_NATIVE.items()),
          'static initialization/native producer source mismatch')
    definitions = checked.get('symbol_definitions', [])
    observations = checked.get('symbol_definition_records', [])
    initializations = checked.get('static_initializations', [])
    _need(_list_container(definitions) and _list_container(observations) and _list_container(initializations),
          'complete typed static observations required')
    _need(len(definitions) == len(rows), 'complete PTX/native symbol set required')
    names, uids, intervals = set(), set(), []
    contracts, writes, used = [], [], set()
    for row in rows:
        _need(type(row.get('size')) is int and 0 < row['size'] <= MAX_STATIC_BYTES
              and type(row.get('alignment')) is int and 0 < row['alignment'] <= 16
              and not row['alignment'] & (row['alignment'] - 1)
              and type(row.get('is_global')) is bool and type(row.get('is_const')) is bool
              and row['is_global'] != row['is_const'], 'typed reviewed static declaration required')
        name = row['symbol_name']
        _need(name not in names and ptx_sha256.get(row['ptx_file']) == row['ptx_sha256'],
              'unique source-bound static declaration required')
        names.add(name)
        matches = [item for item in definitions if item.get('symbol_name') == name]
        _need(len(matches) == 1, 'one actual assembled static definition required')
        definition = matches[0]
        uid = _integer(definition.get('symbol_uid'), 1)
        base = fixed.address(definition.get('base'))
        size = row['size']
        _need(uid not in uids and type(definition.get('size')) is int and definition.get('size') == size
              and definition.get('is_global') is row['is_global']
              and definition.get('is_const') is row['is_const']
              and base % row['alignment'] == 0 and base + size <= fixed.ADDRESS_LIMIT
              and not any(base < b + n and b < base + size for b, n in intervals),
              'PTX/native static extent, flags, alignment or identity disagree')
        uids.add(uid); intervals.append((base, size))
        observed = [item for item in observations if item.get('symbol_uid') == uid]
        _need(len(observed) == 1 and all(observed[0].get(key) == definition[key]
              for key in ('symbol_uid', 'symbol_name', 'base', 'size', 'is_global', 'is_const')),
              'one preceding unchanged native symbol observation required')
        definition_sequence = _integer(observed[0].get('sequence'), 1)
        _need(type(observed[0].get('instruction_cursor')) is int and observed[0]['instruction_cursor'] == 0,
              'static definition must precede the complete instruction window')
        native = sorted([item for item in initializations if item.get('symbol_uid') == uid],
                        key=lambda item: _integer(item.get('sequence'), 1))
        if not row['is_global']:
            _need(not native, 'existing declaration-only constant initialization rule retained')
            continue
        decoded = declaration(row['declaration'], filename=row['ptx_file'], sha256=row['ptx_sha256'])
        _need(decoded == row, 'static declaration metadata differs from original PTX')
        literal = bytes.fromhex(row['initializer_hexbytes'] or '')
        _need(len(native) == len(literal), 'missing or extra actual static initializer writes')
        prior = definition_sequence
        for offset, (value, record) in enumerate(zip(literal, native)):
            sequence = _integer(record.get('sequence'), 1)
            expected = bytes([value]).hex()
            _need(sequence > prior and sequence not in used and record.get('kind') == 'static_initialization'
                  and type(record.get('instruction_cursor')) is int and record['instruction_cursor'] == 0
                  and record.get('symbol_name') == name and type(record.get('address')) is int
                  and record['address'] == base + offset and type(record.get('count')) is int and record['count'] == 1
                  and record.get('literal_bytes') == expected and record.get('actual_bytes') == expected,
                  'PTX/native static byte, address, order or readback mismatch')
            used.add(sequence); prior = sequence
            writes.append(dict(cursor=0, base=hex(base + offset), hexbytes=expected,
                sha256=hashlib.sha256(bytes([value])).hexdigest(), kind='native_static_initializer',
                native_sequence=sequence, symbol_uid=uid, symbol_name=name))
        contracts.append(dict(row, symbol_uid=uid, base=hex(base),
            definition_sequence=definition_sequence, definition_instruction_cursor=0,
            source_zero_provenance='fresh_native_global_backing', default_unwritten_byte=0,
            initializer_bytes=len(literal), zero_tail_bytes=size - len(literal)))
    _need(len(used) == len(initializations), 'unbound actual static initialization record')
    _need(len(names) == len(definitions) and len(uids) == len(definitions),
          'complete unique assembled static symbol set required')
    return contracts, sorted(writes, key=lambda row: (row['cursor'], row['native_sequence']))


def _new_assignments(image):
    support = image.get('static_global_inputs')
    if support is None:
        return None
    _need(_dict_container(support) and image.get('case') == CASE and support.get('schema') == SCHEMA
          and support.get('native_source_sha256') == fixed.CONSTANT_NATIVE
          and support.get('closed_ledger_sha256') == image.get('host_ledger_sha256'),
          'source-bound complete static input contract required')
    contracts, statics = bind_global_records(support['declarations'], support['native_records'],
        source=image['source_files'], ptx_sha256=image['ptx_sha256'])
    _need(contracts == support['global_symbols'], 'static global symbol contract changed')
    actual = image.get('writes', [])
    _need(_list_container(actual), 'typed initial assignment chronology required')
    static_actual = [row for row in actual if row.get('kind') == 'native_static_initializer']
    _need(static_actual == statics, 'initial image differs from actual native static writes')
    hosts = [row for row in actual if row.get('kind') != 'native_static_initializer']
    host_image = dict(image, writes=hosts)
    # Retain the original host payload/kind/cursor validation without weakening it.
    list(_ORIGINAL['host_assignments'](host_image))
    bindings = support.get('host_assignment_order')
    _need(_list_container(bindings) and len(bindings) == len(hosts), 'complete host assignment order required')
    for row, binding in zip(hosts, bindings):
        _need({key: row.get(key) for key in ('cursor', 'request_id', 'service_sequence', 'native_sequence')}
              == binding, 'host native order binding changed')
    sequences = [_integer(row.get('native_sequence'), 1) for row in actual]
    _need(len(sequences) == len(set(sequences)) and actual == sorted(actual,
          key=lambda row: (row['cursor'], row['native_sequence'])),
          'actual static/host instruction-boundary service order required')
    return actual


def host_assignments(image):
    rows = _new_assignments(image)
    if rows is None:
        yield from _ORIGINAL['host_assignments'](image)
    else:
        for row in rows:
            fixed._payload(row)
            yield row


def validate_golden_image(events, image):
    # The original golden validator executes unchanged on the expanded input
    # chronology. Only its descriptive host/static counters are separated.
    result = _ORIGINAL['validate_golden_image'](events, image)
    if image.get('static_global_inputs') is not None:
        statics = sum(row['kind'] == 'native_static_initializer' for row in image['writes'])
        result['actual_host_assignments_checked'] -= statics
        result.update(static_global_input_policy=SCHEMA,
            actual_static_initializer_assignments_checked=statics,
            static_global_symbols_checked=len(image['static_global_inputs']['global_symbols']),
            static_initial_values_from_future_loads=False,
            numeric_analysis_changed=False, fault_population_changed=False)
    return result


def semantic_image(image):
    """Keep static bytes/order, excluding the duplicate acquisition certificate.

    The raw image and descriptor remain fully hash-bound. Absolute record
    numbers only witness the validated ordering; the semantic writes list keeps
    that order and instruction cursor, independent of intervening cache hooks.
    """
    normalized = _ORIGINAL['semantic_image'](image)
    if image.get('static_global_inputs') is None:
        return normalized
    list(host_assignments(image))
    support = normalized['static_global_inputs']
    support.pop('closed_ledger_sha256', None)
    support.pop('native_records', None)
    for row in support['global_symbols']:
        row.pop('definition_sequence', None)
    for row in support['host_assignment_order']:
        row.pop('native_sequence', None)
    for name in ('writes', 'segments'):
        for row in normalized[name]:
            row.pop('native_sequence', None)
    return normalized


def prepare(capture, output, code, *, component='rf', defer_constant_validation=False):
    """Original input-preparation operations plus source-bound static inputs.

    No producer, forward pass, RF canonicalizer, numeric core or classifier is
    invoked. The complete unchanged ledger/footer and trace readers are used.
    """
    from script.execution.memory_effect_records import read_closed_ledger
    from script.execution.trace_transport import read_trace_document
    from script.execution.method_input_context import current_context, read_json
    capture, output, code = Path(capture), Path(output), Path(code)
    metadata = read_json(capture / 'capture.json')
    if metadata.get('case') != CASE:
        return _ORIGINAL['prepare'](capture, output, code, component=component,
                                   defer_constant_validation=defer_constant_validation)
    _need(_STACK, 'static input preparation requires its live scoped provider')
    _need(not defer_constant_validation or current_context(capture) is not None,
          'deferred validation requires the same live own method/core context')
    _need(component in ('rf', 'smem', 'l1d', 'l2'), 'one actual storage component required')
    name = 'inputs-' + component + '.json'
    descriptor = deepcopy(read_json(capture / name))
    _need(descriptor['arguments'] == metadata['arguments']
          and descriptor['binary_sha256'] == metadata['actual_binary_sha256']
          and metadata.get('collection') == 'sara', 'same actual SARA executable and capture required')
    source = read_json(capture / 'native-source-files.json')
    _need(all(source.get(key) == value and fixed._sha(code / key) == value
              for key, value in fixed.CONSTANT_NATIVE.items()),
          'actual static initialization producer/consumer bytes differ')
    trace_role = descriptor['files']['trace']; trace_path = capture / trace_role['path']
    _need(fixed._sha(trace_path) == trace_role['sha256'], 'clean trace bytes changed')
    checked = read_closed_ledger(capture / 'memory.jsonl', trace_path,
        Path(str(trace_path) + '.completeness.json'), expected_cache_state=metadata['cache_state'])
    _need(checked.get('record_consistency_checked') is True
          and checked['source_fingerprint'] == metadata['native_source_fingerprint'],
          'complete actual closed-ledger provenance required')
    trace, _ = read_trace_document(trace_path)
    hosts = []
    originals = [row for row in checked['copy_effects'] if row['effect_kind'] == 'assignment']
    for row in originals:
        _need(0 <= row['instruction_cursor'] <= len(trace['events']), 'host assignment outside complete trace')
        data = bytes.fromhex(row['bytes'])
        hosts.append(dict(cursor=row['instruction_cursor'], base=hex(row['destination']),
            source=hex(row['source']), hexbytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
            kind=row['copy_kind'], request_id=row['request_id'], service_sequence=row['service_sequence'],
            native_sequence=row['sequence']))
    ptx = sorted(capture.glob('*.ptx'))
    _need(ptx, 'the complete original PTX set is required')
    decl = declarations(ptx); ptx_hashes = {path.name: fixed._sha(path) for path in ptx}
    globals_contract, statics = bind_global_records(decl, checked, source=source, ptx_sha256=ptx_hashes)
    const_checked = dict(checked,
        symbol_definitions=[row for row in checked['symbol_definitions'] if row['is_const']],
        symbol_definition_records=[row for row in checked['symbol_definition_records'] if row['is_const']],
        static_initializations=[])
    constants = fixed._prepare_constants([row for row in decl if row['is_const']],
                                        const_checked, hosts, source, code)
    writes = sorted(hosts + statics, key=lambda row: (row['cursor'], row['native_sequence']))
    config = (capture / 'gpgpusim.config').read_text()
    _need(not any(int(value) for value in re.findall(
        r'^\s*-(?:resume_option|checkpoint_option)\s+(\d+)', config, re.M)), 'fresh process required')
    image = dict(schema=fixed.SCHEMA, scope='fresh_process_golden_host_assignments_and_stores',
        default_unwritten_byte=0, address_limit=fixed.ADDRESS_LIMIT,
        native_memory_source_sha256=source['src/cuda-sim/memory.cc'],
        segments=[dict(row) for row in writes if row['cursor'] == 0], writes=writes,
        ptx_sha256=ptx_hashes, source_files=source, case=metadata['case'], arguments=metadata['arguments'],
        output_ranges=read_json(capture / 'output-spec.json'),
        unresolved_native_read_range=[fixed.ADDRESS_LIMIT, fixed.ADDRESS_LIMIT],
        host_ledger_sha256=checked['ledger_sha256'], trace_sha256=trace_role['sha256'],
        binary_sha256=descriptor['binary_sha256'], FI_answers_used=False, hardware_memory_semantics=False,
        static_global_inputs=dict(schema=SCHEMA, declarations=decl, global_symbols=globals_contract,
            native_source_sha256=dict(fixed.CONSTANT_NATIVE), closed_ledger_sha256=checked['ledger_sha256'],
            native_records={key: deepcopy(checked[key]) for key in
                ('symbol_definitions', 'symbol_definition_records', 'static_initializations')},
            host_assignment_order=[{key: row[key] for key in
                ('cursor', 'request_id', 'service_sequence', 'native_sequence')} for row in hosts],
            fresh_zero_is_simulator_only=True, future_load_values_used=False,
            original_numeric_analysis_unchanged=True, fault_population_unchanged=True))
    if constants:
        image['constant_symbols'] = constants
    list(host_assignments(image))
    if not defer_constant_validation:
        from script.core.reg_observed_analyzer import parse_event
        image['static_input_read_validation'] = validate_golden_image(
            [parse_event(row, index) for index, row in enumerate(trace['events'])], image)
    issue = re.findall(r'^\s*-gpgpu_max_insn_issue_per_warp\s+(\d+)\s*$', config, re.M)
    if len(ptx) == 1 and issue == ['1']:
        shader = 'src/gpgpu-sim/shader.cc'
        _need(source.get(shader) == fixed._sha(code / shader), 'actual native scheduler source differs')
        image['loop_ptx'] = ptx[0].read_text()
        image['loop_fault_protocol'] = dict(schema='sara-frozen-cycle-watchdog-v1',
            golden_cycles=metadata['gpu_cycles'], watchdog_factor=10,
            cycle_limit=10 * metadata['gpu_cycles'], dependent_chain_min_core_cycles=1,
            max_insn_issue_per_warp=1, shader_source_sha256=source[shader])
        layout = fixed._loop_layout(trace, image, metadata)
        if layout is not None:
            image['loop_host_layout'] = layout
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'initial-global-image.json'
    target.write_text(json.dumps(image, sort_keys=True) + '\n')
    for role in descriptor['files'].values():
        relative = Path(role['path'])
        _need(not relative.is_absolute() and '..' not in relative.parts, 'portable original input bundle required')
        new = output / relative; new.parent.mkdir(parents=True, exist_ok=True)
        if not new.exists():
            fixed._link_frozen(capture / relative, new)
    for suffix in ('.completeness.json', '.memory_ranges.json'):
        relative = trace_role['path'] + suffix
        if (capture / relative).is_file():
            fixed._link_frozen(capture / relative, output / relative)
    descriptor['files']['initial_global_image'] = dict(path=target.name, sha256=fixed._sha(target))
    (output / name).write_text(json.dumps(descriptor, sort_keys=True) + '\n')
    result = dict(schema=fixed.SCHEMA, static_global_input_policy=SCHEMA,
        host_assignments=len(hosts), native_static_initializer_assignments=len(statics),
        global_symbols=len(globals_contract), source_files=list(fixed.CONSTANT_NATIVE),
        same_strategy_for_both_SM=True, new_simulations=False,
        golden_load_consistency_checked_by_shared_analysis=True,
        host_ledger_sha256=checked['ledger_sha256'], complete_native_ledger_checked=True,
        original_numeric_analysis_unchanged=True, fault_population_unchanged=True,
        static_input_read_validation=(image.get('static_input_read_validation') if not defer_constant_validation
            else dict(required_in_same_shared_core_before_prediction=True, preparation_only_not_admission=True)))
    if constants:
        result['constant_policy'] = fixed.CONSTANT_SCHEMA
    (output / 'preparation.json').write_text(json.dumps(result, sort_keys=True) + '\n')
    return result


@contextmanager
def installed():
    """Install only input entry/accessors, with nested LIFO exact restoration.

    Import prepare after entering this scope (or use this module.prepare).
    Previously bound original prepare aliases are deliberately not mutated.
    """
    _need(hashlib.sha256(Path(fixed.__file__).read_bytes()).hexdigest() == FIXED_IMAGE_SHA256,
          'fixed sparse_global_image source changed')
    replacements = dict(prepare=prepare, host_assignments=host_assignments,
                        validate_golden_image=validate_golden_image, semantic_image=semantic_image)
    saved = {name: getattr(fixed, name) for name in replacements}
    if _STACK:
        _need(all(saved[name] is value for name, value in replacements.items()), 'input scope changed while nested')
    else:
        _need(all(getattr(fixed, name) is value for name, value in _ORIGINAL.items()),
              'fixed input entry/accessor identity changed')
    campaign = sys.modules.get('script.execution.sara_batch_campaign')
    campaign_saved = getattr(campaign, 'semantic_image', None) if campaign is not None else None
    if campaign is not None:
        _need(campaign_saved is (_ORIGINAL['semantic_image'] if not _STACK else semantic_image),
              'campaign input semantic accessor changed')
    token = object(); _STACK.append(token)
    if campaign is not None:
        campaign.semantic_image = semantic_image
    proof = dict(schema=SCHEMA, case=CASE, scope='PTX_and_native_initial_input_bytes_only',
        fixed_source_sha256=FIXED_IMAGE_SHA256, native_source_sha256=dict(fixed.CONSTANT_NATIVE),
        input_functions_replaced=list(replacements), original_image_bytes_function_unchanged=True,
        original_host_writes_function_unchanged=True, numeric_analysis_functions_replaced=[],
        fault_population_changed=False, global_symbol_moves_fabricated=False,
        complete_closed_ledger_required=True, nested_LIFO=True, restored_after_scope=False)
    for name, value in replacements.items():
        setattr(fixed, name, value)
    try:
        yield proof
    finally:
        _need(_STACK and _STACK[-1] is token and all(getattr(fixed, name) is value
              for name, value in replacements.items()), 'input scope LIFO/identity violation')
        for name, value in saved.items():
            setattr(fixed, name, value)
        current_campaign = sys.modules.get('script.execution.sara_batch_campaign')
        if current_campaign is not None:
            _need(current_campaign.semantic_image is semantic_image, 'campaign input alias changed in scope')
            current_campaign.semantic_image = (campaign_saved if campaign is not None
                                                else _ORIGINAL['semantic_image'])
        _STACK.pop(); proof['restored_after_scope'] = True
