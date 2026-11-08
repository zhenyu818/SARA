"""Clean global-memory values for the shared, architecture-independent batch core.

The image records actual successful host assignments in instruction-cursor order.
It is a golden value oracle, not execution of an injected origin. Unwritten zero
is a bound simulator property; neither CUDA hardware nor FI answers supply it.
"""
import argparse
import errno
import hashlib
import json
import os
import re
import shutil
from pathlib import Path

SCHEMA = 'sara-initial-global-image-v2'
ADDRESS_LIMIT = 1 << 32
MEMORY_SOURCES = ('src/cuda-sim/memory.cc', 'src/cuda-sim/memory.h',
                  'src/abstract_hardware_model.h')
CONSTANT_SCHEMA = 'sara-declaration-only-constant-v1'
# These are the reviewed, unchanged native producers/consumers. Merely supplying
# an arbitrary new native file map must not admit a new initialization model.
CONSTANT_NATIVE = {
    'src/cuda-sim/memory.cc': '059e31cb4167b559bcdef39349b5d4b36e9a80b44f30dd09697444108c9cb947',
    'src/cuda-sim/memory.h': '229bff472ac8228f4edfd746bcc19e12aa974f2176066b807659d244c874a539',
    'src/abstract_hardware_model.h': '439aaa6fbdf46c53d2f643269f3d34d856d9d93beef6e61841f317b5625f1fa4',
    'src/abstract_hardware_model.cc': '554ef39e0e1771e8f92de72d44e9173c8bff37c4adfdf6767faf208725d8e289',
    'src/cuda-sim/ptx_parser.cc': '3592676b3ae2f964f190ffb5000f2ea1188a3b7d141b88b2e4cac392d91e0832',
    'libcuda/cuda_runtime_api.cc': '6f538c24138759100aeb47a50b97712e8c5275aa21239ab98ca886a9963b5e56',
    'src/cuda-sim/cuda-sim.cc': '7e69075fd22cf4262e135f1c5cc138b5fe9e94d5dbd980b22a119cb1a4497367',
    'src/cuda-sim/host_copy_observer.h': 'd76e464013823b0e91e9438d5cc330314179ba1141997a820cc131d988709a65',
    'src/cuda-sim/instructions.cc': '7d485b056d2000ea0f7ccefce016ad2ea0a919ae084637ec4cb5da03c5e16979',
}
CONSTANT_DECLARATION = re.compile(
    r'(?:(?:\.visible)\s+)?\.const\s+\.align\s+([1-9][0-9]*)\s+'
    r'\.b8\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*([1-9][0-9]*)\s*\]\s*;\Z')
CONSTANT_LOAD = re.compile(r'ld\.const\.([usb])(8|16|32|64)\Z')


def _constant_declarations(paths):
    """Only complete declaration-only byte arrays; never infer an initializer.

    The current admitted constant path emits one-line .b8 array declarations.
    A different declaration syntax is an admission failure, not zero memory.
    Comments cannot hide an initializer or a second top-level memory symbol.
    """
    declarations = []
    for path in paths:
        text = path.read_text()
        if text.count('/*') != text.count('*/'):
            raise ValueError('complete PTX comments required')
        clean = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
        clean = re.sub(r'//[^\n]*', '', clean)
        depth = 0
        for line in clean.splitlines():
            line = line.strip()
            memory_declaration = re.match(r'(?:(?:\.visible|\.extern|\.weak)\s+)*\.(?:global|const)\b', line)
            if memory_declaration is not None:
                match = CONSTANT_DECLARATION.fullmatch(line) if depth == 0 else None
                if match is None:
                    raise ValueError('unreviewed static global/constant declaration or initializer')
                alignment, name, size = int(match[1]), match[2], int(match[3])
                if (alignment > 16 or alignment & (alignment - 1) or size > 65536
                        or any(row['symbol_name'] == name for row in declarations)):
                    raise ValueError('bounded unique declaration-only constant required')
                declarations.append(dict(symbol_name=name, size=size, alignment=alignment,
                    ptx_file=path.name, ptx_sha256=_sha(path), declaration=line))
            depth += line.count('{') - line.count('}')
            if depth < 0:
                raise ValueError('complete PTX scope required')
        if depth:
            raise ValueError('complete PTX scope required')
    if sum(row['size'] for row in declarations) > 65536:
        raise ValueError('bounded declaration-only constant image required')
    return declarations


def constant_symbols(image):
    """Return source-bound constant ranges, excluding any new fault population.

    The complete initial bytes below are derived from native fresh backing zero
    plus actual host assignments. They are not a captured full-symbol snapshot.
    """
    _contract(image)
    rows = image.get('constant_symbols', [])
    if not isinstance(rows, list):
        raise ValueError('typed declaration-only constant contract required')
    names, uids, intervals = set(), set(), []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('typed declaration-only constant contract required')
        base, size = address(row['base']), row.get('size')
        match = CONSTANT_DECLARATION.fullmatch(row.get('declaration', ''))
        uid, name = row.get('symbol_uid'), row.get('symbol_name')
        if (row.get('schema') != CONSTANT_SCHEMA or type(uid) is not int or uid <= 0
                or name in names or uid in uids or match is None or match[2] != name
                or type(size) is not int or not 0 < size <= 65536 or int(match[3]) != size
                or row.get('alignment') != int(match[1]) or int(match[1]) > 16
                or int(match[1]) & (int(match[1]) - 1) or base % int(match[1])
                or base + size > ADDRESS_LIMIT or row.get('is_const') is not True
                or row.get('is_global') is not False
                or row.get('default_unwritten_byte') != 0
                or row.get('source_zero_provenance') != 'fresh_native_global_backing'
                or row.get('initial_bytes_provenance') != 'native_zero_then_actual_cursor_zero_host_assignments'
                or row.get('native_source_sha256') != CONSTANT_NATIVE
                or any(image.get('source_files', {}).get(key) != value for key, value in CONSTANT_NATIVE.items())
                or image.get('ptx_sha256', {}).get(row.get('ptx_file')) != row.get('ptx_sha256')
                or any(base < old_base + old_size and old_base < base + size for old_base, old_size in intervals)):
            raise ValueError('bound declaration/native/symbol constant contract required')
        data = bytes.fromhex(row.get('initial_hexbytes', ''))
        if len(data) != size or hashlib.sha256(data).hexdigest() != row.get('initial_sha256'):
            raise ValueError('complete derived constant initial bytes required')
        derived = bytearray(size)
        bindings = []
        for assignment in host_assignments(image):
            start, payload = _payload(assignment)
            if start < base + size and base < start + len(payload):
                if (assignment['cursor'] != 0 or assignment['kind'] != 'symbol_to'
                        or start < base or start + len(payload) > base + size):
                    raise ValueError('constant backing has an unbound or later host write')
                derived[start - base:start - base + len(payload)] = payload
                bindings.append({key: assignment[key] for key in
                    ('cursor', 'base', 'sha256', 'request_id', 'service_sequence')})
        if (not bindings or bindings != row.get('host_assignment_bindings')
                or bytes(derived) != data):
            raise ValueError('constant bytes must equal source zero and actual host writes')
        names.add(name); uids.add(uid); intervals.append((base, size))
    return rows


def constant_read_bytes(event, image):
    """Validate an ordinary scalar .const load; return its byte width or None.

    Normal loads must be inside an admitted symbol. Fault-altered aliases are
    handled separately by the existing native backing-memory model; this helper
    does not grant allocation validity or create constant-cache fault sites.
    """
    opcode = event.opcode.strip()
    is_constant = '.const.' in opcode or event.mem_space == 'const'
    if not is_constant:
        return None
    match = CONSTANT_LOAD.fullmatch(opcode)
    if (match is None or event.kind != 'load' or event.mem_space not in ('const', 'global')
            or type(event.mem_access_size_bytes) is not int
            or event.mem_access_size_bytes != int(match[2]) // 8
            or event.mem_addr is None or type(event.dst_val) is not int):
        raise ValueError('reviewed scalar ordinary constant load required')
    count, start = int(match[2]) // 8, address(event.mem_addr)
    if start + count > ADDRESS_LIMIT or len([row for row in constant_symbols(image)
            if address(row['base']) <= start and start + count <= address(row['base']) + row['size']]) != 1:
        raise ValueError('ordinary constant load is not bound to one assembled symbol')
    return count


def constant_symbol_move(event, image):
    """Bind the native literal symbol address; never make it a RF source site."""
    labels = [name for name in event.src_regs if isinstance(name, str) and name.startswith('#const_addr')]
    if not labels:
        return False
    rows = constant_symbols(image)
    matches = [row for row in rows if labels == ['#const_addr_1:' + row['symbol_name']]]
    if (len(matches) != 1 or event.opcode != 'mov.u64' or event.kind != 'inst'
            or event.pred is not None or event.width_bits != 64
            or getattr(event, 'dst_write_mask', None) not in (None, (1 << 64) - 1)
            or not isinstance(event.dst_reg, str) or not event.dst_reg.startswith('%')
            or type(event.dst_reg_uid) is not int or event.dst_reg_uid <= 0
            or event.src_regs != labels or event.src_reg_uids != [-1]
            or event.src_width_bits != [64] or len(event.src_vals) != 1
            or event.src_vals[0] != address(matches[0]['base'])
            or event.dst_val != address(matches[0]['base'])):
        raise ValueError('constant-symbol MOV differs from actual assembled definition')
    return True


def _prepare_constants(declarations, checked, writes, source, code):
    if not declarations:
        if checked.get('symbol_definitions') or checked.get('static_initializations'):
            raise ValueError('native static symbol has no admitted PTX declaration')
        return []
    if checked.get('static_initializations'):
        raise ValueError('explicit static initializer is outside declaration-only constant support')
    if any(source.get(name) != value or _sha(code / name) != value for name, value in CONSTANT_NATIVE.items()):
        raise ValueError('constant initialization/native consumer semantics changed')
    definitions = checked.get('symbol_definitions', [])
    if len(definitions) != len(declarations):
        raise ValueError('complete PTX and assembled constant symbol set required')
    contracts = []
    for declaration in declarations:
        matches = [row for row in definitions if row['symbol_name'] == declaration['symbol_name']]
        if len(matches) != 1:
            raise ValueError('one assembled declaration-only constant definition required')
        definition = matches[0]
        base, size = address(definition['base']), declaration['size']
        if (definition['size'] != size or definition['is_const'] is not True
                or definition['is_global'] is not False or base + size > ADDRESS_LIMIT):
            raise ValueError('PTX and native constant extent/type disagree')
        observations = [row for row in checked.get('symbol_definition_records', [])
                        if row['symbol_uid'] == definition['symbol_uid']]
        if not observations or any(row['instruction_cursor'] != 0 for row in observations):
            raise ValueError('constant definition must precede the complete instruction window')
        initial, bindings = bytearray(size), []
        for original, assignment in zip([row for row in checked['copy_effects'] if row['effect_kind'] == 'assignment'], writes):
            start, payload = _payload(assignment)
            if start < base + size and base < start + len(payload):
                allocation = original.get('destination_allocation', {})
                if (assignment['cursor'] != 0 or assignment['kind'] != 'symbol_to'
                        or start < base or start + len(payload) > base + size
                        or allocation.get('allocator') != 'symbol'
                        or (allocation.get('symbol_uid'), allocation.get('name'), allocation.get('base'), allocation.get('size'))
                        != (definition['symbol_uid'], definition['symbol_name'], base, size)
                        or not any(row['sequence'] < original['sequence'] for row in observations)):
                    raise ValueError('constant host assignment lacks actual preceding symbol identity')
                initial[start - base:start - base + len(payload)] = payload
                bindings.append({key: assignment[key] for key in
                    ('cursor', 'base', 'sha256', 'request_id', 'service_sequence')})
        if not bindings:
            raise ValueError('an actual complete constant symbol host assignment is required')
        contracts.append(dict(declaration, schema=CONSTANT_SCHEMA, symbol_uid=definition['symbol_uid'],
            base=hex(base), is_const=True, is_global=False, default_unwritten_byte=0,
            source_zero_provenance='fresh_native_global_backing', native_source_sha256=dict(CONSTANT_NATIVE),
            initial_bytes_provenance='native_zero_then_actual_cursor_zero_host_assignments',
            initial_hexbytes=bytes(initial).hex(), initial_sha256=hashlib.sha256(initial).hexdigest(),
            host_assignment_bindings=bindings))
    return contracts


def address(value):
    result = int(value, 0) if isinstance(value, str) else value
    if type(result) is not int or not 0 <= result <= ADDRESS_LIMIT:
        raise ValueError('typed native global address required')
    return result


def _payload(row):
    base = address(row['base'])
    data = bytes.fromhex(row['hexbytes'])
    if (not data or base + len(data) > ADDRESS_LIMIT
            or hashlib.sha256(data).hexdigest() != row['sha256']):
        raise ValueError('complete unchanged native global assignment required')
    return base, data


def _contract(image):
    if (not isinstance(image, dict) or image.get('schema') != SCHEMA
            or image.get('scope') != 'fresh_process_golden_host_assignments_and_stores'
            or image.get('default_unwritten_byte') != 0
            or image.get('address_limit') != ADDRESS_LIMIT):
        raise ValueError('explicit clean initial-state contract required')


def image_bytes(image):
    """State after all cursor-zero host assignments, in actual service order."""
    _contract(image)
    if image['segments'] != [row for row in host_assignments(image) if row['cursor'] == 0]:
        raise ValueError('initial segments must equal the actual cursor-zero assignments')
    initial = {}
    for segment in image['segments']:
        base, data = _payload(segment)
        initial.update((base + offset, value) for offset, value in enumerate(data))
    return initial


def host_assignments(image):
    """Yield complete golden assignments; never infer bytes from a future load."""
    _contract(image)
    previous = -1
    for row in image.get('writes', []):
        cursor = row.get('cursor')
        if type(cursor) is not int or cursor < previous:
            raise ValueError('nondecreasing actual host instruction cursors required')
        previous = cursor
        _payload(row)
        if row.get('kind') not in ('h2d', 'memset', 'd2d', 'symbol_to'):
            raise ValueError('explicit host assignment kind required')
        yield row


def host_writes(image):
    for row in host_assignments(image):
        base, data = _payload(row)
        yield row['cursor'], base, data


def validate_golden_image(events, image):
    """Check the complete golden global history, including inter-kernel copies.

    A cursor is the number of retired instruction records, so a copy at cursor N
    precedes event index N and follows index N-1. H2D/memset assign fresh values;
    D2D also checks its source against state at that boundary. This is a local
    golden-value consistency check, not a claim about correlated faulted stores.
    """
    memory = {}
    writes = iter(host_assignments(image))
    following = next(writes, None)
    loads = stores = assignments = constant_loads = constant_moves = 0
    symbols = constant_symbols(image)

    def assign(row):
        base, data = _payload(row)
        if row['kind'] == 'd2d':
            source = address(row['source'])
            if source + len(data) > ADDRESS_LIMIT or bytes(
                    memory.get(source + i, 0) for i in range(len(data))) != data:
                raise ValueError('D2D source differs from earlier golden memory')
        memory.update((base + i, value) for i, value in enumerate(data))

    for event in events:
        while following is not None and following['cursor'] <= event.index:
            assign(following)
            assignments += 1
            following = next(writes, None)
        if event.pred is not None and not event.pred.val:
            continue
        if constant_symbol_move(event, image):
            constant_moves += 1
        if event.opcode.split('.', 1)[0] in ('atom', 'red', 'call', 'callp'):
            raise ValueError('initial image does not represent implicit memory effects')
        constant_count = constant_read_bytes(event, image)
        if ((event.mem_space != 'global' and constant_count is None)
                or event.kind not in ('load', 'store') or '.param.' in event.opcode):
            continue
        count = constant_count if constant_count is not None else (
            event.store_size_bytes if event.kind == 'store' else event.mem_access_size_bytes)
        if (type(count) is not int or not 0 < count <= 8
                or event.mem_addr is None or address(event.mem_addr) + count > ADDRESS_LIMIT):
            raise ValueError('complete scalar native global operand required')
        if event.kind == 'load':
            value = sum(memory.get(event.mem_addr + i, 0) << (8 * i) for i in range(count))
            if event.dst_val is None or value != event.dst_val & ((1 << (8 * count)) - 1):
                raise ValueError('host assignments and earlier stores differ from golden load at event '
                                 + str(event.index))
            if constant_count is not None:
                constant_loads += 1
            else:
                loads += 1
        else:
            if any(address(row['base']) < event.mem_addr + count
                   and event.mem_addr < address(row['base']) + row['size'] for row in symbols):
                raise ValueError('ordinary global store overlaps declaration-only constant backing')
            source = event.store_data_src_index
            offset = event.store_data_byte_offset or 0
            if (type(source) is not int or not 0 <= source < len(event.src_vals)
                    or type(offset) is not int or offset < 0):
                raise ValueError('actual scalar store source and byte offset required')
            value = event.src_vals[source] >> (8 * offset)
            memory.update((event.mem_addr + i, (value >> (8 * i)) & 255) for i in range(count))
            stores += 1
    terminal = len(events)
    while following is not None:
        if following['cursor'] != terminal:
            raise ValueError('host assignment outside complete instruction window')
        assign(following)
        assignments += 1
        following = next(writes, None)
    result = dict(policy=SCHEMA, initial_payload_bytes=len(image_bytes(image)),
                golden_global_loads_checked=loads, golden_global_stores_checked=stores,
                actual_host_assignments_checked=assignments,
                architecture_specific_enablement=False, FI_answers_used=False,
                per_origin_replay=False, hardware_memory_semantics=False,
                classification_is='golden_local_value_relation_then_submitted_batch_model')
    if symbols:
        if not constant_loads or not constant_moves:
            raise ValueError('complete ordinary constant loads and symbol address definitions required')
        result.update(constant_policy=CONSTANT_SCHEMA, golden_constant_loads_checked=constant_loads,
                      golden_constant_symbol_moves_checked=constant_moves,
                      constant_symbols_checked=len(symbols), constant_bytes_source_derived=True)
    return result


def semantic_image(image):
    """Analysis values/semantics, excluding process-local provenance only.

    Full input and file hashes remain validated by checked_inputs/prepare.
    H2D/symbol-to host addresses select already captured payload bytes and are
    not native memory coordinates. D2D source addresses and memset byte values
    remain semantic. A deep copy preserves every original evidence field.
    """
    from copy import deepcopy
    _contract(image)
    normalized = deepcopy(image)
    for key in ('host_ledger_sha256', 'trace_sha256'):
        normalized.pop(key, None)
    for collection in ('writes', 'segments'):
        for row in normalized.get(collection, []):
            if row.get('kind') in ('h2d', 'symbol_to'):
                row.pop('source', None)
    return normalized


def _sha(path):
    from script.execution.method_input_context import file_digest
    return file_digest(path)


def _link_frozen(source, target):
    """Share immutable acquisition bytes, with a lossless cross-device fallback.

    The descriptor hashes still bind every byte. Linking changes storage cost,
    not the analysis inputs or clean host-assignment validation performed here.
    """
    if source.is_symlink() or not source.is_file():
        raise ValueError('regular immutable captured input required')
    if target.exists():
        if target.is_symlink() or not target.is_file() or _sha(source) != _sha(target):
            raise ValueError('frozen input bundle destination changed')
        return
    from script.execution.method_input_context import current_context
    context = current_context(source)
    if context is not None:
        # An audited os.link transition is the sole allowed ctime update to a
        # previously verified input. Cross-filesystem copies retain the strict
        # ordinary fallback and are independently hashed as a new inode.
        try:
            context.link_frozen(source, target)
            return
        except OSError as error:
            if error.errno not in (errno.EXDEV, errno.EPERM, errno.ENOTSUP):
                raise
            shutil.copy2(source, target)
            return
    try:
        os.link(source, target)
    except OSError as error:
        if error.errno not in (errno.EXDEV, errno.EPERM, errno.ENOTSUP):
            raise
        shutil.copy2(source, target)


def _loop_layout(trace, image, metadata):
    """Bind the inspected sparse-dot idiom to actual clean pointer values.

    The PTX admission separately checks the COMPLETE normalized instruction
    text. This function proves its four input spans and sole output range,
    rather than guessing semantic roles from the order of arbitrary segments.
    """
    if metadata['workload_contract']['app'] != 'GESpmm':
        return None
    arguments = metadata['arguments']
    if (not isinstance(arguments, list) or len(arguments) != 4
            or any(type(value) is not int or value <= 0 for value in arguments)):
        return None
    rows, inner, columns, nnz = arguments
    writes = list(host_assignments(image))
    if len(writes) != 4 or any(row['cursor'] != 0 or row['kind'] != 'h2d' for row in writes):
        return None
    names = ('%rd16', '%rd18', '%rd19', '%rd20', '%rd17')
    pointers, kernels = {}, set()
    for event in trace['events']:
        kernels.add(event['kernel_uid'])
        if event.get('opcode') == 'ld.param.u64' and event.get('dst_reg') in names:
            name = event['dst_reg']
            value = address(event['dst_val'])
            if pointers.setdefault(name, value) != value:
                return None
    if len(kernels) != 1 or set(pointers) != set(names):
        return None
    sizes = (4 * (rows + 1), 4 * nnz, 4 * nnz, 4 * inner * columns)
    actual = [(base, len(data)) for base, data in map(_payload, writes)]
    if actual != list(zip((pointers[name] for name in names[:4]), sizes)):
        return None
    outputs = image['output_ranges']
    if (len(outputs) != 1 or address(outputs[0]['base']) != pointers['%rd17']
            or outputs[0]['bytes'] != 4 * rows * columns):
        return None
    return dict(schema='sara-sparse-dot-loop-layout-v1', kernel_uid=next(iter(kernels)),
        row_pointer_base=pointers['%rd16'], column_index_base=pointers['%rd18'],
        values_base=pointers['%rd19'], dense_base=pointers['%rd20'],
        output_base=pointers['%rd17'], arguments=arguments)


def prepare(capture, output, code, *, component='rf', defer_constant_validation=False):
    """Prepare the same clean initial-value strategy for every SM configuration."""
    from script.execution.memory_effect_records import read_closed_ledger
    from script.execution.trace_transport import read_trace_document
    from script.execution.method_input_context import current_context, read_json
    from copy import deepcopy
    capture, output, code = Path(capture), Path(output), Path(code)
    if defer_constant_validation and current_context(capture) is None:
        raise ValueError('deferred constant validation requires the same live own method/core context')
    if component not in ('rf', 'smem', 'l1d', 'l2'):
        raise ValueError('one actual storage component required')
    descriptor_name = 'inputs-' + component + '.json'
    descriptor = deepcopy(read_json(capture / descriptor_name))
    metadata = read_json(capture / 'capture.json')
    if (descriptor['arguments'] != metadata['arguments']
            or descriptor['binary_sha256'] != metadata['actual_binary_sha256']
            or metadata.get('collection') != 'sara'):
        raise ValueError('same fresh clean SARA capture and executable required')
    source = read_json(capture / 'native-source-files.json')
    for name in MEMORY_SOURCES:
        if source.get(name) != _sha(code / name):
            raise ValueError('initial-memory semantics differ from actual native source: ' + name)
    trace_role = descriptor['files']['trace']
    trace_path = capture / trace_role['path']
    if _sha(trace_path) != trace_role['sha256']:
        raise ValueError('clean trace bytes changed')
    checked = read_closed_ledger(capture / 'memory.jsonl', trace_path,
        Path(str(trace_path) + '.completeness.json'),
        expected_cache_state=metadata['cache_state'])
    if checked['source_fingerprint'] != metadata['native_source_fingerprint']:
        raise ValueError('host assignments came from another native build')
    trace, _ = read_trace_document(trace_path)
    count = len(trace['events'])
    writes = []
    for row in checked['copy_effects']:
        if row['effect_kind'] != 'assignment':
            continue
        if not 0 <= row['instruction_cursor'] <= count:
            raise ValueError('actual host assignment outside complete trace')
        data = bytes.fromhex(row['bytes'])
        writes.append(dict(cursor=row['instruction_cursor'], base=hex(row['destination']),
            source=hex(row['source']), hexbytes=data.hex(),
            sha256=hashlib.sha256(data).hexdigest(), kind=row['copy_kind'],
            request_id=row['request_id'], service_sequence=row['service_sequence']))
    ptx = sorted(capture.glob('*.ptx'))
    declarations = _constant_declarations(ptx)
    config = (capture / 'gpgpusim.config').read_text()
    if any(int(value) for value in re.findall(
            r'^\s*-(?:resume_option|checkpoint_option)\s+(\d+)', config, re.M)):
        raise ValueError('fresh process required; checkpoint restoration not admitted')
    image = dict(schema=SCHEMA, scope='fresh_process_golden_host_assignments_and_stores',
        default_unwritten_byte=0, address_limit=ADDRESS_LIMIT,
        native_memory_source_sha256=source['src/cuda-sim/memory.cc'],
        segments=[dict(row) for row in writes if row['cursor'] == 0], writes=writes,
        ptx_sha256={path.name: _sha(path) for path in ptx}, source_files=source,
        case=metadata['case'], arguments=metadata['arguments'],
        output_ranges=read_json(capture / 'output-spec.json'),
        unresolved_native_read_range=[ADDRESS_LIMIT, ADDRESS_LIMIT],
        host_ledger_sha256=checked['ledger_sha256'], trace_sha256=trace_role['sha256'],
        binary_sha256=descriptor['binary_sha256'],
        FI_answers_used=False, hardware_memory_semantics=False)
    constants = _prepare_constants(declarations, checked, writes, source, code)
    if constants:
        image['constant_symbols'] = constants
        # A declaration exception alone is insufficient. Check the actual clean
        # scalar consumers without running backward propagation or querying any
        # sampled origin. Predicate gates are already logical in the raw trace.
        if not defer_constant_validation:
            from script.core.reg_observed_analyzer import parse_event
            events = [parse_event(row, index) for index, row in enumerate(trace['events'])]
            image['constant_read_validation'] = validate_golden_image(events, image)
    issue = re.findall(r'^\s*-gpgpu_max_insn_issue_per_warp\s+(\d+)\s*$', config, re.M)
    if len(ptx) == 1 and issue == ['1']:
        shader = 'src/gpgpu-sim/shader.cc'
        if source.get(shader) != _sha(code / shader):
            raise ValueError('loop issue contract differs from actual native scheduler')
        image['loop_ptx'] = ptx[0].read_text()
        image['loop_fault_protocol'] = dict(schema='sara-frozen-cycle-watchdog-v1',
            golden_cycles=metadata['gpu_cycles'], watchdog_factor=10,
            cycle_limit=10 * metadata['gpu_cycles'], dependent_chain_min_core_cycles=1,
            max_insn_issue_per_warp=1, shader_source_sha256=source[shader])
        layout = _loop_layout(trace, image, metadata)
        if layout is not None:
            image['loop_host_layout'] = layout
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'initial-global-image.json'
    target.write_text(json.dumps(image, sort_keys=True) + '\n')
    for role in descriptor['files'].values():
        relative = Path(role['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('portable input bundle paths required')
        new = output / relative
        new.parent.mkdir(parents=True, exist_ok=True)
        if not new.exists():
            _link_frozen(capture / relative, new)
    for suffix in ('.completeness.json', '.memory_ranges.json'):
        relative = trace_role['path'] + suffix
        if (capture / relative).is_file():
            _link_frozen(capture / relative, output / relative)
    descriptor['files']['initial_global_image'] = dict(path=target.name, sha256=_sha(target))
    (output / descriptor_name).write_text(json.dumps(descriptor, sort_keys=True) + '\n')
    result = dict(schema=SCHEMA, host_assignments=len(writes), source_files=list(MEMORY_SOURCES),
        same_strategy_for_both_SM=True, new_simulations=False,
        golden_load_consistency_checked_by_shared_analysis=True,
        host_ledger_sha256=checked['ledger_sha256'])
    if constants:
        result.update(constant_policy=CONSTANT_SCHEMA,
                      constant_source_files=list(CONSTANT_NATIVE),
                      constant_read_validation=(image['constant_read_validation'] if not defer_constant_validation else
                          {'required_in_same_shared_core_before_prediction': True,
                           'preparation_only_not_admission': True}))
    (output / 'preparation.json').write_text(json.dumps(result, sort_keys=True) + '\n')
    return result


def main():
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--component', choices=('rf', 'smem', 'l1d', 'l2'), default='rf')
    args = parser.parse_args()
    print(json.dumps(prepare(args.capture, args.output, Path(__file__).resolve().parents[2],
                             component=args.component)))


if __name__ == '__main__':
    main()
