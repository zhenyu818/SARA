"""Isolated fixed Stories260K integration; existing scientific readers retained.

Only declared exact capture paths receive explicit resource ceilings. The fixed
trace transport functions keep their original byte/JSON/private-publication
behavior; no alternate parser, prefix, event filter or classification is used.
"""
import os
import hashlib
from pathlib import Path
from types import FunctionType
from script.execution.trace_transport import _json

PHYSICAL_BYTES=16*1024**3
DECODED_BYTES=128*1024**3
# Only the explicitly registered complete sidecar gets this resource bound.
SIDECAR_BYTES=64*1024**2
ORIGINAL_SIDECAR_BYTES=16*1024**2
TRACE_TRANSPORT_SHA='df0cd00805d27463c33df592af1e0b7fda086ff63dc9f5d7c0c1e73da7b97d69'
_SIDECAR_SCOPES=[]
from contextlib import contextmanager
from copy import deepcopy
import re
import time

CASE = 'stories260k-prefix1'
APP = 'LLM_TinyStories260K'
MODEL_COMMIT = '0bd21da7698eaf29a0d7de3992de8a46ef624add'
VOCAB = 512
TOKENS = (1,)
OLD_LEDGER_BYTES = 2*1024**3
LEDGER_BYTES = 16*1024**3
POPULATION_BUDGETS = dict(max_decoded_bytes=16*1024**3,
    max_physical_bytes=8*1024**3, max_records=128000010, max_row_bytes=1024**2)


def _need(value, message):
    if not value:
        raise ValueError(message)


def _option(text, name):
    rows = [line.split('#', 1)[0].split() for line in text.splitlines()]
    found = [row for row in rows if row and row[0] == name]
    _need(len(found) == 1 and len(found[0]) == 2, 'one explicit '+name+' required')
    return found[0][1]


@contextmanager
def sidecar_capacity_scope(trace_path,sidecar_path,*,alias_pairs=(),_allow_future=False):
    """Same fixed decoder; one literal resource constant, exact registered paths.

    The on-disk scientific module, JSON parser, publication function, SHA/CRC
    and lifecycle logic do not change. The temporary raw helper is a different
    function object: only its unique 16MiB co_const becomes 64MiB. Callers must
    retain this explicit distinction from the unchanged numerical entry.
    """
    from script.execution import trace_transport as transport
    from script.execution.method_input_context import OwnInputContext,current_context
    trace,sidecar=Path(trace_path).absolute(),Path(sidecar_path).absolute()
    _need(trace==trace.resolve(strict=not _allow_future)
          and sidecar==sidecar.resolve(strict=not _allow_future)
          and sidecar==Path(str(trace)+'.completeness.json'), 'exact canonical trace/sidecar pair required')
    pairs=((trace,sidecar),)+tuple((Path(a).absolute(),Path(b).absolute()) for a,b in alias_pairs)
    _need(len(pairs)==len(set(pairs)), 'unique explicitly registered trace aliases required')
    module_path=Path(transport.__file__)
    _need(module_path==module_path.resolve(strict=True) and os.statvfs(module_path).f_flag & os.ST_RDONLY
          and hashlib.sha256(module_path.read_bytes()).hexdigest()==TRACE_TRANSPORT_SHA,
          'frozen qualified trace transport bytes required')
    previous_raw,previous_size=transport._read_trace_payload,OwnInputContext.check_size
    base=getattr(previous_raw,'_stories_sidecar_base',previous_raw)
    _need(type(base) is FunctionType and base.__module__==transport.__name__
          and base.__name__=='_read_trace_payload' and base.__globals__ is transport.__dict__,
          'original raw reader or this exact nested resource wrapper required')
    constants=base.__code__.co_consts
    slots=[i for i,value in enumerate(constants) if type(value) is int and value==ORIGINAL_SIDECAR_BYTES]
    _need(len(slots)==1,'unique original literal sidecar capacity required')
    changed=list(constants);changed[slots[0]]=SIDECAR_BYTES
    code=base.__code__.replace(co_consts=tuple(changed))
    restored=list(code.co_consts);restored[slots[0]]=ORIGINAL_SIDECAR_BYTES
    _need(code.co_code==base.__code__.co_code and tuple(restored)==constants
          and code.replace(co_consts=constants)==base.__code__, 'only one reversible resource constant may differ')
    extended=FunctionType(code,base.__globals__,base.__name__,base.__defaults__,base.__closure__)
    extended.__kwdefaults__=dict(base.__kwdefaults__ or {})
    token=object();receipt=dict(original_bound_bytes=ORIGINAL_SIDECAR_BYTES,registered_bound_bytes=SIDECAR_BYTES,
        fixed_module_sha256=TRACE_TRANSPORT_SHA,only_one_co_const_changed=True,bytecode_identical=True,
        original_JSON_and_publication_functions_retained=True,raw_helper_function_object_changed=True,
        exact_registered_pairs=[[str(a),str(b)] for a,b in pairs],raw_calls=0,size_calls=0,bindings_restored=False)
    def registered(path,kind):
        candidate=Path(path).absolute()
        for a,b in pairs:
            if candidate!=(a if kind=='trace' else b):continue
            _need(a==a.resolve(strict=True) and b==b.resolve(strict=True) and a.is_file() and b.is_file()
                  and a.samefile(trace) and b.samefile(sidecar), 'registered aliases must retain exact real source inodes')
            return True
        return False
    def raw(path,**kwargs):
        if not registered(path,'trace'):return previous_raw(path,**kwargs)
        context=kwargs.get('context')
        _need(context is None or current_context(path) is context and context.owns(path),
              'same actual active owner context required')
        receipt['raw_calls']+=1
        return extended(path,**kwargs)
    raw._stories_sidecar_base=base
    def sized(owner,path,maximum):
        if maximum==ORIGINAL_SIDECAR_BYTES and registered(path,'sidecar'):
            _need(current_context(path) is owner and owner.owns(path),'same own sidecar context required')
            receipt['size_calls']+=1
            return previous_size(owner,path,SIDECAR_BYTES)
        return previous_size(owner,path,maximum)
    _SIDECAR_SCOPES.append(token)
    transport._read_trace_payload,OwnInputContext.check_size=raw,sized
    try:yield receipt
    finally:
        _need(_SIDECAR_SCOPES and _SIDECAR_SCOPES[-1] is token
              and transport._read_trace_payload is raw and OwnInputContext.check_size is sized,
              'resource scopes must close in strict original LIFO order')
        transport._read_trace_payload,OwnInputContext.check_size=previous_raw,previous_size
        _SIDECAR_SCOPES.pop();receipt['bindings_restored']=True


def resource_policy():
    return dict(schema='sara-stories260k-prefix1-resource-policy-v1', case=CASE,
        trace_physical_bytes=PHYSICAL_BYTES, trace_decoded_bytes=DECODED_BYTES,
        trace_sidecar_bytes=SIDECAR_BYTES, ledger_bytes=LEDGER_BYTES,
        sidecar_resource_gate_runtime_constant_changed=True,sidecar_original_bound_bytes=ORIGINAL_SIDECAR_BYTES,
        native_capture_wall_time_limit_seconds=None,
        population_decode_budgets=dict(POPULATION_BUDGETS), native_population_codec='plain',
        native_population_lossless_repack=True, ledger_row_bytes=160*1024**2,
        ledger_live_requests=100000, ledger_single_copy_bytes=16*1024**2,
        adapter_scope='exact new-case owned paths and trusted hardlinks; restored on exit',
        scientific_module_bytes_modified=False, algorithm_or_fault_labels_modified=False,
        original14_or_Smol_defaults_modified=False, trace_prefix_accepted=False,
        eager_reader_and_materialization_unchanged=True, RAM_feasibility_guaranteed=False,
        parent_early_memory_stop_bytes=400*1024**3, hard_memory_bytes=448*1024**3)


class Registration:
    def __init__(self, checkpoint, tokens):
        checkpoint = Path(checkpoint).absolute()
        _need(checkpoint == checkpoint.resolve(strict=True) and checkpoint.is_file(),
              'canonical immutable checkpoint required')
        _need(tuple(tokens) == TOKENS, 'only fixed token1 authorized')
        self.checkpoint, self.tokens = checkpoint, TOKENS

    def contract(self, case=CASE):
        _need(case == CASE, 'isolated prefix1 entry cannot select another workload')
        return dict(case=CASE, app=APP, arguments=[str(self.checkpoint)], env_files={},
            outputs=[dict(name='logits', dtype='f32', count=VOCAB, bytes=4*VOCAB)],
            model='Stories260K', official_execution=MODEL_COMMIT,workload_port='cuda-lrg64-v1',cuda_large_block_threads=64,
            output_scope='all512 device logits at position0; host argmax display only',
            batch=1, prefix_tokens=1, layers=5, input_token_ids=list(TOKENS),positions=[0],
            final_position=0,expected_computational_launches=72,generation_feedback=False,
            workload_authorization='isolated new fixed one-token LLM; original registry unchanged')

    def descriptor(self):
        return deepcopy(self.contract())

    def environment(self, case):
        self.contract(case)
        return {'SARA_VALIDATE_CPU':'0'}

    def output_regions(self, log, case):
        from script.execution.method_input_context import read_text
        self.contract(case)
        rows = [dict(base=int(base,16), bytes=int(size), name=name, space='global')
            for base,size,name in re.findall(
                r'GPUFI_OUTPUT base=(0x[0-9a-fA-F]+) bytes=(\d+) name=(\S+)',read_text(log))]
        _need(len(rows) == 1 and rows[0]['name'] == 'logits' and rows[0]['bytes'] == 4*VOCAB,
              'one complete512-logit device allocation required')
        return rows

    @contextmanager
    def installed(self):
        from script.execution import ge_batch_experiment as producer
        from script.execution.batch_workload import contract as original
        old = original('spmm-empty-and-tail')
        try:
            original(CASE)
        except ValueError:
            pass
        else:
            raise ValueError('original registry unexpectedly admits prefix1')
        previous = producer.contract,producer.environment,producer.output_regions
        producer.contract,producer.environment,producer.output_regions = (
            self.contract,self.environment,self.output_regions)
        try:
            _need(original('spmm-empty-and-tail') == old, 'original registry changed')
            yield producer
        finally:
            producer.contract,producer.environment,producer.output_regions = previous
            _need(original('spmm-empty-and-tail') == old, 'original registry changed on exit')

    @contextmanager
    def capture_resources(self, capture, component, persist):
        from script.execution import ge_batch_experiment as producer
        from script.execution import population_repack as repack
        capture = Path(capture).absolute()
        _need(component in ('rf','smem','l1d','l2') and not capture.exists()
              and capture.parent == capture.parent.resolve(strict=True)
              and capture == capture.resolve() and producer.contract(CASE) == self.contract(),
              'fresh exact isolated capture required')
        previous_config,previous_measured,previous_pack = (
            producer.config_text,producer.measured,repack.pack_closed_population)
        receipt = dict(resource_policy(), config_calls=0, native_process_calls=0,
            repack_calls=0, process_receipt_persistence_seconds=0.0, bindings_restored=False)
        def configured(base, options):
            _need(receipt['config_calls'] == 0
                  and options.get('-host_copy_ledger_file') == str(capture/'memory.jsonl')
                  and options.get('-host_copy_ledger_budget_bytes') == str(OLD_LEDGER_BYTES)
                  and options.get('-exact_trace') == '1' and options.get('-regfile_trace') == '0'
                  and options.get('-fi_probe_only') == '0' and options.get('-profile') == '0'
                  and options.get('-cache_state_ledger') == ('1' if component in ('l1d','l2') else '0'),
                  'unexpected producer/path/profile in prefix1 resource adapter')
            text = previous_config(base,dict(options,
                **{'-host_copy_ledger_budget_bytes':str(LEDGER_BYTES)}))
            _need(_option(text,'-host_copy_ledger_budget_bytes') == str(LEDGER_BYTES),
                  'effective producer ledger budget differs')
            receipt['config_calls'] += 1
            return text
        def measured(argv,cwd,log,env,timeout,*,persist_diagnostics=True):
            _need(receipt['native_process_calls'] == 0 and Path(cwd) == capture
                  and Path(log) == capture/'run.log' and persist_diagnostics is False
                  and list(argv) == ['./'+APP,*self.contract()['arguments']],
                  'one exact own native process required')
            receipt['native_process_calls'] += 1
            result = previous_measured(argv,cwd,log,env,timeout=float('inf'),persist_diagnostics=False)
            # Native measured wall has already stopped. Persist now, before
            # repack/packet/qualification can fail and lose this real receipt.
            begin = time.perf_counter()
            persist(capture/'native-process.json',dict(result,
                outer_worker_receipt_persisted_after_native_clock=True,
                original_measured_optional_receipt_was_deferred=True))
            receipt['process_receipt_persistence_seconds'] += time.perf_counter()-begin
            return result
        def packed(source,destination,*,max_decoded_bytes,max_physical_bytes):
            _need(component in ('rf','smem') and receipt['repack_calls'] == 0
                  and Path(source) == capture/'population.native.jsonl'
                  and Path(destination) == capture/'population.jsonl.gz'
                  and max_decoded_bytes == POPULATION_BUDGETS['max_decoded_bytes']
                  and max_physical_bytes == POPULATION_BUDGETS['max_physical_bytes'],
                  'exact complete plain-population repack required')
            # The old repacker accepts byte limits only. Its unchanged closed
            # compact footer gives the complete JSONL record count; the real
            # decoder independently enforces max_records through capture.json.
            with Path(source).open('rb') as stream:
                stream.seek(max(0,Path(source).stat().st_size-16384))
                tail = stream.read(16384)
            _need(tail.endswith(b'\n'), 'closed native population newline required')
            footer = _json(tail.rstrip(b'\n').rsplit(b'\n',1)[-1])
            counts = [footer.get(k) for k in ('descriptors','spans','blocker_count')]
            _need(footer.get('kind') == 'footer' and footer.get('collection_closed') is True
                  and all(type(v) is int and v >= 0 for v in counts)
                  and 2+sum(counts) <= POPULATION_BUDGETS['max_records'],
                  'complete native population record budget exceeded; no prefix')
            result = previous_pack(source,destination,max_decoded_bytes=max_decoded_bytes,
                                   max_physical_bytes=max_physical_bytes)
            receipt['repack_calls'] += 1
            receipt['native_footer_records'] = 2+sum(counts)
            return result
        producer.config_text,producer.measured,repack.pack_closed_population = configured,measured,packed
        try:
            with sidecar_capacity_scope(capture/'trace.json.gz',capture/'trace.json.gz.completeness.json',
                    _allow_future=True) as sidecar_receipt:
                receipt['sidecar_capacity_adapter']=sidecar_receipt
                yield receipt
            _need(receipt['config_calls'] == 1 and receipt['native_process_calls'] == 1
                  and receipt['repack_calls'] == (0 if component in ('l1d','l2') else 1),
                  'necessary capture resource adapters were not exercised exactly once')
        finally:
            producer.config_text,producer.measured,repack.pack_closed_population = (
                previous_config,previous_measured,previous_pack)
            receipt['bindings_restored'] = True

    def _binding(self, context, capture, component):
        from script.execution.method_input_context import current_context
        capture = Path(capture).absolute()
        _need(component in ('rf','smem','l1d','l2') and capture == capture.resolve(strict=True)
              and current_context(capture) is context and context.owns(capture),
              'active exact own prefix1 input context required')
        metadata = context.read_json(capture/'capture.json')
        source_component = metadata.get('component')
        cache = component in ('l1d','l2')
        _need(metadata.get('case') == CASE and metadata.get('collection') == 'sara'
              and (source_component == component or cache and source_component in ('l1d','l2'))
              and metadata.get('minimal_population') is True and metadata.get('cache_state') is cache
              and metadata.get('workload_contract') == self.contract()
              and metadata.get('arguments') == self.contract()['arguments']
              and re.fullmatch(r'[0-9a-f]{64}',str(metadata.get('native_source_fingerprint','')))
              and re.fullmatch(r'sha256:[0-9a-f]{64}',str(metadata.get('image_id',''))),
              'exact source-bound prefix1 own SARA collection required')
        config = capture/'gpgpusim.config'
        _need(context.digest(config) == metadata.get('effective_config_sha256')
              and _option(context.read_text(config),'-host_copy_ledger_budget_bytes') == str(LEDGER_BYTES),
              'effective config must declare exactly16GiB ledger')
        if not cache:
            transport = metadata.get('population_transport',{})
            _need(transport.get('native_codec') == 'plain' and transport.get('stored_codec') == 'gzip'
                  and transport.get('decode_budgets') == POPULATION_BUDGETS
                  and transport.get('logical_population_modified') is False,
                  'complete bounded population decode metadata required')
        ledger = capture/'memory.jsonl'
        _need(ledger == ledger.resolve(strict=True) and ledger.is_file(), 'exact owned ledger required')
        identity = lambda p:(p.st_dev,p.st_ino,p.st_size,p.st_mtime_ns,p.st_ctime_ns)
        before = ledger.stat()
        with ledger.open('rb') as stream:
            row = stream.readline(1024**2+1)
        _need(len(row) <= 1024**2 and row.endswith(b'\n')
              and identity(before) == identity(ledger.stat()), 'bounded unchanged ledger header required')
        header = _json(row)
        _need(header.get('kind') == 'header' and header.get('schema') == 'sara-memory-effects-v2'
              and header.get('sequence') == 0 and header.get('max_ledger_bytes') == LEDGER_BYTES
              and header.get('cache_state_enabled') is cache
              and header.get('source_fingerprint') == metadata['native_source_fingerprint']
              and header.get('image_id') == metadata['image_id'],
              'actual source-bound native16GiB ledger required')
        return dict(capture=capture, ledger=ledger, component=component,
            source_component=source_component, metadata=metadata)

    @contextmanager
    def input_resources(self, context, capture, component):
        from script.execution import trace_transport as original
        from script.execution import memory_effect_records as effects
        from script.execution import trace_completeness as completeness
        from script.execution import cache_physical_facts as facts
        from script.execution import sara_batch_campaign as campaign
        binding = self._binding(context,capture,component)
        capture,ledger = binding['capture'],binding['ledger']
        key=(str(capture),component)
        active=context.__dict__.get('_stories260k_prefix1_resources',[])
        _need(type(active) is list and key not in active,'duplicate capture/component resource scope forbidden')
        directories = (capture,capture/'initial-state') + (
            (capture/'initial-state-l2',) if component in ('l1d','l2') else ())
        originals = dict(trace=capture/'trace.json.gz',sidecar=capture/'trace.json.gz.completeness.json',
                         ledger=ledger)
        names = dict(trace='trace.json.gz',sidecar='trace.json.gz.completeness.json',ledger='memory.jsonl')
        def exact(path,kind):
            candidate = Path(path).absolute()
            if candidate not in tuple(directory/names[kind] for directory in directories):
                return False
            _need(candidate == candidate.resolve(strict=True) and context.owns(candidate)
                  and candidate.is_file() and candidate.samefile(originals[kind]),
                  'only exact original and explicit trusted initial-state hardlinks allowed')
            return True
        old_size = context.check_size
        had_size = 'check_size' in context.__dict__
        saved = [(original,'read_trace_payload',original.read_trace_payload),
                 (original,'read_trace_document',original.read_trace_document),
                 (effects,'read_trace_payload',effects.read_trace_payload),
                 (completeness,'read_trace_payload',completeness.read_trace_payload),
                 (campaign,'read_trace_document',campaign.read_trace_document),
                 (facts,'read_closed_ledger',facts.read_closed_ledger)]
        receipt = dict(resource_policy(),component=component,source_component=binding['source_component'],
            capture=str(capture),size_translations=0,trace_payload_calls=0,trace_document_calls=0,
            cache_ledger_translations=0,bindings_restored=False)
        def sized(path,maximum):
            for kind,previous,updated in (('trace',512*1024**2,PHYSICAL_BYTES),
                    ('sidecar',16*1024**2,SIDECAR_BYTES),('ledger',OLD_LEDGER_BYTES,LEDGER_BYTES)):
                if maximum == previous and exact(path,kind):
                    receipt['size_translations'] += 1
                    return old_size(path,updated)
            return old_size(path,maximum)
        old_payload,old_document,old_cache_reader = saved[0][2],saved[1][2],saved[-1][2]
        def budgets(values):
            _need(set(values) <= {'max_physical_bytes','max_decoded_bytes'}, 'unexpected transport budget')
            _need(values.get('max_physical_bytes',512*1024**2) in (512*1024**2,PHYSICAL_BYTES)
                  and values.get('max_decoded_bytes',1024**3) in (1024**3,DECODED_BYTES),
                  'only exact declared transport bound translation allowed')
            return dict(max_physical_bytes=PHYSICAL_BYTES,max_decoded_bytes=DECODED_BYTES)
        def payload(path,**values):
            if not exact(path,'trace'):
                return old_payload(path,**values)
            receipt['trace_payload_calls'] += 1
            return old_payload(path,**budgets(values))
        def document(path,**values):
            if not exact(path,'trace'):
                return old_document(path,**values)
            receipt['trace_document_calls'] += 1
            return old_document(path,**budgets(values))
        def checked(path,trace,sidecar,*,expected_budget_bytes=None,expected_cache_state=None):
            if not exact(path,'ledger'):
                return old_cache_reader(path,trace,sidecar,expected_budget_bytes=expected_budget_bytes,
                                        expected_cache_state=expected_cache_state)
            _need(component in ('l1d','l2') and expected_cache_state is True
                  and expected_budget_bytes in (OLD_LEDGER_BYTES,LEDGER_BYTES)
                  and exact(trace,'trace') and exact(sidecar,'sidecar')
                  and Path(path).parent == Path(trace).parent == Path(sidecar).parent,
                  'same exact cache ledger/trace/sidecar tuple required')
            receipt['cache_ledger_translations'] += 1
            return old_cache_reader(path,trace,sidecar,expected_budget_bytes=LEDGER_BYTES,
                                    expected_cache_state=True)
        if not active:context._stories260k_prefix1_resources=active
        active.append(key)
        context.check_size = sized
        for module,name,_previous in saved:
            setattr(module,name,checked if name == 'read_closed_ledger' else
                    document if name == 'read_trace_document' else payload)
        try:
            aliases=tuple((directory/'trace.json.gz',directory/'trace.json.gz.completeness.json')
                          for directory in directories[1:])
            with sidecar_capacity_scope(capture/'trace.json.gz',capture/'trace.json.gz.completeness.json',
                    alias_pairs=aliases) as sidecar_receipt:
                receipt['sidecar_capacity_adapter']=sidecar_receipt
                yield receipt
        finally:
            for module,name,previous in saved:
                setattr(module,name,previous)
            if had_size:
                context.check_size = old_size
            else:
                del context.check_size
            _need(active and active[-1]==key,'resource scopes must restore in reverse entry order')
            active.pop()
            if not active:del context._stories260k_prefix1_resources
            receipt['bindings_restored'] = True

    def capacity_admission(self, context, capture, component):
        binding = self._binding(context,capture,component)
        capture = binding['capture']
        trace,sidecar,ledger = (capture/name for name in
            ('trace.json.gz','trace.json.gz.completeness.json','memory.jsonl'))
        for path,maximum in ((trace,PHYSICAL_BYTES),(sidecar,SIDECAR_BYTES),(ledger,LEDGER_BYTES)):
            context.check_size(path,maximum)
        closed = context.read_json(sidecar)
        storage = closed.get('storage',{})
        _need(closed.get('trace_close_succeeded') is True and storage.get('close_succeeded') is True
              and storage.get('codec') == 'gzip' and storage.get('physical_bytes') == trace.stat().st_size
              and type(storage.get('decoded_bytes')) is int and 0 < storage['decoded_bytes'] <= DECODED_BYTES
              and closed.get('trace_bytes') == storage['decoded_bytes']
              and closed.get('trace_sha256') == storage.get('decoded_sha256'),
              'complete actual trace exceeds admitted bounds or lacks closed identity; no prefix')
        return dict(schema='sara-stories260k-prefix1-capacity-admission-v1',admitted=True,
            trace_physical_bytes=trace.stat().st_size,trace_decoded_bytes=storage['decoded_bytes'],
            sidecar_bytes=sidecar.stat().st_size,ledger_bytes=ledger.stat().st_size,
            transport_policy=resource_policy(),actual_full_validation_still_required=True,
            resident_memory_predicted=False, eager_materialization_capacity_guaranteed=False,
            whole_forward_required=True,all_output_logits=VOCAB)
