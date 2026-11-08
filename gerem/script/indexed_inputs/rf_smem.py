"""Indexes and invocation-local SIC reuse around the unchanged method solver.

No final fault answer is cached. Every draw still selects its actual lifetime
and consumer. A SIC cache entry contains only the static probability/result.
"""
from bisect import bisect_right
from collections import defaultdict
from copy import deepcopy
from script.storage_rules import rf_smem as method
from script.execution.method_input_context import freeze

POLICY = 'method-v1-exact-solver-indexed-static-core-v1'


class _QueryView:
    _same_kernel = staticmethod(method.NaiveStorageEFM._same_kernel)
    _shared_access = staticmethod(method.NaiveStorageEFM._shared_access)

    def __init__(self, owner, events):
        self.events, self.cycle_stop, self._sic = events, owner.cycle_stop, owner._sic


class _Intervals:
    def __init__(self, items):
        self.items = sorted(items, key=lambda item:(item[0],item[2]))
        self.starts = [item[0] for item in self.items]
        self.max_end = []; maximum = -1
        for _start,end,_ordinal,_row in self.items:
            maximum = max(maximum,end); self.max_end.append(maximum)

    def at(self,address):
        index = bisect_right(self.starts,address)-1; result = []
        while index >= 0 and self.max_end[index] > address:
            start,end,ordinal,row = self.items[index]
            if start <= address < end:
                result.append((ordinal,row))
            index -= 1
        result.sort(key=lambda item:item[0])
        return [row for _ordinal,row in result]


class IndexedStorageEFM(method.NaiveStorageEFM):
    def __init__(self,trace,sampling_space,static_trace=None):
        super().__init__(trace,sampling_space,static_trace)
        self.stats = dict(queries=0,rf_index_queries=0,smem_index_queries=0,index_fallbacks=0,
            sic_calls=0,sic_hits=0,sic_misses=0,sic_core_evaluations=0,program_builds=0,
            static_nodes_compiled=0,reachable_regions_built=0,reachable_region_hits=0)
        self._threads = defaultdict(list); self._registers = defaultdict(list); self._bad_threads = set()
        self._scopes = defaultdict(list); self._bad_scopes = set(); intervals = defaultdict(list)
        for ordinal,row in enumerate(self.events):
            thread = row.get('thread_id')
            try: hash(thread)
            except TypeError: thread = None
            self._threads[thread].append(row)
            names,uids = row.get('src_regs',[]),row.get('src_reg_uids',[])
            kernel = row.get('kernel_uid')
            if (not isinstance(names,list) or not isinstance(uids,list) or uids and len(uids)!=len(names)
                    or kernel is not None and method._coordinate(kernel) is None):
                self._bad_threads.add(thread)
            else:
                relevant = set(name for name in names if isinstance(name,str))
                if isinstance(row.get('dst_reg'),str): relevant.add(row['dst_reg'])
                for name in relevant: self._registers[thread,name].append(row)
            if row.get('mem_space') not in ('shared','smem'): continue
            scope = (row.get('sm_id'),row.get('cta_id'))
            try: hash(scope)
            except TypeError: continue
            self._scopes[scope].append(row)
            kind = row.get('kind'); start = method._coordinate(row.get('mem_addr'))
            size = method._coordinate(row.get('load_size_bytes' if kind=='load' else 'store_size_bytes',row.get('mem_access_size_bytes')))
            if kind not in ('load','store') or start is None or size is None or size==0:
                self._bad_scopes.add(scope)
            else: intervals[scope].append((start,start+size,ordinal,row))
        self._intervals = {key:_Intervals(value) for key,value in intervals.items()}
        self._sic_cache = {}; self._program_source = object(); self._sync_program()

    def _sync_program(self):
        if self.static_trace is self._program_source: return
        # An owned immutable copy prevents caller mutation from silently changing
        # a cached dependency. Replacing static_trace explicitly rebuilds it.
        self.static_trace = freeze(self.static_trace) if self.static_trace is not None else None
        self._program_source = self.static_trace; self._program_token = object(); self._sic_cache.clear()
        self._nodes = {}; self._regions = {}
        self._pc_rows = defaultdict(list); self._static_index_safe = True
        if self.static_trace is not None:
            try:
                for row in self.static_trace['events']:
                    if not isinstance(row,method.Mapping): raise ValueError('static instruction must be an object')
                    self._pc_rows[method._required_coordinate(row.get('pc'),'static PC')].append(row)
            except (ValueError,TypeError,KeyError): self._static_index_safe = False
        self.stats['program_builds'] += int(self.static_trace is not None)

    def _instruction(self,pc,consumer):
        if not self._static_index_safe:
            return method.NaiveStorageEFM._instruction(self,pc,consumer)
        found = None
        for row in self._pc_rows.get(pc,()):
            if not self._same_kernel(row,{'kernel':consumer.get('kernel_uid')}): continue
            if found is not None: raise ValueError('ambiguous static PC in the own program')
            found = row
        return found

    def _sic(self,consumer):
        self.stats['sic_calls'] += 1; self._sync_program()
        pc,kernel = method._coordinate(consumer.get('pc')),consumer.get('kernel_uid')
        normalized_kernel = method._coordinate(kernel) if kernel is not None else None
        tolerance,maximum = self.sic_tolerance,self.sic_max_iterations
        usable = (pc is not None and (kernel is None or normalized_kernel is not None)
            and type(maximum) is int and maximum>=1 and type(tolerance) in (int,float) and 0<tolerance<1)
        if not usable:
            self.stats['sic_misses'] += 1; self.stats['sic_core_evaluations'] += 1
            return method.NaiveStorageEFM._sic(self,consumer)
        load = self._instruction(pc,consumer) if self.static_trace is not None else None
        next_pc = method._coordinate(load.get('next_pc')) if load is not None else None
        key = (POLICY,self._program_token,normalized_kernel,pc,next_pc,type(tolerance).__name__,
               float(tolerance).hex(),maximum)
        if key in self._sic_cache:
            self.stats['sic_hits'] += 1
            return deepcopy(self._sic_cache[key])
        self.stats['sic_misses'] += 1; self.stats['sic_core_evaluations'] += 1
        # The original reachable-node order, recurrence, lower/upper stopping
        # bounds and numerical precision execute unchanged at the first miss.
        result = self._compiled_sic(consumer,pc,load)
        self._sic_cache[key] = deepcopy(result)
        return result

    def _node(self,pc,consumer,kernel):
        key = kernel,pc
        if key in self._nodes: return self._nodes[key]
        row = self._instruction(pc,consumer)
        if row is None:
            result = None,(None,'static_path_has_missing_successor',{},'unsupported_static_program')
        else:
            kind,opcode = row.get('kind','inst'),row.get('opcode','')
            if not isinstance(opcode,str): raise ValueError('static opcode must be a string')
            base = opcode.lower().split('.',1)[0]
            is_branch = kind=='branch' or base in ('bra','brx')
            if kind=='ret' or base in ('ret','exit'):
                result = dict(pc=pc,terminal=True,coefficient=1.0,successors=[]),None
            elif base in ('call','callp','retp','brx','trap'):
                result = None,(None,'interprocedural_or_indirect_static_path_not_supported',{},'unsupported_static_program')
            else:
                successors = []
                for field in (('taken_target_pc','fallthrough_pc') if is_branch else ('next_pc',)):
                    if row.get(field) is not None:
                        successor = method._required_coordinate(row[field],'static successor')
                        if successor not in successors: successors.append(successor)
                if not successors:
                    result = None,(None,'static_path_has_no_explicit_termination',{},'unsupported_static_program')
                else:
                    conditional = is_branch and (len(successors)>1 or row.get('has_predicate') is True)
                    result = dict(pc=pc,terminal=False,coefficient=0.5 if base in ('min','max') or conditional else 1.0,
                                  successors=successors),None
        self._nodes[key] = result; self.stats['static_nodes_compiled'] += 1
        return result

    def _compiled_sic(self,consumer,pc,load):
        if self.static_trace is None: return None,'complete_static_program_not_supplied_for_SMEM_SIC',{},'unmapped'
        if load is None: return None,'shared_consumer_missing_from_static_program',{},'unmapped'
        if load.get('next_pc') is None: return None,'shared_load_has_no_explicit_next_static_instruction',{},'unsupported_static_program'
        start = method._required_coordinate(load['next_pc'],'shared-load successor')
        kernel = method._coordinate(consumer.get('kernel_uid'))
        region_key = kernel,start
        if region_key in self._regions:
            self.stats['reachable_region_hits'] += 1; nodes,refusal = self._regions[region_key]
        else:
            pending,nodes,seen,refusal = [start],[],set(),None
            while pending:
                current = pending.pop()
                if current in seen: continue
                node,refusal = self._node(current,consumer,kernel)
                if refusal is not None: break
                seen.add(current); nodes.append(node); pending.extend(node['successors'])
            if refusal is None:
                terminal = [node['pc'] for node in nodes if node['terminal']]
                if not terminal:
                    refusal = None,'reachable_static_program_has_no_explicit_terminal',{},'unsupported_static_program'
                else:
                    reachable = set(terminal); changed = True
                    while changed:
                        changed = False
                        for node in nodes:
                            if node['pc'] not in reachable and any(child in reachable for child in node['successors']):
                                reachable.add(node['pc']); changed = True
                    if len(reachable)!=len(nodes):
                        refusal = None,'reachable_static_region_has_no_terminal_path',{},'unsupported_static_program'
            self._regions[region_key] = nodes,refusal; self.stats['reachable_regions_built'] += 1
        if refusal is not None: return deepcopy(refusal)
        # Original Jacobi arithmetic and successor summation order, with an
        # ordinary PC->vector-offset dictionary replacing linear previous_value.
        positions = {node['pc']:offset for offset,node in enumerate(nodes)}
        def previous_value(values,wanted_pc):
            if wanted_pc not in positions: raise ValueError('reachable CFG lost an explicit successor')
            return values[positions[wanted_pc]]
        lower = [1.0 if node['terminal'] else 0.0 for node in nodes]
        upper = [1.0 for _node in nodes]; residual,gap = 1.0,1.0
        for iteration in range(1,self.sic_max_iterations+1):
            next_lower,next_upper = [],[]
            for node in nodes:
                if node['terminal']: lo = hi = 1.0
                else:
                    count = len(node['successors'])
                    lo = node['coefficient'] * sum(previous_value(lower,child) for child in node['successors']) / count
                    hi = node['coefficient'] * sum(previous_value(upper,child) for child in node['successors']) / count
                next_lower.append(lo); next_upper.append(hi)
            residual = max(max(abs(a-b) for a,b in zip(next_lower,lower)),max(abs(a-b) for a,b in zip(next_upper,upper)))
            gap = max(hi-lo for lo,hi in zip(next_lower,next_upper)); lower,upper = next_lower,next_upper
            if residual<=self.sic_tolerance and gap<=self.sic_tolerance:
                lo,hi = previous_value(lower,start),previous_value(upper,start)
                return (lo+hi)/2.0,'declared_naive_static_SIC_reproduction_choices',dict(iterations=iteration,
                    residual=residual,solution_bound_width=gap,start_lower_bound=lo,start_upper_bound=hi,
                    tolerance=self.sic_tolerance,max_iterations=self.sic_max_iterations,reachable_static_nodes=len(nodes),
                    branch_successor_weights='equal',converged=True),'method_guided_naive_reproduction'
        return None,'static_SIC_fixed_point_did_not_converge',dict(iterations=self.sic_max_iterations,
            residual=residual,solution_bound_width=gap,tolerance=self.sic_tolerance,max_iterations=self.sic_max_iterations,
            reachable_static_nodes=len(nodes),branch_successor_weights='equal',converged=False),'numerical_unconverged'

    def _rf(self,target,cycle,bit):
        thread = method._coordinate(target.get('thread')); name = target.get('register',target.get('reg'))
        kernel = target.get('kernel')
        if (thread is None or not isinstance(name,str) or thread in self._bad_threads
                or kernel is not None and method._coordinate(kernel) is None):
            self.stats['index_fallbacks'] += 1
            return method.NaiveStorageEFM._rf(self,target,cycle,bit)
        self.stats['rf_index_queries'] += 1
        return method.NaiveStorageEFM._rf(_QueryView(self,self._registers.get((thread,name),())),target,cycle,bit)

    def _smem(self,target,cycle,bit):
        scope = tuple(method._coordinate(target.get(key)) for key in ('sm','cta_id'))
        address = method._coordinate(target.get('byte_addr'))
        if None in scope or address is None or scope in self._bad_scopes:
            self.stats['index_fallbacks'] += 1
            return method.NaiveStorageEFM._smem(self,target,cycle,bit)
        self.stats['smem_index_queries'] += 1
        table = self._intervals.get(scope)
        return method.NaiveStorageEFM._smem(_QueryView(self,table.at(address) if table else ()),target,cycle,bit)

    def query(self,trial):
        self.stats['queries'] += 1
        return super().query(trial)

    def statistics(self):
        return dict(self.stats,raw_events=len(self.events),rf_register_index_keys=len(self._registers),
            shared_scope_indexes=len(self._intervals),static_PC_keys=len(self._pc_rows),sic_cached_cores=len(self._sic_cache),
            size_semantics='counts of retained rows/keys, not heap bytes or reset memory peaks',
            cached_diagnostics_iterations='iterations of the reused numerical solution; actual core evaluations/cache hits reported separately')
