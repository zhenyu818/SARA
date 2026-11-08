"""Structural validation of the two native standalone storage profiles.

The native standalone producer deliberately emits capture_bytes=false and omits
host-copy, launch-parameter and static-initializer payloads. No bytes are filled
in here. Original Validator handles every other record, including allocations,
request stages, disposition/WB ancestry, cache owner/hooks/mass and drained close.
Functional issue witnesses retain the original extension shape checks: omitted
operands are NULL; any optional operand bytes are shape-checked, not certified.
This adapter is not a numeric trace/assignment-equality or producer certificate.
"""
from script.execution.memory_effect_records import Validator,integer

MAX_COPY_BYTES = 16*1024**2
UINT64_MAX = 2**64-1
_STANDALONE_PROFILES = {'storage-population-v1','storage-efm-v1'}
_FUNCTIONAL = {'functional_cache_load_source','functional_cache_store_intent'}
_OVERRIDES = {'copy_begin','copy_end','kernel_parameter_assignment','static_initialization'} | _FUNCTIONAL


def _need(value,message):
    if not value:
        raise ValueError(message)


def _omitted(row,names):
    for name in names:
        _need(name in row and (row[name] is None or type(row[name]) is str and row[name] == ''),
              'population_payload_must_be_explicitly_omitted:'+name)


def _extent(address,count):
    _need(count <= UINT64_MAX-address,'population_copy_address_extent_overflow')


class PopulationRecordValidator(Validator):
    """Only known standalone profiles; never substitutes for ordinary Validator."""
    def __init__(self):
        super().__init__()
        self.population_overrides = {kind:0 for kind in _OVERRIDES}
        self.population_service_sequence = 0
        self.functional_null_operands = self.functional_present_operands = 0

    def consume(self,row):
        if self.header is None:
            super().consume(row)
            _need(self.header.get('capture_profile') in _STANDALONE_PROFILES
                  and self.header['cache_state_enabled'] is True,
                  'explicit_storage_population_cache_profile_required')
            _need(type(self.header.get('max_copy_bytes')) is int
                  and self.header['max_copy_bytes'] == MAX_COPY_BYTES,
                  'native_population_copy_budget_required')
            return
        if not isinstance(row,dict) or row.get('kind') not in _OVERRIDES:
            return super().consume(row)
        _need(not self.closed,'record_after_close_or_nondict')
        self.sequence += 1
        _need(integer(row.get('sequence'),positive=True) == self.sequence,'record_sequence_gap_or_duplicate')
        integer(row.get('instruction_cursor'))
        kind = row['kind']
        if kind in ('copy_begin','copy_end'):
            _,request = self.request(row)
            stages = request['stages']
            _need(kind not in stages,'duplicate_request_stage')
            _need(('service_enter' if kind == 'copy_begin' else 'copy_begin') in stages,'request_stage_order')
            if kind == 'copy_begin':
                self._copy_begin(row,request)
            else:
                self._copy_end(row,request)
            stages.add(kind)
        elif kind == 'kernel_parameter_assignment':
            self._parameter(row)
        elif kind == 'static_initialization':
            self._initializer(row)
        else:
            self._functional(row)
        self.population_overrides[kind] += 1

    def _functional(self,row):
        from script.execution.cache_semantic_records import validate_extension
        _need(self.header.get('cache_functional_contract') == 'actual_functional_cache_candidates_v1',
              'undeclared_functional_cache_contract')
        _need('actual_operand_bytes' in row,'functional_operand_field_required')
        present = row['actual_operand_bytes'] is not None
        # Native issue witnesses have no timing request lifetime fields. The
        # unchanged disposition/WB branches retain all actual ancestry checks.
        validate_extension(row,self.cache_requests,self.cache_request_parents,values_required=present)
        if present:
            self.functional_present_operands += 1
        else:
            self.functional_null_operands += 1

    def _copy_begin(self,row,request):
        count = integer(row.get('count'),positive=True)
        _need(count == request['count'] and count <= self.header['max_copy_bytes']
              and row.get('copy_kind') == request['copy_kind'] and row.get('capture_bytes') is False,
              'population_copy_capture_or_arguments')
        source,destination = integer(row.get('source')),integer(row.get('destination'))
        handle,offset = integer(row.get('symbol_handle')),integer(row.get('symbol_offset'))
        _need((handle,offset) == (request['symbol_handle'],request['symbol_offset']), 'symbol_request_identity_changed')
        kind = request['copy_kind']
        if kind not in ('symbol_to','symbol_from'):
            _need((source,destination) == (request['source'],request['destination']), 'helper_API_arguments_differ')
        # As in the original observer/Validator, symbol API addresses are not
        # helper-address witnesses (the native API emits zero placeholders).
        # Handle/offset/count, actual allocations and all lifecycle gates stay.
        if kind == 'memset':
            _need(source <= 255,'population_memset_literal_out_of_byte_range')
        else:
            _extent(source,count)
        _extent(destination,count)
        source_needed = kind in ('d2d','d2h','symbol_from')
        destination_needed = kind in ('d2d','h2d','symbol_to','memset')
        for field,address,needed in (('source_allocation',source,source_needed),
                                     ('destination_allocation',destination,destination_needed)):
            _need(field in row,'population_copy_allocation_field_missing')
            if needed:
                allocation = self.allocation(row[field],address,count)
                if kind in ('symbol_to','symbol_from'):
                    _need(allocation['allocator'] == 'symbol' and allocation['offset'] == offset,
                          'actual_symbol_helper_allocation_or_offset_changed')
            else:
                _need(row[field] is None,'host_or_literal_side_must_not_invent_GPU_allocation')
        _need(kind != 'd2d' or not (source < destination+count and destination < source+count), 'overlapping_D2D')
        sequence = integer(row.get('service_sequence'),positive=True)
        _need(sequence == self.population_service_sequence+1,'population_service_sequence_gap_or_reuse')
        self.population_service_sequence = sequence
        request['copy'] = row

    def _copy_end(self,row,request):
        copy = request['copy']
        _need(integer(row.get('service_sequence'),positive=True) == copy['service_sequence'],'helper_sequence_mismatch')
        _need(row['instruction_cursor'] == copy['instruction_cursor'],'instruction_executed_inside_copy_helper')
        _omitted(row,('source_before','destination_before','source_after','destination_after'))
        self.copy_effects.append(dict(copy,instruction_cursor_after=row['instruction_cursor'],bytes=None,
            effect_kind='output' if request['copy_kind'] in ('d2h','symbol_from') else 'assignment',
            payload_values_available=False,byte_assignment_equality_checked=False))

    def _parameter(self,row):
        uid = integer(row.get('kernel_uid'),positive=True); index = integer(row.get('parameter_index'))
        count = integer(row.get('count'),positive=True)
        integer(row.get('symbol_uid'),positive=True); address = integer(row.get('address'))
        integer(row.get('entry_pc')); integer(row.get('scalar_type'))
        integer(row.get('host_source_address'),positive=True)
        _need(row.get('schema') == 'sara-launch-parameter-assignment-v1' and count <= 1024**2
              and integer(row.get('declared_size_bits'),positive=True) == count*8
              and isinstance(row.get('entry'),str) and row['entry']
              and isinstance(row.get('symbol_name'),str) and row['symbol_name']
              and address+count <= 2**64,'actual_parameter_assignment_metadata_required')
        _omitted(row,('source_bytes','assigned_bytes'))
        parameters = self.launch_parameters.setdefault(uid,{})
        _need(uid not in self.kernels and uid not in self.closed_parameters and index not in parameters,
              'parameter_assignment_after_close_launch_or_duplicate')
        _need(not any(address < item['address']+item['count'] and item['address'] < address+count
                      for item in parameters.values()),'overlapping_launch_parameter_assignments')
        parameters[index] = row

    def _initializer(self,row):
        uid = integer(row.get('symbol_uid'),positive=True)
        address,count = integer(row.get('address')),integer(row.get('count'),positive=True)
        _extent(address,count)
        symbol = self.symbol_definitions.get(uid)
        _need(symbol is not None and row.get('symbol_name') == symbol['symbol_name']
              and symbol['base'] <= address and address+count <= symbol['base']+symbol['size'],
              'population_initializer_symbol_or_extent_mismatch')
        _omitted(row,('literal_bytes','actual_bytes'))
        self.static_initializations.append(dict(row))

    def report(self):
        report = super().report()  # The original close/request/cache gates must actually succeed.
        return dict(report,schema='gerem-method-population-records-checked-v1',
            base_validator_schema=report['schema'],capture_profile=self.header['capture_profile'],
            population_overridden_record_counts=dict(self.population_overrides),
            copy_payload_values_available=False,byte_assignment_equality_checked=False,
            parameter_byte_equality_checked=False,static_initializer_byte_equality_checked=False,
            functional_operand_equality_checked=False,actual_optional_bytes_shape_only=True,
            functional_null_operands=self.functional_null_operands,
            functional_present_operand_shape_checks=self.functional_present_operands,
            numeric_trace_binding_checked=False,producer_authenticity_certified=False,
            full_method_fidelity_certified=False)
