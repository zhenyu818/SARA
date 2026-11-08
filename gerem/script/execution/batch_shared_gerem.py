"""Value-free shared def/use adapter for GEREM's own allocated domain.

Original storage DCR/SIC rules are reused. Initial page bytes have allocator
births, not invented instruction values. This is not an outcome predictor fit
to FI and does not consume SARA sensitivity or numerical traces.
Compact page inventories expose their existing byte-span view lazily; this
adapter does not persist an expanded per-byte inventory, selectors or ACKs.
The changed acquisition interface requires fresh scoped validation on B.
"""
import hashlib
import io
import json
from pathlib import Path


def number(value):
    if isinstance(value,bool): raise ValueError('boolean storage coordinate')
    value = int(value,0) if isinstance(value,str) else value
    if type(value) is not int or value < 0: raise ValueError('invalid coordinate')
    return value


def static_instructions(table):
    if (table.get('schema') != 'sara-function-static-cfg-v1' or
            table.get('source') != 'actual_assembled_ptx_instruction_memory' or
            table.get('complete_for_gerem') is not True or table.get('issues') != []):
        raise ValueError('complete actual assembled CFG required for shared SIC')
    rows = table['instructions'];start=number(table['start_pc']);cursor=start;pcs=set()
    if len(rows) != table['instruction_count'] or not rows:
        raise ValueError('truncated/empty static function')
    for row in rows:
        pc=number(row['pc']);size=number(row['size_bytes'])
        if pc!=cursor or not 1<=size<=8 or pc in pcs or row.get('unsupported')!='':
            raise ValueError('actual static instruction partition is incomplete')
        if row['base_opcode'] != row['opcode'].split('.',1)[0]:
            raise ValueError('actual static opcode disagrees')
        cursor+=size;pcs.add(pc)
    if cursor!=start+number(table['extent_bytes']):raise ValueError('unclosed static extent')
    result=[]
    for row in rows:
        pc=number(row['pc']);sequential=pc+number(row['size_bytes']);base=row['base_opcode']
        if type(row.get('has_predicate')) is not bool:raise ValueError('missing static predicate metadata')
        edges={'next_pc':None,'taken_target_pc':None,'fallthrough_pc':None}
        if base=='bra':
            kind='branch';edges['taken_target_pc']=number(row['taken_target_pc'])
            if row['has_predicate']:edges['fallthrough_pc']=sequential
        elif base in ('ret','exit'):
            kind='ret'
            if row['has_predicate']:raise ValueError('conditional return not admitted')
        else:
            if base in ('brx','break','breakaddr','call','callp','retp','trap','ssy'):
                raise ValueError('indirect/interprocedural SIC not admitted')
            kind='store' if row['memory_write'] else 'load' if row['memory_read'] else 'inst'
            edges['next_pc']=sequential
        if row['kind']!=kind:raise ValueError('static kind mismatch')
        for key,value in edges.items():
            actual=None if row[key] is None else number(row[key])
            if actual!=value or value is not None and value not in pcs:
                raise ValueError('missing/inconsistent actual CFG successor')
        result.append({'pc':hex(pc),'kind':kind,'opcode':row['opcode'],
            **{key:hex(value) for key,value in edges.items() if value is not None}})
    return result


def population_births(inventory):
    """Original allocator-birth events from byte or compact-page input.

    Every allocated byte still gets its same storage birth. Scope/object checks
    happen once per compact page, without constructing a second byte inventory.
    """
    spans = inventory['spans']
    pages = getattr(spans, 'pages', None)
    rows = pages if pages is not None else spans
    slots, objects, births = {}, {}, {}
    for span in rows:
        if pages is None:
            if span['component'] != 'smem' or span['bit_count'] != 8:
                raise ValueError('same complete allocated shared-byte population required')
            addresses = (number(span['target']['byte_addr']),)
        else:
            if span['component'] != 'smem_page':
                raise ValueError('compact shared-page population required')
            begin, count = number(span['byte_start']), number(span['byte_count'])
            if not count: raise ValueError('nonempty complete allocated shared page required')
            addresses = range(begin, begin + count)
        target, life = span['target'], span['lifecycle']
        uid = number(life['shared_storage_uid'])
        scope = (number(target['sm']), number(target['cta_id']))
        slot = number(life['shared_allocator_slot'])
        if slots.setdefault(scope, (uid, slot)) != (uid, slot) or objects.setdefault(uid, scope) != scope:
            raise ValueError('persistent shared object mapping is not bijective')
        birth = (number(span['cycle_start']), number(target['kernel']), scope)
        for address in addresses:
            key = (uid, address)
            if key not in births or birth[0] < births[key][0]: births[key] = birth
    return slots, objects, births


def read_profile(path, inventory, *, source_fingerprint):
    from script.execution.method_input_context import current_context
    context = current_context(path)
    prefix=hashlib.sha256();bytes_seen=0;header=None;footer=None
    functions={};accesses=[]
    # The production context hashes and retains this own method input once.
    # Standalone validation keeps the prior streaming behavior.
    complete = hashlib.sha256() if context is None else None
    if context is not None:
        stream = io.BytesIO(context.read_bytes(path))
        context.count(path, 'shared_profile_decodes')
    else:
        stream = Path(path).open('rb')
    with stream:
        for line in stream:
            if complete is not None:
                complete.update(line)
            row=json.loads(line)
            if footer is not None:raise ValueError('shared profile has trailing records')
            kind=row.get('kind')
            if header is None:
                if (kind!='header' or row.get('schema')!='sara-gerem-shared-def-use-v1' or
                        row.get('values_collected') is not False or
                        row.get('source_fingerprint')!=source_fingerprint or
                        row.get('shared_identity_contract')!='actual_allocator_persistent_object_owner_epoch_v1'):
                    raise ValueError('value-free source-bound shared profile required')
                header=row
            elif kind=='static_cfg':
                key=(number(row['kernel_uid']),number(row['function']['start_pc']))
                if key in functions:raise ValueError('duplicate assembled function')
                functions[key]=row['function']
            elif kind=='access':
                if number(row['ordinal'])!=len(accesses)+1 or type(row.get('write')) is not bool:
                    raise ValueError('shared access ordinal/type lost')
                if accesses and number(row['cycle'])<accesses[-1]['cycle']:
                    raise ValueError('shared def/use is not ordered')
                row['cycle']=number(row['cycle']);accesses.append(row)
            elif kind=='footer':
                footer=row
                if (row.get('producer_complete') is not True or row.get('prefix_bytes')!=bytes_seen or
                        row.get('prefix_sha256')!=prefix.hexdigest() or row.get('records')!=len(accesses) or
                        row.get('functions')!=len(functions) or not accesses or
                        row.get('first_cycle')!=accesses[0]['cycle'] or row.get('last_cycle')!=accesses[-1]['cycle']):
                    raise ValueError('shared profile close/hash/count mismatch')
                continue
            else:raise ValueError('unknown minimal shared profile record')
            prefix.update(line);bytes_seen+=len(line)
    if footer is None:raise ValueError('shared producer did not close')
    decoded_by_function={key:{number(r['pc']):r for r in table['instructions']}
                         for key,table in functions.items()}
    slots, objects, births = population_births(inventory)
    events=[]
    for (uid,address),(cycle,kernel,scope) in births.items():
        events.append({'cycle':cycle,'_order':-1,'kernel_uid':kernel,'sm_id':scope[0],
            'cta_id':scope[1],'kind':'store','mem_space':'shared','mem_addr':address,
            'store_size_bytes':1,'mem_access_size_bytes':1,
            'allocator_birth_not_PTX_instruction':True})
    for row in accesses:
        scope=(number(row['sm_id']),number(row['cta_id']));uid=number(row['object_uid'])
        if slots.get(scope)!=(uid,number(row['allocator_slot'])) or not number(row['owner_epoch']):
            raise ValueError('actual access/population shared identity mismatch')
        key=(number(row['kernel_uid']),number(row['function_start_pc']))
        decoded=decoded_by_function[key][number(row['pc'])]
        if row['opcode']!=decoded['opcode'] or row['write']!=decoded['memory_write']:
            raise ValueError('shared access differs from actual decoded instruction')
        size=number(row['size_bytes'])
        if not 1<=size<=8:raise ValueError('scalar shared access scope exceeded')
        events.append({'cycle':row['cycle'],'_order':row['ordinal'],'kernel_uid':row['kernel_uid'],
            'thread_id':row['thread_id'],'sm_id':scope[0],'cta_id':scope[1],
            'kind':'store' if row['write'] else 'load','mem_space':'shared',
            'mem_addr':number(row['mem_addr']),'mem_access_size_bytes':size,
            ('store_size_bytes' if row['write'] else 'load_size_bytes'):size,
            'pc':row['pc'],'opcode':row['opcode']})
    # Build each full static table once. This input supplies no dynamic values.
    structural={}
    for table in functions.values():
        for row in static_instructions(table):
            if row['pc'] in structural and structural[row['pc']]!=row:
                raise ValueError('same PC has incompatible per-kernel SIC context')
            structural[row['pc']]=row
    events.sort(key=lambda row:(row['cycle'],row['_order']))
    return {'events':events},{'events':list(structural.values())},{
        'actual_shared_accesses':len(accesses),'assembled_functions':len(functions),
        'initial_allocated_byte_versions':len(births),'numeric_values_collected':False,
        'persistent_shared_objects':len(objects),'prefix_sha256':prefix.hexdigest(),
        'def_use_sha256':context.digest(path) if context is not None else complete.hexdigest(),
        'own_population_mapping_used':True,'FI_selectors_or_ACKs_required':False,
        'EFM_probability_rules_changed':False}
