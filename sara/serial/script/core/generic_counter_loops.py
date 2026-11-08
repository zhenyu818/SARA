"""Structural counter-loop certificates; no program names or fixed registers.

The certificate only proves a lower bound on dependent counter updates. It
does not replay loop bodies, infer unseen memory values, or claim a completion
upper bound. Non-admitted loops retain the ordinary SARA prediction.
"""
from collections import defaultdict
from dataclasses import dataclass
import math
import re
import time

WORD = (1 << 32) - 1
SCHEMA = 'sara-generic-integer-counter-loop-v1'


@dataclass(frozen=True)
class RFLoopEffect:
    kernel: int
    thread: int
    uid: int
    start: int
    stop: int
    due: int = 0
    masked: int = 0
    value_only: int = 0
    rule: str = ''


def required_updates(value, step, width=32):
    """Least positive k with value + k*step == 0 modulo 2**width.

    None means the modular recurrence never reaches zero. Width is explicit
    for arithmetic qualification; production admission below is exactly u32.
    """
    if not 1 <= width <= 64 or not 0 <= value < 1 << width:
        raise ValueError('bounded integer word required')
    modulus = 1 << width
    step %= modulus
    g = math.gcd(step, modulus)
    if value % g:
        return None
    reduced = modulus // g
    if reduced == 1:
        return 1
    k = ((-value // g) * pow(step // g, -1, reduced)) % reduced
    return k if k else reduced


def parse_single_entry(text):
    """Parse the small explicit PTX subset used by the loop certificate.

    Unknown statements are retained and consequently refuse admission. Label
    and register spelling carry identity only, never a prediction policy.
    """
    if not isinstance(text, str):
        return None
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    entries = list(re.finditer(r'\.entry\s+[^\s(]+\s*\(', text))
    if len(entries) != 1 or re.search(r'\.func\b', text):
        return None
    start = text.find('{', entries[0].end())
    end = text.rfind('}')
    if start < 0 or end <= start or '{' in text[start+1:end] or '}' in text[start+1:end]:
        return None
    body = text[start+1:end]
    labels, rows = {}, []
    pending = ''
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(':'):
            if pending or line[:-1] in labels:
                return None
            labels[line[:-1]] = len(rows)
            continue
        if line.startswith('.'):
            if not line.startswith(('.reg ', '.pragma ', '.loc ')):
                return None
            continue
        pending += ' ' + line
        while ';' in pending:
            statement, pending = pending.split(';', 1)
            m = re.fullmatch(r'\s*(?:@(!?%[\w.$]+)\s+)?([\w.]+)\s*(.*?)\s*', statement)
            if not m:
                return None
            pred, op, args = m.groups()
            rows.append(dict(pred=pred, op=op, args=tuple(a.strip() for a in args.split(',')) if args else ()))
    return (rows, labels) if not pending.strip() else None


def structural_loops(text):
    parsed = parse_single_entry(text)
    if parsed is None:
        return []
    rows, labels = parsed
    result = []
    for end, branch in enumerate(rows):
        if (branch['op'] != 'bra' or not branch['pred'] or branch['pred'].startswith('!')
                or len(branch['args']) != 1 or end < 2):
            continue
        begin = labels.get(branch['args'][0], end)
        update, test = rows[end-2:end]
        if (not begin <= end-2 or test['pred'] is not None or update['pred'] is not None
                or test['op'] not in ('setp.ne.s32', 'setp.ne.u32')
                or len(test['args']) != 3 or test['args'][0] != branch['pred']
                or test['args'][2] not in ('0', '0x0', '0x00000000')
                or update['op'] not in ('add.s32', 'add.u32', 'sub.s32', 'sub.u32')
                or len(update['args']) != 3 or update['args'][0] != update['args'][1]
                or update['args'][0] != test['args'][1]):
            continue
        counter = update['args'][0]
        try:
            step = int(update['args'][2], 0) * (-1 if update['op'].startswith('sub') else 1)
        except ValueError:
            continue
        if not step & WORD:
            continue
        # One unconditional update, no alternate exit, predicated execution,
        # interprocedural transfer, synchronization, trap, or side-effecting
        # instruction whose control behavior has not been closed.
        admitted = True
        for row in rows[begin:end-2]:
            root = row['op'].split('.', 1)[0]
            if (row['pred'] is not None or root in ('bra','brx','call','callp','ret','exit','trap','brkpt','bar','membar','atom','red')
                    or (row['args'] and row['args'][0] == counter)):
                admitted = False
                break
        if admitted:
            result.append(dict(counter=counter, step=step & WORD, update_op=update['op'], update_pc=(end-2)*8,
                test_op=test['op'], predicate=test['args'][0], begin=begin, end=end,
                body_signature=tuple((r['op'],r['args']) for r in rows[begin:end+1])))
    return result


def construct(events, image):
    start = time.perf_counter()
    facts = dict(schema=SCHEMA, FI_answers_used=False, per_origin_replay=False,
        application_specific_dispatch=False, source_hash_selects_rules=False,
        effects=0, due_bit_intervals=0, masked_bit_intervals=0,
        extra_zero_loop_completion_upper_bound_available=False)
    protocol = image.get('loop_fault_protocol') if image else None
    loops = structural_loops(image.get('loop_ptx')) if image else []
    if not loops or len({e.kernel_uid for e in events}) != 1 or protocol is None:
        facts.update(status='not_admitted_ordinary_model_retained', construction_seconds=time.perf_counter()-start)
        return [], facts
    rows, _ = parse_single_entry(image['loop_ptx'])
    # Bind every observed instruction, rather than assuming that a register
    # name denotes this particular loop everywhere in the kernel.
    for e in events:
        try:
            pc = int(e.pc, 0) if isinstance(e.pc,str) else int(e.pc)
        except (ValueError,TypeError):
            pc = -1
        if pc < 0 or pc % 8 or pc//8 >= len(rows) or rows[pc//8]['op'] != e.opcode:
            facts.update(status='PTX_event_alignment_unproved_ordinary_model_retained',
                         construction_seconds=time.perf_counter()-start)
            return [], facts
    if (protocol.get('schema') != 'sara-frozen-cycle-watchdog-v1'
            or any(type(protocol.get(k)) is not int for k in ('golden_cycles','watchdog_factor','cycle_limit','dependent_chain_min_core_cycles'))
            or protocol['golden_cycles']*protocol['watchdog_factor'] != protocol['cycle_limit']
            or protocol['watchdog_factor'] != 10 or protocol['dependent_chain_min_core_cycles'] != 1
            or protocol.get('max_insn_issue_per_warp') != 1
            or protocol.get('shader_source_sha256') != image.get('source_files',{}).get('src/gpgpu-sim/shader.cc')):
        raise ValueError('existing native dependent issue and watchdog contract required')
    by_counter = defaultdict(list)
    for loop in loops:
        by_counter[loop['counter']].append(loop)
    last, effects = {}, []
    for e in events:
        if e.pred is not None and not e.pred.val:
            continue
        if (e.kind == 'inst' and e.dst_reg in by_counter and e.dst_reg_uid is not None
                and e.dst_write_mask == WORD and len(e.src_regs) == 2
                and e.src_reg_uids[0] == e.dst_reg_uid and e.src_regs[0] == e.dst_reg
                and e.src_width_bits == [32,32]):
            pc = int(e.pc,0) if isinstance(e.pc,str) else int(e.pc)
            matches = [l for l in by_counter[e.dst_reg] if pc == l['update_pc'] and e.opcode == l['update_op']
                       and ((int(e.src_vals[1]) * (-1 if e.opcode.startswith('sub') else 1)) & WORD) == l['step']]
            # A repeated counter spelling at different loops is not enough to
            # bind a dynamic update; refuse ambiguous static candidates.
            if len(matches) == 1:
                loop = matches[0]
                key = (e.kernel_uid,e.thread_id,e.dst_reg_uid)
                previous = last.get(key)
                value = int(e.src_vals[0]) & WORD
                if (int(e.dst_val) & WORD) != (value+loop['step']) & WORD:
                    raise ValueError('native golden counter update mismatch')
                if previous is not None and previous < e.cycle:
                    due = 0
                    for bit in range(32):
                        required = required_updates(value ^ (1 << bit), loop['step'])
                        if required is None or e.cycle+required-1 > protocol['cycle_limit']:
                            due |= 1 << bit
                    if due:
                        effects.append(RFLoopEffect(*key,previous,e.cycle,due=due,rule='structurally_closed_modular_counter_lower_bound'))
        for uid in e.src_reg_uids:
            if uid is not None and uid >= 0:
                last[e.kernel_uid,e.thread_id,uid] = e.cycle
        if e.dst_reg_uid is not None and e.dst_reg_uid >= 0:
            last[e.kernel_uid,e.thread_id,e.dst_reg_uid] = e.cycle
    facts.update(status='structural_counter_certificates', structural_loops=len(loops), effects=len(effects),
        due_bit_intervals=sum(bin(e.due).count('1') for e in effects), cycle_limit=protocol['cycle_limit'],
        construction_seconds=time.perf_counter()-start,
        proof='unconditional modular update;single counter exit;fixed dependent-update lower bound',
        unsupported_loop_policy='unchanged_generic_model_no_new_Unknown')
    return effects, facts
