"""Exact native RF membership and trace-local printed-name noninterference.

No alpha renaming, prediction, fault replay, Unknown overlay or population
filtering occurs here. A printed name may denote multiple physical UIDs only
when its observed use history admits the existing name-keyed local core. A UID
transition requires an active complete physical-width write; later reads must
use that current UID. This is a golden-trace/model admission proof, not a proof
for all alternative faulted executions or changed control paths.
"""
POLICY = 'native-RF-UID-primary-and-trace-local-name-noninterference-v1'
IDENTITY_CORRECTIONS = (
    'RF_projection_UID_primary_with_printed_name_crosscheck',
    'input_register_name_noninterference_guard',
)


def need(value, message):
    if not value:
        raise ValueError(message)


def build_rf_identity_index(inventory):
    members, by_name, widths = {}, {}, {}
    for span in inventory['spans']:
        need(span['component'] == 'rf', 'RF identity index received another component')
        target = span['target']
        key = target['kernel'], target['thread'], target['register_uid']
        name = target['register']
        need(type(key[2]) is int and key[2] >= 0 and isinstance(name, str) and name,
             'Actual native physical RF UID/name required')
        previous = members.setdefault(key, name)
        need(previous == name, 'One physical RF UID has contradictory allocated names')
        by_name.setdefault((key[0], key[1], name), set()).add(key[2])
        width = target.get('width_bits')
        need(type(width) is int and 1 <= width <= 64, 'Actual RF physical width required')
        previous_width = widths.setdefault(key, width)
        need(previous_width == width, 'One physical RF UID has contradictory widths')
    return dict(members=members, by_name=by_name, widths=widths)


def actual_writes(event):
    if event.pred is not None and not event.pred.val:
        return ()
    if getattr(event, 'shuffle44', None) is not None:
        from script.core.ptx_shuffle_down import destination_writes
        return tuple((name, uid, mask, row['width_bits']) for (name, uid, mask), row in
                     zip(destination_writes(event), event.shuffle44['destinations']))
    if event.dst_reg is None:
        return ()
    return ((event.dst_reg, event.dst_reg_uid, event.dst_write_mask, event.width_bits),)


def validate_input_register_name_noninterference(events, rf_inventory=None):
    """A complete-input identity/width preflight and chronological admission.

    Only ambiguous printed names need the chronological binding proof. For
    them actual RF inventory is required to establish physical widths. The
    maximum source/write/implicit-destination width over this complete input
    is also checked; event instruction width alone is not physical authority.
    """
    name_uids, observed_widths = {}, {}
    for event in events:
        owner = event.kernel_uid, event.thread_id
        references = []
        if event.pred is not None:
            references.append(('pred', 0, event.pred.reg, event.pred.uid, 1))
        active = event.pred is None or bool(event.pred.val)
        if active:
            references.extend(('src', role, name, uid, event.src_width_bits[role])
                for role, (name, uid) in enumerate(zip(event.src_regs, event.src_reg_uids)))
        elif event.dst_reg is not None:
            # The existing core uses this physical old destination to evaluate
            # predicate-flip effects. Observe its identity, not a data access
            # or a write; the observation does not change an established UID.
            references.append(('pred_off_destination', -1, event.dst_reg,
                               event.dst_reg_uid, event.width_bits))
        writes = actual_writes(event)
        for _kind, _role, name, uid, width in references:
            if type(uid) is int and uid >= 0:
                key = owner + (name,)
                name_uids.setdefault(key, set()).add(uid)
                observed_widths[owner + (uid,)] = max(observed_widths.get(owner + (uid,), 0), int(width))
        for name, uid, _mask, width in writes:
            if type(uid) is int and uid >= 0:
                name_uids.setdefault(owner + (name,), set()).add(uid)
                observed_widths[owner + (uid,)] = max(observed_widths.get(owner + (uid,), 0), int(width))
    ambiguous = {key for key, uids in name_uids.items() if len(uids) > 1}
    proof = dict(status='PASS', policy=POLICY, events_checked=len(events),
        ambiguous_name_bindings=len(ambiguous), checked_reads=0, checked_writes=0,
        UID_full_write_switches=0, first_identity_observation_established_bindings=0,
        predicated_off_destination_identity_observations=0,
        maximum_observed_widths_from_complete_input=True,
        physical_width_authority='not_needed_for_unambiguous_names',
        primary_and_secondary_writes_checked=True,
        predicate_reads_and_active_data_reads_checked=True,
        predicated_off_data_reads_or_writes_counted=False,
        all_admitted_UID_transitions_use_full_physical_width_writes=True,
        core_numeric_rules_changed=False, alpha_renaming_used=False, Unknown_wrapper_used=False,
        proof_scope='this_complete_golden_input_under_existing_local_model;not_all_faulted_executions')
    if not ambiguous:
        return proof
    need(rf_inventory is not None, 'Ambiguous printed register names require actual RF physical-width authority')
    index = build_rf_identity_index(rf_inventory)
    physical = index['widths']
    for key in ambiguous:
        kernel, thread, name = key
        for uid in name_uids[key]:
            owner_uid = kernel, thread, uid
            need(index['members'].get(owner_uid) == name,
                 'Ambiguous input UID/name is absent from actual RF population')
            need(observed_widths[owner_uid] <= physical[owner_uid],
                 'Observed input width exceeds actual physical RF width')
    proof['physical_width_authority'] = 'actual_RF_inventory_with_complete_input_width_crosscheck'
    current = {}
    for event in events:
        owner = event.kernel_uid, event.thread_id
        references = []
        if event.pred is not None:
            references.append(('pred', 0, event.pred.reg, event.pred.uid))
        if event.pred is None or event.pred.val:
            references.extend(('src', role, name, uid) for role, (name, uid) in
                              enumerate(zip(event.src_regs, event.src_reg_uids)))
        elif event.dst_reg is not None:
            references.append(('pred_off_destination', -1, event.dst_reg, event.dst_reg_uid))
        for kind, role, name, uid in references:
            key = owner + (name,)
            if key not in ambiguous or type(uid) is not int or uid < 0:
                continue
            previous = current.get(key)
            if previous is None:
                current[key] = dict(UID=uid, index=event.index, write=False)
                proof['first_identity_observation_established_bindings'] += 1
            elif previous['UID'] != uid:
                raise ValueError('Input name noninterference failed: old/different UID identity observation ' +
                    repr(dict(kernel=owner[0], thread=owner[1], register=name, read_UID=uid,
                        event_index=event.index, pc=event.pc, read_kind=kind, src_index=role,
                        current_binding=previous)))
            if kind == 'pred_off_destination':
                proof['predicated_off_destination_identity_observations'] += 1
            else:
                proof['checked_reads'] += 1
        for name, uid, mask, _event_width in actual_writes(event):
            key = owner + (name,)
            if key not in ambiguous or type(uid) is not int or uid < 0:
                continue
            previous = current.get(key)
            if previous is not None and previous['UID'] != uid:
                width = physical[owner + (uid,)]
                need(type(mask) is int and mask >= 0
                     and mask & ((1 << width) - 1) == (1 << width) - 1,
                     'Input name noninterference failed: partial cross-UID write ' +
                     repr(dict(kernel=owner[0], thread=owner[1], register=name, new_UID=uid,
                         event_index=event.index, pc=event.pc, physical_width=width,
                         write_mask=mask, current_binding=previous)))
                proof['UID_full_write_switches'] += 1
            current[key] = dict(UID=uid, index=event.index, write=True)
            proof['checked_writes'] += 1
    return proof
