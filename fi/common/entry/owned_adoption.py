"""Read-only, one-owner GELU RF adoption; never execute or re-time a method.

The externally SHA-pinned provenance JSON lives at the condition root. All
roles and complete old job trees are regular condition-relative members.
This consumer deliberately has no arbitrary source/version allowlist and no
ELF-omission exception: a later public packer must preserve this exact closure
or introduce a separately reviewed portable proof, not weaken this reader.
"""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

OLD_SOURCE = '1cd7cd5c424b45180ce18f4adb4c995d38547564be79ac9b6a7a86d28d4d223e'
NEW_SOURCE = '5b95804546679f169fbc06e4ca6e9bccb70820128ef565dae6b4372477b43d6d'
NATIVE_SHA = 'e306a1ee85eda5fa42888f20224133eb30170da753e3a3bcf82d75ad88918f10'
IMAGE = 'sha256:6f88c35052e8db66eb00c44700c180c57c69fdcd4569578e5730582ee93c54be'
OLD_ADAPTER = '64ab4d5c4f464edc5c8b72cc0cbeb9c5aa137bdd37be489c9b98930c221ea9d7'
OLD_HOST = '7789120150fc958d743c051b80dad73d2c204f6d5ce0d66c6a7b3d921f3394a6'
OLD_TERMINAL_SHA = 'c12c8d49122732a48db749d5e0ff1b351957df49233ad4b55e0358ba9226ef97'
OLD_GUARD_SHA = '370873991604f3df5a3bbbb3b2064e14a66ba7bf63742ee3316721b95d3c09e8'
MASTER_SHA = '119dacfc9b1c55a215016a3309582f811302e4e51e033e2dee93bf9f2bc50d16'
PACKET_SHA = '57bc36a1b7214f8d2c85c78b5972d7a7c2476d33e6fa3ebec3f432ac59c204e9'
INPUT_FP = '78870df742196869d4ac7ea0c297c984cb3f81804b5f0213be12fe2e48d2f845'
POPULATION_FP = 'c39e6baad943a5050f75c98c1691ae0d739be07b5a3e97111ec8bd460b3b46bd'
PREPARED_SHA = 'b0e3e617eb07345027020fd16eea52e3c39e04f3f979c6853e53544cb9d0c73a'
EXECUTION = {
 'script/common/outcome_oracle.py':'1c27623c3abc84de7496e8a14097ad990e6966220213db1ad6f6124e4a8b0ee9',
 'script/execution/batch_fi.py':'02b38b826b7aa203923deadc438527a6e28d3829b01202004c8a834c81f600c0',
 'script/execution/batch_workload.py':'5d204700f4573eebad6916eb167fd4dca9a83ce0d045c12ea7c9a3b83e22bc0b',
 'script/execution/fi_campaign.py':'df467d55d8ec8fad027b94a6dd5b30984dc98f1b94f4bef616ff8f43b8f997a0'}
CHANGES = {
 'script/core/batch_backward.py':('d511e2222b50a8b913c80ef1a918dba0d015b95c1858fe75e23cf8fd6425823c','3541fa93f271eff0684463f725a80bc5a4978160c34b70477e8d3d4dd50f210e'),
 'script/core/ptx_s32_divrem_semantics.py':('856550be9853778c4972035254c53ac4bf76518acd7bd5e0205689bae6d47271','3271754623f30efff6368b772072bcdcf92018a2dae05673f8b5fde32dd8b85b'),
 'script/core/reg_observed_analyzer.py':('cc162632270d11ee26c51f7fc75784a19551757b470c0f2bff39c28885796f47','855682ed2df2aa5e3bacb993c2fd1d53d667234c6f1ad4068729c3cb6333439f'),
 'script/execution/sara_batch_campaign.py':('442e55557a8d32ef8e4a6f9302f489f53e4ea48d66f225b83d6d016663cb6298','10f9204824dcbe22269f4bdd5fc197aa0be0d7e3c3a205d71dd1cfc3c8745aba')}
SCOPE = dict(application='GELU', architecture='SM75', component='rf', draw_range=[0,1000])


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def hex64(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}',value) is not None


def regular(path):
    path = Path(path)
    require(path == path.resolve(strict=True) and not path.is_symlink()
            and stat.S_ISREG(path.lstat().st_mode), 'canonical regular evidence required: '+str(path))
    return path


def relative(root, name):
    require(isinstance(name,str) and '\\' not in name and name,
            'nonempty portable POSIX evidence path required')
    value = PurePosixPath(name)
    require(not value.is_absolute() and str(value) == name
            and all(part not in ('','.','..') for part in value.parts), 'unsafe evidence path')
    path = root.joinpath(*value.parts)
    require(path.resolve(strict=True) == path and root in path.parents,
            'evidence path escapes its exact condition root')
    return path


def read(path):
    return json.loads(regular(path).read_text())


def map_identity(files):
    return hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()


class OwnedAdoption:
    def __init__(self,path,expected_sha,*,code_root=Path('/code')):
        self.path = regular(Path(path).absolute())
        require(hex64(expected_sha) and digest(self.path) == expected_sha,
                'owned provenance exact external SHA required')
        self.sha256, self.root = expected_sha, self.path.parent
        self.value = read(self.path)
        p = self.value
        require(p.get('schema') == 'sara-GELU-source08-owned-method-adoption-v1'
                and p.get('status') == 'complete' and p.get('scope') == SCOPE
                and p.get('original_source_id') == OLD_SOURCE and p.get('current_source_id') == NEW_SOURCE
                and p.get('native_manifest_sha256') == NATIVE_SHA and p.get('image') == IMAGE
                and p.get('old_clocks_modified') is False and p.get('old_jobs_executed_again') is False
                and p.get('failed_rates_scientific_inputs_reused') is False,
                'only exact GELU SM75 original RF first-1K adoption is allowed')
        require(set(p.get('trees',{})) == {'FI','GEREM'}, 'only two completed method trees may be adopted')
        self.files, self.trees = {}, {}
        require(isinstance(p.get('files'),dict) and p['files'], 'explicit evidence file bindings required')
        for name,item in p['files'].items():
            self.files[name] = self._file(name,item)
        for method,item in p['trees'].items():
            require(item.get('path') == '00001000/'+method and isinstance(item.get('members'),dict)
                    and item['members'], 'old method tree must retain canonical first-prefix path')
            root = relative(self.root,item['path'])
            self._tree(root,item['members'])
            self.trees[method] = root
        roles = p.get('roles',{})
        required = {'old_source_files','new_source_files','native_manifest','old_prepared',
                    'compatibility','old_failed_terminal','old_failed_guard','old_FI_adapter',
                    'full_master','dispatch_packet','failed_rates_partial','failed_rates_resource',
                    'failed_rates_container','failed_rates_request'}
        require(set(roles) == required and all(name in self.files for name in roles.values()),
                'complete named adoption/failed-attempt evidence roles required')
        self.roles = {role:self.files[name] for role,name in roles.items()}
        old,new = read(self.roles['old_source_files']),read(self.roles['new_source_files'])
        require(isinstance(old,dict) and isinstance(new,dict) and len(old) == len(new) == 850
                and set(old) == set(new) and map_identity(old) == OLD_SOURCE and map_identity(new) == NEW_SOURCE,
                'exact original and current 850-file maps required')
        require({name:(old[name],new[name]) for name in old if old[name] != new[name]} == CHANGES,
                'source difference is not the fixed four-file REM/model-identity repair')
        from script.execution.experiment import scientific_files
        require(scientific_files(code_root) == new, 'actual /code is not complete source08 candidate02')
        native = read(self.roles['native_manifest'])
        require(digest(self.roles['native_manifest']) == NATIVE_SHA and native
                and all(old.get(k) == v == new.get(k) for k,v in native.items()),
                'native03 compiled execution closure changed')
        require(all(old.get(k) == v == new.get(k) for k,v in EXECUTION.items())
                and digest(self.roles['old_FI_adapter']) == OLD_ADAPTER,
                'original FI algorithm/oracle or old adapter changed')
        for name in ('script/execution/batch_method_run.py','script/execution/batch_gerem.py',
                     'script/execution/ge_batch_experiment.py','script/execution/method_performance.py',
                     'script/execution/method_input_context.py'):
            require(old.get(name) and old[name] == new[name], 'GEREM execution/collection closure changed')
        require(digest(self.roles['full_master']) == MASTER_SHA
                and digest(self.roles['dispatch_packet']) == PACKET_SHA
                and digest(self.roles['old_prepared']) == PREPARED_SHA,
                'retained master/packet/prepared bytes changed')
        prepared = read(self.roles['old_prepared'])
        require(prepared.get('source_id') == OLD_SOURCE and prepared.get('status') == 'complete'
                and prepared.get('application') == 'Gelu' and prepared.get('architecture') == 'SM75'
                and prepared.get('groups',{}).get('rf',{}).get('master_sha256') == MASTER_SHA
                and prepared['groups']['rf'].get('dispatch_inputs_sha256') == PACKET_SHA,
                'retained preparation belongs to another case/master')
        compat = read(self.roles['compatibility'])
        require(compat.get('schema') == 'sara-GELU-source08-retained-input-compatibility-v1'
                and compat.get('status') == 'complete' and compat.get('scope') == SCOPE
                and compat.get('original_source_id') == OLD_SOURCE and compat.get('current_source_id') == NEW_SOURCE
                and compat.get('old_prepared_sha256') == PREPARED_SHA
                and compat.get('native_manifest_sha256') == NATIVE_SHA and compat.get('image') == IMAGE
                and compat.get('source_changes') == {k:list(v) for k,v in CHANGES.items()}
                and all(compat.get(k) is True for k in ('FI_execution_closure_unchanged',
                    'GEREM_execution_closure_unchanged','native_compiled_subset_unchanged','prepared_inputs_unchanged'))
                and compat.get('new_scientific_execution') is False,
                'separate source08 compatibility receipt is incomplete')
        self._failed_origin()
        self._completed_jobs()
        self._failed_cost()
        self.verify_unchanged()

    def _file(self,name,item):
        path = regular(relative(self.root,name))
        require(isinstance(item,dict) and type(item.get('bytes')) is int and item['bytes'] >= 0
                and hex64(item.get('sha256')) and path.stat().st_size == item['bytes']
                and digest(path) == item['sha256'], 'owned evidence size/SHA differs: '+name)
        return path

    def _tree(self,root,members):
        require(root.is_dir() and not root.is_symlink(), 'regular old job directory required')
        actual = set()
        for directory,dirs,names in os.walk(root,followlinks=False):
            for name in dirs:
                require(not (Path(directory)/name).is_symlink(), 'symlink in old job tree')
            for name in names:
                path = regular(Path(directory)/name)
                rel = path.relative_to(root).as_posix()
                actual.add(rel)
                require(rel in members, 'undeclared old job member: '+rel)
                item = members[rel]
                require(type(item.get('bytes')) is int and path.stat().st_size == item['bytes']
                        and hex64(item.get('sha256')) and digest(path) == item['sha256'],
                        'old job member bytes changed: '+rel)
        require(actual == set(members), 'missing original old-job member')

    def _failed_origin(self):
        terminal,guard = read(self.roles['old_failed_terminal']),read(self.roles['old_failed_guard'])
        scope = guard.get('scope',{})
        require(digest(self.roles['old_failed_terminal']) == OLD_TERMINAL_SHA
                and digest(self.roles['old_failed_guard']) == OLD_GUARD_SHA
                and terminal.get('schema') == 'sara-original14-prefix-controller-v1'
                and terminal.get('status') == 'failed_evidence_preserved'
                and terminal.get('application') == 'GELU' and terminal.get('budget') == 1000
                and terminal.get('phase') == 'run' and terminal.get('source_id') == OLD_SOURCE
                and terminal.get('image') == IMAGE and terminal.get('administrative_entry_sha256') == OLD_HOST
                and terminal.get('adapter_files',{}).get('prefix_fi.py') == OLD_ADAPTER
                and terminal.get('next_dispatch') is None
                and guard.get('schema') == 'sara-kernel-storage-guard-v1'
                and guard.get('status') == 'failed_evidence_preserved'
                and guard.get('child_exit_status') == 1 and guard.get('monitor_exit_status') == 0
                and guard.get('child_PID') == terminal.get('PID')
                and scope.get('application') == 'GELU' and scope.get('budget') == 1000
                and scope.get('phase') == 'original14_run' and scope.get('source_id') == OLD_SOURCE
                and scope.get('entry_sha256') == OLD_HOST and scope.get('image') == IMAGE
                and len(guard.get('failures',[])) == 1
                and guard['failures'][0].get('reason') == 'scientific_child_incomplete; not_an_application_DUE'
                and guard['failures'][0].get('kernel_line') is None,
                'old failed source07 provenance is not the preserved REM failure')

    def _completed_jobs(self):
        for method,root in self.trees.items():
            request = read(root/'request.json')
            require(request.get('source') == OLD_SOURCE and request.get('image') == IMAGE,
                    'adopted Runner request owner differs')
            attempts = sorted(root.glob('attempt-*'))
            require(len(attempts) == 1 and attempts[0].name == 'attempt-0001',
                    'only original single complete attempt may be adopted')
            resource,container = read(attempts[0]/'job-resource.json'),read(attempts[0]/'container.json')
            host = container.get('HostConfig',{})
            require(resource.get('exit_status') == resource.get('child_exit_status') == 0
                    and resource.get('completion_resources_verified') is True
                    and resource.get('limits_verified') is True and resource.get('window_interrupted') is False
                    and resource.get('interrupted_signals') == []
                    and host.get('Runtime') == 'runc' and host.get('NanoCpus') == 64000000000
                    and host.get('Memory') == host.get('MemorySwap') == 448*1024**3
                    and not host.get('DeviceRequests') and container.get('Image') == IMAGE
                    and container.get('State',{}).get('OOMKilled') is False
                    and container['State'].get('ExitCode') == 0 and container['State'].get('Running') is False,
                    'adopted old method lacks complete bounded actual execution')
            require(request.get('argv') == resource.get('command'), 'old request and executed command differ')
        fi = read(self.trees['FI']/'output/path/fi/campaign.json')
        pref,spec = fi.get('prefix',{}),fi.get('spec',{})
        require(pref.get('source_id') == OLD_SOURCE and pref.get('adapter_sha256') == OLD_ADAPTER
                and pref.get('range') == [0,1000] and pref.get('preceding_seals') == []
                and pref.get('application') == 'GELU' and pref.get('architecture') == 'SM75'
                and pref.get('component') == 'rf' and pref.get('native_manifest_sha256') == NATIVE_SHA
                and pref.get('parent_master_sha256') == MASTER_SHA
                and fi.get('dispatch_inputs_sha256') == PACKET_SHA and fi.get('performance_measurement') is True
                and spec.get('execution_code') == EXECUTION and spec.get('input_fingerprint') == INPUT_FP
                and spec.get('population_fingerprint') == POPULATION_FP,
                'old FI execution closure/spec/master differ')
        seal = read(self.trees['FI']/'output/path/fi/fi_completion.json')
        require(seal.get('status') == 'complete' and seal.get('aggregate') ==
                read(self.trees['FI']/'output/path/fi/aggregate.json'), 'old FI seal incomplete')
        from script.execution import fair_comparison_report as report
        from script.execution.campaign import fingerprint
        from script.execution.validation_records import read_chunks
        complete_fi = report.load_fi(self.trees['FI']/'output/path/fi')
        trials = read(self.roles['full_master']).get('trials',[])
        require(len(trials) == 10000 and [complete_fi['trials'][tid] for tid in complete_fi['ordered']]
                == trials[:1000], 'old FI evidence does not contain the exact first 1K master draws')
        g = read(self.trees['GEREM']/'output/path/end-to-end.json')
        require(g.get('method') == 'gerem' and g.get('component') == 'rf'
                and g.get('own_population_and_collection') is True and g.get('borrowed_collection_inputs') is False
                and g.get('FI_answers_read') is False and g.get('headline_performance_receipt') == 'performance-window.json'
                and g.get('stages',{}).get('collection',{}).get('exit_status') == 0
                and g['stages']['collection'].get('interruption') is None,
                'old GEREM own collection did not complete')
        gpath = self.trees['GEREM']/'output/path'
        ga,gi,gw = read(gpath/'aggregate.json'),read(gpath/'validation-state/index.json'),read(gpath/'performance-window.json')
        ident = ga.get('identity',{})
        require(ga.get('schema') == 'sara-gerem-probability-aggregate-v1'
                and ga.get('method') == 'GEREM' and ga.get('component') == 'rf'
                and ga.get('planned') == ga.get('completed') == ga.get('denominator') == 1000
                and ga.get('hard_label_generated') is False and ga.get('FI_answers_read') is False
                and ident.get('manifest_sha256') == MASTER_SHA
                and ident.get('master_population_fingerprint') == POPULATION_FP
                and ident.get('native_source_fingerprint') == '99855aaeb178ee50c55c6b0c984ce2db9be15a93b5c90629260e659f276796cc'
                and gi.get('identity') == ident and gi.get('validation_only') is True
                and gw.get('schema') == 'sara-method-performance-window-v1'
                and gw.get('method') == 'GEREM' and gw.get('component') == 'rf'
                and gw.get('complete') is True and gw.get('partial') is False
                and gw.get('aggregate_fsynced') is True and gw.get('aggregate_file') == 'aggregate.json'
                and gw.get('wall_seconds') == g.get('wall_seconds'),
                'old GEREM aggregate/own input/native/point export/window is not complete')
        points = list(read_chunks(gpath/'validation-state/index.json'))
        require(len(points) == 1000, 'old GEREM export lost original draws')
        seen = set()
        by_id = {trial['trial_id']:trial for trial in trials[:1000]}
        for point in points:
            trial = by_id.get(point.get('trial_id'))
            require(trial is not None and point['trial_id'] not in seen and point.get('status') == 'complete'
                    and point.get('site_id') == trial['site_id']
                    and point.get('manifest_fingerprint') == fingerprint(trial)
                    and point.get('hard_label_generated') is False
                    and point.get('independent_DUE_probability') is None
                    and type(point.get('unknown_mass')) is int and point['unknown_mass'] in (0,1),
                    'old GEREM point identity or original probability semantics differ')
            probability = point.get('p_sdc')
            require(probability is None if point['unknown_mass'] else
                    type(probability) in (int,float) and math.isfinite(probability) and 0 <= probability <= 1,
                    'old GEREM Unknown/probability is invalid')
            seen.add(point['trial_id'])
        self.fi_identity = fi

    def _failed_cost(self):
        row = read(self.roles['failed_rates_partial'])
        resource,container = read(self.roles['failed_rates_resource']),read(self.roles['failed_rates_container'])
        request = read(self.roles['failed_rates_request'])
        host = container.get('HostConfig',{})
        require(row.get('schema') == 'sara-method-performance-window-v1'
                and row.get('method') == 'SARA-rates' and row.get('component') == 'rf'
                and row.get('performance_measurement') is True and row.get('partial') is True
                and row.get('complete') is False and row.get('paired_query_included') is False
                and row.get('validation_export_included') is False
                and row.get('reason') == 'Unsupported opcode with observed/due/trace destination bits: thread_id=32, pc=0x00000068, event_index=3165, opcode=rem.s32, canonical_op=REM.S32'
                and request.get('source') == OLD_SOURCE and request.get('image') == IMAGE
                and request.get('argv') == resource.get('command')
                and request.get('argv',[])[:5] == ['python3','-m','script.execution.batch_method_run','--method','rates']
                and resource.get('child_exit_status') == 1 and resource.get('window_interrupted') is False
                and container.get('Image') == IMAGE and host.get('Runtime') == 'runc'
                and host.get('NanoCpus') == 64000000000 and host.get('Memory') == host.get('MemorySwap') == 448*1024**3
                and not host.get('DeviceRequests') and container.get('State',{}).get('OOMKilled') is False,
                'failed07 rates cost must remain actual incomplete infrastructure work')
        for key in ('wall_seconds','cpu_user_seconds','cpu_system_seconds'):
            require(type(row.get(key)) in (int,float) and math.isfinite(row[key]) and row[key] >= 0,
                    'missing reliable failed-attempt cost: '+key)
        self.failed_rates = row

    def owner(self,directory):
        directory = Path(directory).resolve(strict=True)
        for method,root in self.trees.items():
            if directory == root:
                return OLD_SOURCE
        return NEW_SOURCE

    def fi_owner(self,root,begin,end,*,untimed=False):
        old = Path(root).resolve(strict=True) == self.trees['FI']/'output/path/fi'
        if old:
            require(not untimed and [begin,end] == [0,1000], 'adoption never applies to another FI range/cohort')
            return OLD_SOURCE,OLD_ADAPTER
        return NEW_SOURCE,None

    def bind_master(self,path):
        require(digest(regular(path)) == MASTER_SHA, 'owned condition cannot adopt another master')

    def verify_unchanged(self):
        require(digest(self.path) == self.sha256, 'provenance changed while reading')
        for name,item in self.value['files'].items():
            self._file(name,item)
        for method,item in self.value['trees'].items():
            self._tree(self.trees[method],item['members'])

    def summary(self):
        return dict(schema=self.value['schema'],provenance_sha256=self.sha256,scope=SCOPE,
            original_source_id=OLD_SOURCE,current_source_id=NEW_SOURCE,
            adopted_methods=['FI','GEREM'],adopted_range=[0,1000],old_FI_adapter_sha256=OLD_ADAPTER,
            native_manifest_sha256=NATIVE_SHA,image=IMAGE,
            original_clocks_retained=True,old_jobs_executed_again=False,
            failed07_rates_scientific_inputs_reused=False,
            original_failed_terminal_sha256=digest(self.roles['old_failed_terminal']),
            original_failed_guard_sha256=digest(self.roles['old_failed_guard']),
            prepared07_sha256=PREPARED_SHA,compatibility_sha256=digest(self.roles['compatibility']))


def load_owned(path,expected_sha,*,code_root=Path('/code')):
    require((path is None) == (expected_sha is None), 'owned provenance path/SHA must be supplied together')
    return None if path is None else OwnedAdoption(path,expected_sha,code_root=code_root)
