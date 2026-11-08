"""Canonical populations and the retained FI dispatcher, without prediction changes."""
import argparse,hashlib,json,os,shutil,sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
sys.path[:0]=['/code','/code/script/common','/code/script/core']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operation',choices=('population','fi'),required=True)
    p.add_argument('--case',required=True);p.add_argument('--architecture',choices=('SM75','SM86'),required=True)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--component',required=True)
    p.add_argument('--budget',type=int,required=True);a=p.parse_args()
    from script.execution.policy import require_container_execution
    from script.execution import ge_batch_experiment as collector
    from script.execution.campaign import atomic_json
    from script.execution.fault_manifest import FaultPopulation
    from script.execution.batch_workload import contract
    profile=require_container_execution()
    config=Path('/configs')/a.architecture.lower()/'gpgpusim.config'
    workload=contract(a.case)
    if a.operation=='population':
        registry=json.loads(Path('/opt/sara/benchmarks/registry.json').read_bytes())['groups']
        selected=[r for r in registry if r['case']==a.case and r['architecture']==a.architecture]
        if len(selected)!=1:raise ValueError('One registered workload is required')
        cachecap=None
        for c in selected[0]['components']:
            root=Path('/out')/c;root.mkdir();capture=root/'capture'
            cache=c in ('l1d','l2')
            if cache and cachecap:
                shutil.copytree(cachecap,capture)
            else:
                args=SimpleNamespace(case=a.case,output=capture,base_config=config,simulator_root=Path('/native'),
                    executable=a.binary,component=c,minimal_population=False,cache_state=cache,
                    collection='cache-population' if cache else 'population',cache_profile='changes',
                    validate_cpu=False,defer_diagnostics=False,timeout=7200)
                collector.capture(args)
                if cache:cachecap=capture
            args=SimpleNamespace(capture=capture,no_manifest=True,population_only=True,component=None if cache else c)
            (collector.prepare_cache if cache else collector.prepare_smem if c=='smem' else collector.prepare_rf)(args)
            inventory=json.loads((capture/('inventory-'+c+'.json')).read_bytes())
            population=FaultPopulation(inventory)
            atomic_json(root/'inventory.json',inventory)
            manifest=population.sample(10000,2026,'matched-'+workload['app']+'-'+c)
            atomic_json(root/'manifest.json',manifest)
        atomic_json(Path('/out/complete.json'),dict(status='complete',seed=2026,draws_per_condition=10000,
            sampling='with_replacement',source_of_truth='component inventory and its canonical fingerprint'))
    else:
        # A fresh full campaign uses the same dispatch core; historical append
        # adapters remain available separately for their recorded routes.
        from script.execution.batch_fi import main as dispatch
        c=a.component;root=Path('/masters')/c
        dispatch(['--capture',str(root/'capture'),'--simulator-root','/native','--component',c,
            '--site-manifest',str(root/'manifest.json'),'--seed','2026','--campaign-id',c+'-'+str(a.budget),
            '--target-count',str(a.budget),'--output','/out','--jobs',str(profile.cpus),
            '--watchdog-factor','10','--timeout','300'])
if __name__=='__main__':main()
