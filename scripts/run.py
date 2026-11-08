"""Bounded CPU-only workflows using the distributed collectors and predictors."""
import argparse,hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def write(path,value):
    if path.exists():raise FileExistsError(path)
    path.write_text(json.dumps(value,indent=2)+'\n')
def pin(path,read_path):
    return dict(path=read_path,bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--method',choices=('sara','gerem','population','fi'),required=True)
    p.add_argument('--application',default='GEMM');p.add_argument('--architecture',choices=('SM75','SM86'),default='SM75')
    p.add_argument('--budget',type=int,choices=(1000,5000,10000,200000),default=10000)
    p.add_argument('--component',choices=('rf','smem','l1d','l2'),default='rf')
    p.add_argument('--masters',type=Path,help='completed canonical population directory')
    p.add_argument('--image',default='sara:local');p.add_argument('--cpus',type=int,default=4)
    p.add_argument('--memory-gib',type=int,default=8);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.cpus<1 or a.memory_gib<1:p.error('Positive integer resource limits are required')
    if a.method=='fi' and a.budget==200000:p.error('The supported FI budgets are 1K, 5K and 10K')
    if a.method in ('fi','gerem') and not a.masters:p.error('Generate the canonical population first and pass --masters')
    rows=json.loads((ROOT/'benchmarks/registry.json').read_text())['groups']
    rows=[r for r in rows if r['application']==a.application and r['architecture']==a.architecture]
    if len(rows)!=1:p.error('Choose a registered application and architecture')
    row=rows[0];out=a.output.resolve()
    if out.exists():p.error('Output must be a fresh directory')
    out.parent.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(out.parent).free<2*1024**3:p.error('Less than 2 GiB free; do not start the small workflow')
    out.mkdir();(out/'build').mkdir();(out/'prepared').mkdir()
    image=json.loads(subprocess.check_output(['docker','image','inspect',a.image],text=True))[0]['Id']
    base=['docker','run','--rm','--runtime=runc','--network=none','--cpus='+str(a.cpus),
        '--memory='+str(a.memory_gib)+'g','--memory-swap='+str(a.memory_gib)+'g',
        '-e','NVIDIA_VISIBLE_DEVICES=void','-e','NVIDIA_DRIVER_CAPABILITIES=','-e','SARA_IMAGE_ID='+image]
    def bind(source,target,readonly=False):
        source=Path(source).resolve()
        if ',' in str(source):raise ValueError('A comma in a bind path is unsupported')
        return ['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly' if readonly else '')]
    def run(label,command,mounts,code='sara/serial',extra=None):
        cmd=base+bind(ROOT/code,'/code',True)+bind(ROOT/'benchmarks/apps','/code/test_apps',True)
        cmd+=bind(ROOT/'configs','/configs',True)
        for source,target,readonly in mounts:cmd+=bind(source,target,readonly)
        if extra:cmd+=extra
        cmd += [a.image]+command
        start=time.monotonic()
        with (out/(label+'.log')).open('w') as log:status=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT).returncode
        write(out/(label+'-execution.json'),dict(exit_status=status,seconds=time.monotonic()-start,image=image))
        if status:raise RuntimeError(label+' failed; partial output is retained; see '+str(out/(label+'.log')))
    # Compilation is deliberately outside the method workflow clock.
    run('build',['python3','-B','/opt/sara/scripts/build_benchmarks.py','--app',row['source_directory'],
        '--architecture',a.architecture.lower(),'--output','/build/bin'],[(out/'build','/build',False)])
    common=[(out/'build/bin','/binaries',True),(out/'prepared','/prepared',False)]
    start=time.monotonic()
    if a.method in ('population','fi'):
        methodout=out/'result';methodout.mkdir()
        mounts=common+[(methodout,'/out',False)]
        if a.masters:mounts.append((a.masters,'/masters',True))
        code='sara/serial'
        if a.method=='fi':
            routes=json.loads((ROOT/'fi/route-map.json').read_text())
            admitted=[r for r in routes.get('conditions',[]) if r.get('application')==a.application and r.get('architecture')==a.architecture and r.get('component')==a.component]
            route=admitted[0]['first'] if len(admitted)==1 else 'main'
            code=out/'fi-source'
            subprocess.run([sys.executable,str(ROOT/'fi/materialize.py'),'--route',route,'--output',str(code)],check=True)
        run(a.method,['python3','-B','/opt/sara/scripts/collect_and_inject.py',
            '--operation',a.method,'--case',row['case'],'--architecture',a.architecture,
            '--binary','/binaries/'+row['source_directory'],'--component',a.component,'--budget',str(a.budget)],mounts,code=code)
    else:
        group=dict(group_id=row['group_id'],application=row['application'],architecture=row['architecture'],components=[])
        for c in row['components']:
            entry=dict(component=c)
            if a.method=='gerem':
                entry['master']=pin(a.masters.resolve()/c/'manifest.json','/masters/'+c+'/manifest.json')
            group['components'].append(entry)
        request=dict(group=group,method=a.method,budget=a.budget,case=row['case'],
            binary='/binaries/'+row['source_directory'],configuration='/configs/'+a.architecture.lower()+'/gpgpusim.config',
            fresh_input_root='/prepared/input',package_search_roots=['/code/script'])
        write(out/'request.json',request);checksum=hashlib.sha256((out/'request.json').read_bytes()).hexdigest()
        for stage in ('produce','consume'):
            target=out/stage;target.mkdir()
            mounts=[(out/'build/bin','/binaries',True),(out/'request.json','/request.json',True),
                (out/'prepared','/prepared',stage=='consume'),(target,'/out',False)]
            if a.masters:mounts.append((a.masters,'/masters',True))
            run(stage,['python3','-B','/opt/sara/scripts/workflow_worker.py','--stage',stage,
                '--request-sha256',checksum],mounts,code='gerem' if a.method=='gerem' else 'sara/serial')
    write(out/'complete.json',dict(status='complete',method=a.method,application=a.application,architecture=a.architecture,
        budget=None if a.method=='sara' else a.budget,image=image,active_workflow_seconds=time.monotonic()-start,
        compilation_excluded=True,resource_profile=dict(cpus=a.cpus,memory_gib=a.memory_gib,swap_gib=0),
        scope='consecutive method containers including launch, preparation, prediction and required persistence'))
    print(json.dumps(dict(status='complete',output=str(out))))
if __name__=='__main__':main()
