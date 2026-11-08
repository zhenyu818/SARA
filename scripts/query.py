"""Export current grouped SARA predictions for an immutable sampled prefix."""
import argparse,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared',type=Path,required=True,help='prepared directory of a completed grouped SARA run')
    p.add_argument('--masters',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--budget',type=int,choices=(1000,5000,10000),default=10000)
    p.add_argument('--method',choices=('sara','gerem'),default='sara')
    p.add_argument('--image',default='sara:local');p.add_argument('--cpus',type=int,default=4);p.add_argument('--memory-gib',type=int,default=8)
    a=p.parse_args()
    if a.output.exists():p.error('Output must be fresh')
    a.output.mkdir(parents=True)
    cmd=['docker','run','--rm','--runtime=runc','--network=none','--cpus='+str(a.cpus),
        '--memory='+str(a.memory_gib)+'g','--memory-swap='+str(a.memory_gib)+'g',
        '-e','NVIDIA_VISIBLE_DEVICES=void','-e','NVIDIA_DRIVER_CAPABILITIES=']
    for source,target,readonly in [(ROOT/('sara/serial' if a.method=='sara' else 'gerem'),'/code',True),(a.prepared,'/prepared',True),(a.masters,'/masters',True),(a.output,'/out',False)]:
        cmd+=['--mount','type=bind,src='+str(source.resolve())+',dst='+target+(',readonly' if readonly else '')]
    cmd += [a.image,'python3','-B','/opt/sara/scripts/query_worker.py','--budget',str(a.budget),'--method',a.method]
    with (a.output/'execution.log').open('w') as stream:subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT,check=True)
    print(json.dumps(dict(status='complete',output=str(a.output))))
if __name__=='__main__':main()
