"""Build fixed workload sources with the recorded CUDA compilation options."""
import argparse,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--architecture',choices=('sm75','sm86'),default='sm75')
    p.add_argument('--app',default='Gemm');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    src=ROOT/'benchmarks/apps'/a.app
    if not src.is_dir():raise SystemExit('Unknown workload')
    a.output.mkdir(parents=True,exist_ok=False)
    if a.app=='LLM_TinyStories260K':unit=src/'forward_prefix1.cu'
    else:
        unit=a.output/(a.app+'.cu')
        unit.write_text('#include '+json.dumps(str(src/'benchmark.cuh'))+'\n')
    binary=a.output/a.app;ptx=a.output/(a.app+'.ptx');arch='sm_'+a.architecture[2:]
    base=['nvcc','-std=c++14','-g','-arch='+arch]
    if a.app=='LLM_TinyStories260K':base+=['-DUSE_CUDA','-I/usr/local/cuda/include']
    subprocess.run(base+['--cudart=shared',str(unit),'-lcudart','-o',str(binary)],check=True)
    subprocess.run(base+['-ptx','-lineinfo',str(unit),'-o',str(ptx)],check=True)
    record={'application':a.app,'architecture':a.architecture,'compiler':subprocess.check_output(['nvcc','--version'],text=True),
            'files':{q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in (binary,ptx)}}
    (a.output/'build.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
if __name__=='__main__':main()

