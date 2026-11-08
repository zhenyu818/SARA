"""Import each distributed implementation in its own Python process."""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PROBE="""
import importlib,sys,json
from pathlib import Path
r=Path(sys.argv[1]);sys.path[:0]=[str(r),str(r/'script/core'),str(r/'script/common')]
rows=[]
for name in sys.argv[2:]:
 m=importlib.import_module(name);rows.append({'module':name,'file':Path(m.__file__).relative_to(r).as_posix()})
print(json.dumps(rows))
"""

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);a=p.parse_args()
    plans={'serial':('sara/serial',['script.method_group.sara_group','script.core.generic_counter_loops','script.core.closed_word_flow','script.core.reg_observed_analyzer']),
           'parallel':('sara/parallel',['script.parallel_stream.inputs','script.parallel_stream.group','script.method_group.sara_group']),
           'gerem':('gerem',['script.indexed_storage.group','script.compatible_cache.cache','script.storage_rules.rf_smem'])}
    receipts={}
    for name,(root,modules) in plans.items():
        result=subprocess.check_output([sys.executable,'-I','-B','-c',PROBE,str(ROOT/root)]+modules,text=True)
        receipts[name]=json.loads(result)
    record={'status':'pass','scope':'entry point and dependency imports; no simulation or prediction','imports':receipts}
    if a.output:a.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))
if __name__=='__main__':main()

