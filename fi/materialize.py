"""Materialize one *admitted* FI dependency tree without running an experiment."""
import argparse,hashlib,json,shutil
from pathlib import Path
d=Path(__file__).resolve().parent
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--route',required=True,choices=['main','updated-apps','render','llm'])
ap.add_argument('--append',action='store_true',help='use the continuous append adapter; only for historical append windows')
ap.add_argument('--output',type=Path,required=True,help='fresh directory')
a=ap.parse_args()
if a.output.exists():raise SystemExit('Refusing to overwrite an existing path.')
if a.append and a.route=='llm':raise SystemExit('No LLM append campaign exists.')
routes=json.loads((d/'route-map.json').read_bytes())
for rel,digest in routes['routes'][a.route].items():
    path=(d/'llm'/'overlay'/rel if a.route=='llm' else d/'overlays'/a.route/rel)
    if not path.exists():path=d/'common'/rel
    if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('unexpected source: '+rel)
    target=a.output/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
if a.append:
    shutil.copyfile(d/'append'/a.route/'prefix_fi.py',a.output/'entry'/'prefix_fi.py')
    shutil.copyfile(d/'append'/'continuous_fi_prior_cache.py',a.output/'entry'/'continuous_fi_prior_cache.py')
if a.route=='llm':
    (a.output/'entry').mkdir(exist_ok=True)
    shutil.copyfile(d/'llm'/'run_rf10_worker_b01.py',a.output/'entry'/'run_rf10_worker_b01.py')
print('Materialized source only:',a.output)
