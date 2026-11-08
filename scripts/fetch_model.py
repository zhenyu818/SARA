"""Download only the pinned, trained small-model checkpoint."""
import argparse,hashlib,json,urllib.request
from pathlib import Path
URL='https://huggingface.co/karpathy/tinyllamas/resolve/0bd21da7698eaf29a0d7de3992de8a46ef624add/stories260K/stories260K.bin'
SHA='b0a507e7ad0f626624f17112325e66691f9076d622e1d3274d103d00299f2696'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise SystemExit('Refuse to overwrite an existing checkpoint')
with urllib.request.urlopen(URL,timeout=120) as f:b=f.read()
if len(b)!=1056540 or hashlib.sha256(b).hexdigest()!=SHA:raise RuntimeError('Checkpoint identity differs')
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(b)
print(json.dumps({'bytes':len(b),'sha256':SHA}))

