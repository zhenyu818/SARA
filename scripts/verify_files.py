"""Check the distributed owned-file SHA-256 list and pinned submodule identity."""
import argparse,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--skip-submodule',action='store_true');a=p.parse_args()
    count=0
    for line in (ROOT/'provenance/files.sha256').read_text().splitlines():
        digest,rel=line.split('  ',1);path=ROOT/rel
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Distributed bytes differ: '+rel)
        count+=1
    if not a.skip_submodule:
        expected=json.loads((ROOT/'environment/dependencies.json').read_text())['gpgpusim']['commit']
        actual=subprocess.check_output(['git','-C',str(ROOT/'fi/upstream/gpgpusim'),'rev-parse','HEAD'],text=True).strip()
        if actual!=expected:raise ValueError('Submodule identity differs')
    print(json.dumps(dict(status='pass',owned_files=count,submodule_checked=not a.skip_submodule)))
if __name__=='__main__':main()
