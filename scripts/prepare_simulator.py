"""Materialize the pinned simulator and apply the distributed source patch."""
import argparse,hashlib,json,shutil,subprocess,urllib.request,tarfile,io
import re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--upstream',type=Path,default=ROOT/'fi/upstream/gpgpusim')
    a=p.parse_args();spec=json.loads((ROOT/'environment/dependencies.json').read_text())
    if a.output.exists():raise SystemExit('Output must be a new directory.')
    actual=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
    if actual!=spec['gpgpusim']['commit']:raise SystemExit('Initialize the pinned simulator submodule first.')
    subprocess.run(['git','-C',str(a.upstream),'diff','--exit-code'],check=True)
    blob=subprocess.check_output(['git','-C',str(a.upstream),'archive','--format=tar',actual])
    a.output.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
        for member in archive.getmembers():
            if member.name.startswith('/') or '..' in Path(member.name).parts:
                raise RuntimeError('Unsafe upstream archive path')
        archive.extractall(a.output)
    pins=json.loads((ROOT/'provenance/native-sources.json').read_text())
    for item in pins['modified_files']:
        path=a.output/item['path']
        if path.is_file():
            b=path.read_bytes().replace(b'\r\n',b'\n')
            b=re.sub(rb'\bTC\b',b'TRACE_COLUMN',b)
            path.write_bytes(b if not b or b.endswith(b'\n') else b+b'\n')
    subprocess.run(['git','-C',str(a.output),'apply','--unidiff-zero','--check',str(ROOT/'fi/patches/gpgpusim.patch')],check=True)
    subprocess.run(['git','-C',str(a.output),'apply','--unidiff-zero',str(ROOT/'fi/patches/gpgpusim.patch')],check=True)
    dep=spec['nlohmann_json'];target=a.output/dep['path'];target.parent.mkdir(parents=True,exist_ok=True)
    with urllib.request.urlopen(dep['url'],timeout=60) as f:b=f.read()
    if hashlib.sha256(b).hexdigest()!=dep['sha256']:raise RuntimeError('JSON dependency checksum differs')
    target.write_bytes(b)
    # Select the source parser used by the retained simulator, rather than
    # regenerating a different parser with an arbitrary Bison installation.
    generated=a.output/'src/cuda-sim/generated';generated.mkdir(exist_ok=True)
    for source in (ROOT/'fi/parser_sources').iterdir():shutil.copyfile(source,generated/source.name)
    make=a.output/'src/cuda-sim/Makefile';text=make.read_text()
    pattern=r'(\$\(OUTPUT_DIR\)/([^:\n]+):[^\n]+\n)\t@if command -v (bison|flex) >/dev/null 2>&1; then \\\n'
    def preferred(m):
        leaf=m[2];copies=[leaf]
        if leaf.endswith('.tab.c'):copies.append(leaf[:-1]+'h')
        recipe='\t@if [ -f $(PREGENERATED_PARSER_DIR)/'+leaf+' ]; then \\\n'
        for name in copies:recipe+='\t\tcp $(PREGENERATED_PARSER_DIR)/'+name+' $(OUTPUT_DIR)/'+name+'; \\\n'
        return m[1]+recipe+'\telif command -v '+m[3]+' >/dev/null 2>&1; then \\\n'
    text,count=re.subn(pattern,preferred,text)
    if count!=4:raise RuntimeError('Recorded parser build rules changed')
    make.write_text(text)
    identities={x.relative_to(a.output).as_posix():hashlib.sha256(x.read_bytes()).hexdigest()
        for folder in ('src','libcuda') for x in (a.output/folder).rglob('*')
        if x.is_file() and x.suffix in ('.h','.cc','.cpp','.c')}
    (a.output/'compiled-source-files.json').write_text(json.dumps(identities,sort_keys=True)+'\n')
    print(json.dumps({'status':'source_ready','upstream_commit':actual,'source_files':len(identities)}))
if __name__=='__main__':main()

