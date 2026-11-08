"""Install a declared, cgroup-checked local execution profile, then run a command."""
import hashlib,json,os,sys
from pathlib import Path

def main():
    if os.geteuid()!=0 or not Path('/.dockerenv').is_file():raise SystemExit('A bounded CPU-only container is required')
    if os.environ.get('NVIDIA_VISIBLE_DEVICES')!='void' or list(Path('/dev').glob('nvidia*')):
        raise SystemExit('GPU access must be disabled')
    cpu=(Path('/sys/fs/cgroup')/'cpu.max').read_text().split()
    memory=(Path('/sys/fs/cgroup')/'memory.max').read_text().strip()
    swap=(Path('/sys/fs/cgroup')/'memory.swap.max').read_text().strip()
    if cpu[0]=='max' or memory=='max' or swap!='0':raise SystemExit('Explicit CPU, memory and zero-swap limits are required')
    cpus=int(cpu[0])//int(cpu[1]);mem=int(memory)
    if cpus<1 or int(cpu[0])%int(cpu[1]) or mem%1024**3:raise SystemExit('Use integer CPUs and GiB memory limits')
    document={'schema':'sara-execution-host-v1','role':'bounded_primary','cpus':cpus,'memory_bytes':mem,'swap_bytes':0,'schedule':'always_open'}
    raw=(json.dumps(document,sort_keys=True,separators=(',',':'))+'\n').encode()
    path=Path('/etc/sara-execution.json');path.write_bytes(raw);path.chmod(0o400)
    env=os.environ.copy();env['SARA_EXECUTION_ROLE']='bounded_primary';env['SARA_EXECUTION_PROFILE_SHA256']=hashlib.sha256(raw).hexdigest()
    command=sys.argv[1:] or ['bash'];os.execvpe(command[0],command,env)
if __name__=='__main__':main()

