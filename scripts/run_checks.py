"""Run import and local-semantics checks in the bounded installed image."""
import argparse,subprocess
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',default='sara:local');a=p.parse_args()
    base=['docker','run','--rm','--runtime=runc','--network=none','--cpus=4','--memory=8g','--memory-swap=8g',
        '-e','NVIDIA_VISIBLE_DEVICES=void','-e','NVIDIA_DRIVER_CAPABILITIES=',a.image]
    for command in (['python3','-B','scripts/check_imports.py'],['python3','-B','-m','unittest','discover','-s','tests','-v']):
        subprocess.run(base+command,check=True)
if __name__=='__main__':main()
