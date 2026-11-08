"""Identity-checked pairing of newly generated FI and native prediction chunks."""
import argparse,json,math,sys
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'sara/serial')]
from point_records import read_chunks
from script.execution.campaign import fingerprint
KNOWN=('Masked','SDC','DUE')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fi-root',type=Path,required=True);p.add_argument('--sara',type=Path,required=True)
    p.add_argument('--gerem',type=Path);p.add_argument('--whole',type=Path,required=True)
    p.add_argument('--application',required=True);p.add_argument('--architecture',choices=('SM75','SM86'),required=True)
    p.add_argument('--component',choices=('rf','smem','l1d','l2'),required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('Output must be fresh')
    fi={}
    for index in sorted((a.fi_root/'checkpoints').glob('batch-*/index.json')):
        for r in read_chunks(index):
            if r['trial_id'] in fi:raise ValueError('FI draw appears in more than one checkpoint')
            if r['result'].get('status')!='complete':raise ValueError('An FI draw is unfinished')
            fi[r['trial_id']]=r
    pred={r['trial_id']:r for r in read_chunks(a.sara)}
    if not fi or set(fi)!=set(pred):raise ValueError('FI and SARA draw identities differ')
    probabilities={} if a.gerem is None else {r['trial_id']:r for r in read_chunks(a.gerem)}
    if a.gerem and set(probabilities)!=set(fi):raise ValueError('GEREM draw identities differ')
    matrix={x:{y:0 for y in KNOWN+('Unknown',)} for x in KNOWN+('Unknown',)}
    pairs=[]
    for draw,r in fi.items():
        trial=r['trial'];answer=pred[draw]
        if (trial['component']!=a.component or answer['site_id']!=trial['site_id']
                or answer['requested_draw_fingerprint']!=fingerprint(trial)):
            raise ValueError('SARA and FI physical draw identity differs')
        observed=r['result']['outcome'];estimated=answer['outcome']
        if observed not in matrix or estimated not in matrix:raise ValueError('Unrecognized physical outcome')
        matrix[observed][estimated]+=1
        if a.gerem:
            g=probabilities[draw]
            if g['site_id']!=trial['site_id']:raise ValueError('GEREM and FI physical site differs')
            value=g['answer'].get('p_sdc')
            if value is not None:
                if not math.isfinite(value) or not 0<=value<=1:raise ValueError('Invalid native SDC probability')
                if observed in KNOWN:pairs.append((value,int(observed=='SDC')))
    n=len(fi);k=sum(matrix[x][y] for x in KNOWN for y in KNOWN)
    result=dict(application=a.application,architecture=a.architecture,component=a.component,budget=n,
        requested_draws=n,paired_known_n=k,paired_known_coverage_pct=k/n*100,
        paired_error_pct=None if not k else (k-sum(matrix[c][c] for c in KNOWN))/k*100,
        confusion_reference_rows=matrix,legal_repeated_sites_preserved=True,probability_threshold=None)
    whole=json.loads(a.whole.read_bytes());counts=whole['counts'];mass=whole['population_mass']
    if sum(counts.values())!=mass:raise ValueError('Whole-population mass differs')
    known_mass=mass-counts['Unknown'];fi_counts=Counter(r['result']['outcome'] for r in fi.values());fi_known=sum(fi_counts[c] for c in KNOWN)
    result['class_mae_pp']=None if not known_mass or not fi_known else sum(abs(counts[c]/known_mass-fi_counts[c]/fi_known)*100 for c in KNOWN)/3
    result['model_known_coverage_pct']=known_mass/mass*100
    result['SDC_probability_rate_absdiff_pp']=None if not pairs else abs(sum(p for p,y in pairs)-sum(y for p,y in pairs))/len(pairs)*100
    result['SDC_probability_point_MAE_pct']=None if not pairs else sum(abs(p-y) for p,y in pairs)/len(pairs)*100
    result['gerem_known_pairs']=len(pairs) if a.gerem else None
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status='complete',draws=n,paired_known=k)))
if __name__=='__main__':main()
