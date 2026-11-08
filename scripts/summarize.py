"""Equal-condition summaries from identity-checked comparison JSON records."""
import argparse,csv,json,math
from pathlib import Path
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('inputs',type=Path,nargs='+');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Output must be fresh')
    rows=[json.loads(x.read_bytes()) for x in a.inputs];seen=set()
    for row in rows:
        key=tuple(row[k] for k in ('application','architecture','component','budget'))
        if key in seen:raise ValueError('Duplicate condition')
        seen.add(key)
    output=[];metrics=('paired_error_pct','paired_known_coverage_pct','class_mae_pp','model_known_coverage_pct',
        'SDC_probability_rate_absdiff_pp','SDC_probability_point_MAE_pct')
    for budget in sorted({r['budget'] for r in rows}):
        byarch={}
        for arch in ('SM75','SM86'):
            group=[r for r in rows if r['budget']==budget and r['architecture']==arch]
            if not group:continue
            item=dict(architecture=arch,budget=budget,conditions=len(group))
            for key in metrics:
                values=[r[key] for r in group if r.get(key) is not None]
                item[key]=math.fsum(values)/len(values) if values else '';item[key+'_valid_conditions']=len(values)
            byarch[arch]=item;output.append(item)
        if len(byarch)==2:
            item=dict(architecture='Mean',budget=budget,conditions=sum(x['conditions'] for x in byarch.values()))
            for key in metrics:
                values=[x[key] for x in byarch.values() if x[key]!='']
                item[key]=math.fsum(values)/2 if len(values)==2 else '';item[key+'_valid_conditions']=sum(x[key+'_valid_conditions'] for x in byarch.values())
            output.append(item)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(output[0]));writer.writeheader();writer.writerows(output)
if __name__=='__main__':main()
