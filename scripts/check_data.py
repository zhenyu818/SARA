"""Check the supplied numerical summaries without simulation or hidden inputs."""
import argparse,csv,json,math
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def rows(p):return list(csv.DictReader(p.open(newline='',encoding='utf-8')))
def close(a,b,label):
    if not math.isclose(float(a),float(b),rel_tol=2e-12,abs_tol=2e-10):raise ValueError('Numerical mismatch: '+label)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data',type=Path,default=ROOT/'data');p.add_argument('--output',type=Path);a=p.parse_args()
    data=a.data;checks=[]
    overall=rows(data/'agreement/overall.csv');byarch={r['architecture']:r for r in overall}
    for key in overall[0]:
        if key!='architecture':close(byarch['Mean'][key],(float(byarch['SM75'][key])+float(byarch['SM86'][key]))/2,'architecture mean '+key)
    for r in rows(data/'agreement/class_proportions.csv'):
        if r['method']=='sara_whole':close(sum(float(r[c+'_gap_pp']) for c in ('masked','sdc','due'))/3,
            byarch[r['architecture']]['sara_whole_proportion_gap_pp'],'whole class-gap mean')
        if r['method']=='gerem_probability':close(r['sdc_gap_pp'],byarch[r['architecture']]['gerem_sdc_rate_gap_pp'],'native probability gap')
    registry=json.loads((ROOT/'benchmarks/registry.json').read_text())['groups']
    weights={(r['application'],r['architecture']):len(r['components']) for r in registry}
    perapp=rows(data/'agreement/by_application.csv')
    fields={'sara_point':'sara_point_inconsistency_pct','sara_whole':'sara_whole_proportion_gap_pp','gerem_probability':'gerem_expected_inconsistency_pct'}
    for arch in ('SM75','SM86'):
        for method,key in fields.items():
            selected=[r for r in perapp if r['architecture']==arch and r['method']==method]
            if len(selected)!=14:raise ValueError('Fourteen applications are required')
            total=sum(weights[r['application'],arch] for r in selected)
            close(sum(float(r['inconsistency_value'])*weights[r['application'],arch] for r in selected)/total,byarch[arch][key],arch+' '+method)
            checks.append(dict(architecture=arch,method=method,applications=14,conditions=total))
    for r in rows(data/'language_model/outcomes.csv'):
        close(sum(float(r[c+'_pct']) for c in ('masked','sdc','due','unknown')),100,'language-model outcome closure')
    close(sum(float(r['sdc_mass_share_pct']) for r in rows(data/'evidence/sdc_attribution.csv')),100,'attribution closure')
    perf=rows(data/'performance/summary.csv')
    for method in sorted({r['method'] for r in perf}):
        selected={r['architecture']:r for r in perf if r['method']==method}
        for key in perf[0]:
            if key not in ('architecture','method'):close(selected['Mean'][key],(float(selected['SM75'][key])+float(selected['SM86'][key]))/2,'resource mean '+method+' '+key)
    result=dict(status='pass',scope='released-summary arithmetic and closure',checks=checks,
        paired_draws_recomputed=False,new_simulations=0)
    if a.output:
        if a.output.exists():raise FileExistsError(a.output)
        a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':main()
