"""Report arithmetic only. The executable caller admits B-only evidence first.

No predictor, FI, trace parser, sampler, or probability threshold is imported.
"""
import math
from collections import Counter, defaultdict

KNOWN = ('Masked', 'SDC', 'DUE')
ALL = KNOWN + ('Unknown',)
ARCHS = ('SM75', 'SM86')
BUDGETS = (1000, 5000, 10000)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def integer(value, name='count'):
    need(type(value) is int and value >= 0, 'nonnegative integer required: ' + name)
    return value


def number(value, name='measurement', nullable=False):
    if nullable and value is None:
        return None
    need(type(value) in (int, float) and math.isfinite(value), 'finite numeric required: ' + name)
    return value


def div(a, b, scale=1):
    return a * scale / b if b else None


def counts(value, denominator):
    need(type(value) is dict and set(value) == set(ALL), 'exact four-class counts required')
    result = {c: integer(value[c], c) for c in ALL}
    need(sum(result.values()) == integer(denominator), 'four-class mass conservation failed')
    return result


def base(meta, method, denominator, known, unknown):
    row = dict(meta, method=method, denominator=denominator, model_known_denominator=known,
        model_unknown_count=unknown, model_known_coverage_pct=div(known, denominator, 100) if known is not None else None,
        full_Unknown_pct=div(unknown, denominator, 100) if unknown is not None else None, paired_known_n=None,
        paired_known_coverage_pct=None, paired_error_pct=None, paired_accuracy_pct=None,
        class_mae_pp=None, SDC_probability_rate_absdiff_pp=None,
        SDC_probability_point_MAE_pct=None, SDC_probability_Brier=None,
        independent_GEREM_Masked_DUE_available=False if method == 'gerem_probability' else None,
        hard_labels_generated=False, FI_same_cache_model_certified=False,
        comparison_is_accuracy_regression_certification=False)
    for c in KNOWN:
        row.update({c + '_conditional_model_pct': None, c + '_conditional_FI_pct': None,
                    c + '_absdiff_pp': None, c + '_paired_class_error_pct': None,
                    'full_' + c + '_pct': None})
    return row


def distribution(row, predicted, observed):
    differences = []
    for c in KNOWN:
        p, y = predicted[c], observed[c]
        row[c + '_conditional_model_pct'] = p
        row[c + '_conditional_FI_pct'] = y
        d = abs(p - y) if p is not None and y is not None else None
        row[c + '_absdiff_pp'] = d
        differences.append(d)
    row['class_mae_pp'] = math.fsum(differences) / 3 if all(d is not None for d in differences) else None


def sara_rows(meta, report, whole):
    """Use sealed same-draw confusion, not marginal labels or new queries."""
    n = integer(meta['budget'])
    joined = report['original_population']
    fi = counts(joined['FI']['counts'], n)
    point_counts = counts(joined['SARA']['counts'], n)
    matrix = joined['paired']['confusion_matrix_reference_rows']
    need(type(matrix) is dict and set(matrix) == set(ALL), 'four reference confusion rows required')
    matrix = {a: {b: integer(matrix[a][b]) for b in ALL} for a in ALL
              if type(matrix[a]) is dict and set(matrix[a]) == set(ALL)}
    need(set(matrix) == set(ALL), 'four prediction confusion columns required')
    need(all(sum(matrix[a].values()) == fi[a] for a in ALL), 'FI confusion marginals differ')
    need(all(sum(matrix[a][b] for a in ALL) == point_counts[b] for b in ALL), 'SARA confusion marginals differ')
    k = sum(matrix[a][b] for a in KNOWN for b in KNOWN)
    need(k == joined['paired']['jointly_known_count'], 'paired-known denominator differs')
    point = base(meta, 'sara_point', n, n - point_counts['Unknown'], point_counts['Unknown'])
    point.update(paired_known_n=k, paired_known_coverage_pct=div(k, n, 100),
        reference_unknown_count=fi['Unknown'], unresolved_pair_count=n-k,
        reference_support='same FI/SARA jointly-known draws',
        point_evidence='sealed original same-master confusion; fixed-SARA whole/source compatibility admitted')
    correct = sum(matrix[c][c] for c in KNOWN)
    point.update(paired_accuracy_pct=div(correct, k, 100), paired_error_pct=div(k-correct, k, 100),
                 known_correct_count=correct, known_error_count=k-correct)
    distribution(point,
        {c: div(sum(matrix[a][c] for a in KNOWN), k, 100) for c in KNOWN},
        {c: div(sum(matrix[c][b] for b in KNOWN), k, 100) for c in KNOWN})
    for c in KNOWN:
        support = sum(matrix[c][b] for b in KNOWN)
        point[c + '_paired_FI_support_n'] = support
        point[c + '_paired_class_error_pct'] = div(support-matrix[c][c], support, 100)
        point['full_' + c + '_pct'] = div(point_counts[c], n, 100)
    point['full_class_counts'] = point_counts
    for c in ALL:point['FI_full_'+c+'_pct']=fi[c]/n*100
    point['FI_reference_N']=n

    mass = integer(whole['population_mass'])
    need(mass > 0, 'positive whole population mass required')
    wc = counts(whole['counts'], mass)
    need(report['whole_population']['population_mass'] == mass
         and report['whole_population']['counts'] == wc, 'current fixed-SARA whole differs from original report')
    wk, fk = mass-wc['Unknown'], n-fi['Unknown']
    total = base(meta, 'sara_whole', mass, wk, wc['Unknown'])
    total.update(reference_unknown_count=fi['Unknown'], reference_known_n=fk,
        reference_support='all known FI prefix outcomes versus known whole-population model mass',
        point_accuracy_not_applicable=True, full_class_counts=wc,
        whole_reused_for_all_three_budgets=True)
    for c in ALL:total['FI_full_'+c+'_pct']=fi[c]/n*100
    total['FI_reference_N']=n
    distribution(total, {c: div(wc[c], wk, 100) for c in KNOWN},
                 {c: div(fi[c], fk, 100) for c in KNOWN})
    for c in KNOWN:
        total['full_' + c + '_pct'] = div(wc[c], mass, 100)
    return point, total


def gerem_rows(meta, points, fi_outcomes, missing_reason=None):
    """Native probabilities; known-pair proper scores never manufacture labels."""
    result = []
    if points is None:
        for n in BUDGETS:
            row = base(dict(meta, budget=n), 'gerem_probability', n, None, None)
            row.update(model_known_coverage_pct=None, full_Unknown_pct=None,
                evidence_status='UNAVAILABLE', unavailable_reason=missing_reason,
                reference_support='no current native per-draw GEREM evidence; old models not substituted')
            result.append(row)
        return result
    need(len(points) == 10000, 'one complete native 10K C export required')
    if fi_outcomes is not None:
        need(len(fi_outcomes) == 10000 and all(y in ALL for y in fi_outcomes), 'complete original FI outcome prefix required')
    for n in BUDGETS:
        rows = points[:n]
        probabilities = [r['answer'].get('p_sdc') for r in rows]
        for p in probabilities:
            need(p is None or (type(p) in (int, float) and math.isfinite(p) and 0 <= p <= 1), 'native probability outside [0,1]')
        known = sum(p is not None for p in probabilities)
        unknown = n-known
        row = base(dict(meta, budget=n), 'gerem_probability', n, known, unknown)
        psum = math.fsum(p for p in probabilities if p is not None)
        row.update(evidence_status='AVAILABLE', native_known_SDC_probability_pct=div(psum, known, 100),
            full_SDC_probability_mass_pct=psum/n*100,
            full_nonSDC_probability_mass_pct=(known-psum)/n*100,
            full_N_SDC_probability_bounds_pct=[psum/n*100,(psum+unknown)/n*100],
            reference_support='same native GEREM-known and FI-known draw intersection',
            probability_score_is_not_three_class_accuracy=True,
            DUE_reference_is_nonSDC_only_for_binary_score=True,
            independent_DUE_probability=None, thresholding_performed=False)
        native = Counter(r['answer'].get('efm') for r in rows if r['answer'].get('efm') is not None)
        resolved = Counter(r['answer'].get('efm') for r in rows
                           if r['answer'].get('efm') is not None and r['answer'].get('p_sdc') is not None)
        need(set(native) <= {'benign','dcr','ebc'}, 'unknown native EFM category')
        unsupported = [r['answer'] for r in rows if r['answer'].get('efm') is None or r['answer'].get('p_sdc') is None]
        row.update(native_known_EFM_counts={k:native[k] for k in ('benign','dcr','ebc')},
            resolved_EFM_counts={k:resolved[k] for k in ('benign','dcr','ebc')},
            unsupported_draws=len(unsupported), unsupported_pct=len(unsupported)/n*100,
            unsupported_by_status=dict(Counter(a.get('support_status','unreported') for a in unsupported)),
            unsupported_by_reason=dict(Counter(a.get('reason') or 'unspecified' for a in unsupported)))
        for efm in ('benign','dcr','ebc'):
            row['native_'+efm+'_EFM_full_N_pct']=native[efm]/n*100
            row['resolved_'+efm+'_EFM_full_N_pct']=resolved[efm]/n*100
        if fi_outcomes is None:
            row.update(probability_score_unavailable_reason='original FI per-draw evidence unavailable',
                       FI_reference_unknown_count=None)
        else:
            pairs = [(p, 1 if y == 'SDC' else 0) for p,y in zip(probabilities,fi_outcomes[:n])
                     if p is not None and y in KNOWN]
            k = len(pairs)
            mean_p = div(math.fsum(p for p,y in pairs), k, 100)
            mean_y = div(sum(y for p,y in pairs), k, 100)
            row.update(paired_known_n=k, paired_known_coverage_pct=div(k,n,100),
                FI_reference_unknown_count=sum(y == 'Unknown' for y in fi_outcomes[:n]),
                same_support_GEREM_SDC_probability_pct=mean_p, same_support_FI_SDC_pct=mean_y,
                SDC_probability_rate_absdiff_pp=abs(mean_p-mean_y) if k else None,
                SDC_probability_point_MAE_pct=div(math.fsum(abs(p-y) for p,y in pairs),k,100),
                SDC_probability_Brier=div(math.fsum((p-y)**2 for p,y in pairs),k),
                probability_score_unavailable_reason=None if k else 'no jointly-known FI/GEREM draws')
        result.append(row)
    return result


METRICS = ('paired_error_pct','paired_accuracy_pct','class_mae_pp','model_known_coverage_pct',
    'paired_known_coverage_pct','full_Unknown_pct','SDC_probability_rate_absdiff_pp',
    'SDC_probability_point_MAE_pct','SDC_probability_Brier','unsupported_pct',
    'native_known_SDC_probability_pct','same_support_GEREM_SDC_probability_pct','same_support_FI_SDC_pct',
    'full_SDC_probability_mass_pct','full_nonSDC_probability_mass_pct') + tuple(
    key for c in KNOWN for key in (c+'_conditional_model_pct',c+'_conditional_FI_pct',
        c+'_absdiff_pp',c+'_paired_class_error_pct','full_'+c+'_pct')) + tuple(
        prefix+efm+'_EFM_full_N_pct' for prefix in ('native_','resolved_') for efm in ('benign','dcr','ebc')) + tuple(
        'FI_full_'+c+'_pct' for c in ALL)


def macro(rows, dimensions):
    """Equal actual conditions, then equal two-SM means; no pooled draw weighting."""
    groups = defaultdict(list)
    for row in rows:
        need(row['architecture'] in ARCHS, 'unknown architecture')
        groups[tuple(row[k] for k in dimensions)].append(row)
    output = []
    for key, values in sorted(groups.items()):
        by_arch = {}
        for arch in ARCHS:
            subset = [r for r in values if r['architecture'] == arch]
            if not subset:
                continue
            entry = dict(zip(dimensions,key), architecture=arch, n_conditions=len(subset))
            for metric in METRICS:
                valid = [number(r[metric]) for r in subset if r.get(metric) is not None]
                entry[metric] = math.fsum(valid)/len(valid) if valid else None
                entry['n_valid_'+metric] = len(valid)
            by_arch[arch] = entry
            output.append(entry)
        average = dict(zip(dimensions,key), architecture='SM_AVERAGE',
            n_conditions=sum(r['n_conditions'] for r in by_arch.values()),
            n_architectures_present=len(by_arch), aggregation='equal SM75 and SM86 macro means; both required')
        for metric in METRICS:
            valid = [r[metric] for r in by_arch.values() if r[metric] is not None]
            average[metric] = math.fsum(valid)/2 if len(valid) == 2 else None
            average['n_valid_'+metric] = sum(r['n_valid_'+metric] for r in by_arch.values())
            average['n_valid_SM_'+metric] = len(valid)
        output.append(average)
    return output


def tables(rows):
    overall = macro(rows, ('budget','method'))
    classes = []
    for row in overall:
        for c in KNOWN:
            entry={k:row[k] for k in ('architecture','budget','method','n_conditions')}
            entry.update(dict(
                outcome=c, mean_abs_difference_pp=row[c+'_absdiff_pp'],
                n_valid=row['n_valid_'+c+'_absdiff_pp'],
                paired_class_error_pct=row[c+'_paired_class_error_pct'],
                n_valid_paired_class_error=row['n_valid_'+c+'_paired_class_error_pct'],
                GEREM_binary_SDC_rate_absdiff_pp=row['SDC_probability_rate_absdiff_pp'] if c=='SDC' else None,
                GEREM_three_class_metric_available=False if row['method']=='gerem_probability' else None))
            classes.append(entry)
    return {'01_overall':overall,'02_classes':classes,
        '03_components':macro(rows,('budget','component','method')),
        '04_applications':macro(rows,('budget','application','method'))}
