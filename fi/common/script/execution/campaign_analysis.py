"""Validate completed campaigns and report uncertainty without dropping Unknown.

Wilson intervals describe IID with-replacement sampling uncertainty for each
marginal outcome, not uncertainty caused by unsupported semantics. Identification
bounds show the separate effect of Unknown. FI-10K is a sampled reference, never
an exact population truth.
"""
from collections import Counter
import json
import math
from pathlib import Path

from script.execution.campaign import CampaignLedger, OUTCOMES, atomic_json, fingerprint


def wilson(successes, total, z=1.959963984540054):
    if type(total) is not int or total <= 0 or type(successes) is not int or not 0 <= successes <= total:
        raise ValueError("binomial count must lie in a nonempty denominator")
    p = successes / total
    scale = 1 + z * z / total
    center = (p + z * z / (2 * total)) / scale
    half = z / scale * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return [max(0.0, center - half), min(1.0, center + half)]


def marginal(outcomes):
    if not outcomes or any(item not in OUTCOMES for item in outcomes):
        raise ValueError("all trials require valid completed outcomes")
    counts = Counter(outcomes)
    total, unknown = len(outcomes), counts["Unknown"]
    return {"denominator": total, "counts": {key: counts[key] for key in sorted(OUTCOMES)},
            "rates": {key: counts[key] / total for key in sorted(OUTCOMES)},
            "sampling_wilson_95": {key: wilson(counts[key], total) for key in sorted(OUTCOMES)},
            "unknown_identification_bounds": {key: [counts[key] / total, (counts[key] + unknown) / total]
                                               for key in sorted(OUTCOMES - {"Unknown"})}}


def distribution_distance(reference, prediction):
    """Total variation of three-class marginals; never site accuracy.

    Unknown mass may be allocated anywhere on each three-class simplex. The
    maximum of this convex distance is attained at simplex vertices; the
    minimum is the known L1 excess after assigning both Unknown masses.
    """
    a,b=marginal(reference),marginal(prediction)
    keys=("Masked","SDC","DUE")
    av=[a["rates"][key] for key in keys];bv=[b["rates"][key] for key in keys]
    ua=a["rates"]["Unknown"];ub=b["rates"]["Unknown"]
    low=max(0.0,(sum(abs(x-y) for x,y in zip(av,bv))-ua-ub)/2)
    high=max(sum(abs(x+(ua if k==i else 0)-y-(ub if k==j else 0))
        for k,(x,y) in enumerate(zip(av,bv)))/2 for i in range(3) for j in range(3))
    return {"classes":list(keys),"total_variation_identification_bounds":[low,min(1.0,high)],
        "observed_total_variation":low if ua==ub==0 else None,
        "marginal_overlap_identification_bounds":[max(0.0,1-high),1-low],
        "overlap_is_not_site_accuracy":True,
        "uncertainty_scope":"Unknown identification only; sampled marginals also have sampling uncertainty"}


def known_class_metrics(matrix):
    """Descriptive precision/recall conditional on both paired labels known."""
    keys=("Masked","SDC","DUE");result={}
    for key in keys:
        tp=matrix[key][key];predicted=sum(matrix[a][key] for a in keys)
        actual=sum(matrix[key][b] for b in keys)
        truth_with_unknown_prediction=matrix[key]["Unknown"]
        result[key]={"jointly_known_TP":tp,"jointly_known_predicted_positive":predicted,
            "jointly_known_actual_positive":actual,
            "precision_jointly_known":tp/predicted if predicted else None,
            "recall_jointly_known":tp/actual if actual else None,
            "known_FI_positive_with_unknown_prediction":truth_with_unknown_prediction,
            "recall_bounds_on_known_FI_positives":[tp/(actual+truth_with_unknown_prediction),
                (tp+truth_with_unknown_prediction)/(actual+truth_with_unknown_prediction)] if actual+truth_with_unknown_prediction else None,
            "conditioning":"jointly known precision/recall are conditional, not full-population coverage; Unknown remains in N"}
    return result


def paired(reference, prediction, alpha=0.05):
    if len(reference) != len(prediction) or not reference:
        raise ValueError("paired predictions require identical nonempty trial manifests")
    if not 0 < alpha < 1: raise ValueError("valid paired interval alpha required")
    marginal(reference)
    marginal(prediction)
    matrix = {actual: {predicted: 0 for predicted in sorted(OUTCOMES)} for actual in sorted(OUTCOMES)}
    for actual, predicted in zip(reference, prediction):
        matrix[actual][predicted] += 1
    n = len(reference)
    known = sum(a != "Unknown" and b != "Unknown" for a, b in zip(reference, prediction))
    wrong_known = sum(a != b and a != "Unknown" and b != "Unknown" for a, b in zip(reference, prediction))
    unresolved = n - known
    differences = {}
    half = math.sqrt(2 * math.log(2 / alpha) / n)
    # A difference involving an Unknown label is only partially identified.
    for outcome in sorted(OUTCOMES - {"Unknown"}):
        pred_count = prediction.count(outcome)
        ref_count = reference.count(outcome)
        low = (pred_count - ref_count - reference.count("Unknown")) / n
        high = (pred_count + prediction.count("Unknown") - ref_count) / n
        differences[outcome] = {
            "recorded_rate_difference": (pred_count - ref_count) / n,
            "unknown_identification_bounds": [low, high],
            "sampling_and_unknown_hoeffding_bounds": [max(-1.0, low - half), min(1.0, high + half)]}
    return {"denominator": n, "confusion_matrix_reference_rows": matrix,
            "jointly_known_count": known, "known_disagreements": wrong_known,
            "jointly_known_coverage": known / n,
            "known_pair_accuracy": (known - wrong_known) / known if known else None,
            "known_pair_accuracy_wilson_95": wilson(known - wrong_known,known) if known else None,
            "accuracy_identification_bounds_all_N": [(known - wrong_known) / n,
                (known - wrong_known + unresolved) / n],
            "unresolved_pairs": unresolved,
            "disagreement_identification_bounds": [wrong_known / n, (wrong_known + unresolved) / n],
            "outcome_differences": differences,
            "outcome_differences_percentage_points":{key:100*value["recorded_rate_difference"] for key,value in differences.items()},
            "three_class_distribution":distribution_distance(reference,prediction),
            "class_metrics":known_class_metrics(matrix),
            "common_SDC_probability_scoring":sdc_probability_scores(reference,[
                {key:float(key==value) for key in OUTCOMES} for value in prediction]),
            "interval_alpha": alpha,
            "difference_interval_notes": "Per-outcome conservative bounded paired-draw intervals, including Unknown identification; no exact population truth or simultaneous all-outcome claim.",
            "reference_unknown_count": reference.count("Unknown"),
            "reference_unknown_truth": "unidentified; Unknown is not a correct/incorrect observed scientific label"}


def sdc_probability_scores(reference, vectors):
    """Binary SDC probability scoring, retaining all N identification bounds.

    Calibration bins are descriptive only for fully observed FI/model pairs;
    excluded Unknown draws remain explicit. An observed DUE is non-SDC (y=0)
    for this unconditional binary-SDC score. This does not evaluate DUE
    classification; its outcome rate/difference/confusion are separate reports.
    """
    if len(reference) != len(vectors) or not reference:
        raise ValueError("nonempty paired SDC probability rows required")
    n, lower_sum, upper_sum = len(reference), 0.0, 0.0
    match_low, match_high = 0.0, 0.0
    bins = [{"bin": i, "low": i / 10, "high": (i + 1) / 10,
             "count": 0, "predicted_sum": 0.0, "observed_SDC": 0} for i in range(10)]
    fully_observed = 0
    for actual, vector in zip(reference, vectors):
        lo, hi = vector["SDC"], vector["SDC"] + vector["Unknown"]
        if actual == "Unknown":
            match_low += min(lo,1-hi)
            match_high += max(hi,1-lo)
        elif actual == "SDC":
            match_low += lo;match_high += hi
        else:
            match_low += 1-hi;match_high += 1-lo
        if actual == "Unknown":
            low_score = min(lo ** 2, (1 - hi) ** 2)
            high_score = max(hi ** 2, (1 - lo) ** 2)
        else:
            y = float(actual == "SDC")
            distances = [(lo - y) ** 2, (hi - y) ** 2]
            low_score, high_score = min(distances), max(distances)
        lower_sum += low_score; upper_sum += high_score
        if actual != "Unknown" and vector["Unknown"] == 0:
            row = bins[min(9, int(lo * 10))]
            row["count"] += 1; row["predicted_sum"] += lo; row["observed_SDC"] += int(actual == "SDC")
            fully_observed += 1
    for row in bins:
        row["mean_prediction"] = row["predicted_sum"] / row["count"] if row["count"] else None
        row["observed_frequency"] = row["observed_SDC"] / row["count"] if row["count"] else None
        row["bin_interval"] = "[low,high]" if row["bin"] == 9 else "[low,high)"
    return {"denominator": n, "binary_outcome": "SDC", "thresholding_performed": False,
        "common_outcomes":["SDC","non-SDC"],
        "probability_match_identification_bounds_all_N":[match_low/n,match_high/n],
        "probability_match_is_not_observed_hard_label_accuracy":True,
        "reference_DUE_count": reference.count("DUE"),
        "brier_identification_bounds_all_N": [lower_sum / n, upper_sum / n],
        "calibration_fully_observed_count": fully_observed,
        "calibration_unknown_pairs_count": n - fully_observed,
        "calibration_bins_fully_observed_pairs_only": bins,
        "scope": "unconditional binary SDC proper score; observed DUE is non-SDC (y=0), not a test of DUE classification; model/ref Unknown remains an interval; descriptive known-pair calibration is conditional and not full-population calibration; GEREM DUE not modeled"}


def probability_report(reference, rows, alpha=0.05):
    """Keep GEREM SIC probabilities intact; never threshold p=0.5 into a label.

    Hoeffding bounds cover sampling of bounded per-site probabilities. They are
    conservative per-outcome intervals, not simultaneous intervals or claims
    that the EFM probabilities are calibrated against FI.
    """
    if not reference or len(reference) != len(rows) or not 0 < alpha < 1:
        raise ValueError("nonempty paired probability rows and valid alpha required")
    marginal(reference)
    vectors = []
    for row in rows:
        vector = row.get("rate_vector", {})
        if set(vector) != OUTCOMES or any(isinstance(v, bool) or not isinstance(v, (int, float))
                or not math.isfinite(v) or not 0 <= v <= 1 for v in vector.values()):
            raise ValueError("invalid probability vector")
        if not math.isclose(sum(vector.values()), 1.0, rel_tol=0, abs_tol=1e-12):
            raise ValueError("probability vector must sum to one")
        vectors.append(vector)
    n = len(rows)
    sums = {outcome: sum(v[outcome] for v in vectors) for outcome in OUTCOMES}
    half = math.sqrt(math.log(2 / alpha) / (2 * n))
    matrix = {outcome: {predicted: 0.0 for predicted in sorted(OUTCOMES)} for outcome in sorted(OUTCOMES)}
    for actual, vector in zip(reference, vectors):
        for predicted, mass in vector.items():
            matrix[actual][predicted] += mass
    differences = {}
    ref_unknown = reference.count("Unknown")
    for outcome in sorted(OUTCOMES - {"Unknown"}):
        recorded = (sums[outcome] - reference.count(outcome)) / n
        low = recorded - ref_unknown / n
        high = recorded + sums["Unknown"] / n
        differences[outcome] = {
            "recorded_mean_difference": recorded,
            "unknown_identification_bounds": [low, high],
            "sampling_and_unknown_hoeffding_bounds": [max(-1, low - 2 * half), min(1, high + 2 * half)]}
    return {"denominator": n, "prediction_kind": "GEREM_storage_EFM_site_probabilities",
            "independent_DUE_estimate":None,
            "three_class_accuracy_supported":False,
            "expected_counts": sums, "mean_rate_vector": {k: v / n for k, v in sums.items()},
            "sampling_hoeffding_95": {k: [max(0, v / n - half), min(1, v / n + half)] for k, v in sums.items()},
            "unknown_identification_bounds": {k: [sums[k] / n, (sums[k] + sums["Unknown"]) / n]
                                               for k in sorted(OUTCOMES - {"Unknown"})},
            "fractional_expected_confusion_reference_rows": matrix,
            "sdc_probability_scoring": sdc_probability_scores(reference, vectors),
            "reference_unknown_count": ref_unknown,
            "reference_unknown_truth": "unidentified; Unknown row retains probabilities without imputing FI truth",
            "outcome_differences": differences,
            "outcome_differences_percentage_points":{key:100*value["recorded_mean_difference"] for key,value in differences.items()},
            "interval_notes": "Per-outcome IID with-replacement bounds for bounded site contributions; no calibration guarantee."}


def independent_difference(reference, predictions, alpha=0.05):
    """Independent sampled-reference difference with full-N partial identification.

    Predictions may be deterministic one-hot rows or unthresholded SIC vectors.
    This function does not itself establish independent streams; the CLI reopens
    both original manifests and binds their bytes to the completed FI ledgers.
    """
    if not reference or not predictions or not 0 < alpha < 1:
        raise ValueError("nonempty independent samples and valid alpha required")
    marginal(reference)
    vectors = []
    for row in predictions:
        vector = row.get("rate_vector", {})
        if (set(vector) != OUTCOMES or any(type(value) not in (int, float)
                or not math.isfinite(value) or not 0 <= value <= 1 for value in vector.values())
                or not math.isclose(sum(vector.values()), 1.0, rel_tol=0, abs_tol=1e-12)):
            raise ValueError("invalid independent prediction vector")
        vectors.append(vector)
    nr, np = len(reference), len(vectors)
    half = math.sqrt(.5 * (1 / nr + 1 / np) * math.log(2 / alpha))
    unknown_r = reference.count("Unknown") / nr
    unknown_p = sum(row["Unknown"] for row in vectors) / np
    differences = {}
    for outcome in sorted(OUTCOMES - {"Unknown"}):
        ref_rate = reference.count(outcome) / nr
        pred_rate = sum(row[outcome] for row in vectors) / np
        low, high = pred_rate - ref_rate - unknown_r, pred_rate + unknown_p - ref_rate
        differences[outcome] = {"recorded_rate_difference": pred_rate - ref_rate,
            "prediction_recorded_rate": pred_rate, "reference_recorded_rate": ref_rate,
            "unknown_identification_bounds": [low, high],
            "sampling_and_unknown_hoeffding_bounds": [max(-1.0, low - half), min(1.0, high + half)],
            "recorded_relative_error": abs(pred_rate - ref_rate) / ref_rate if ref_rate else None,
            "relative_error_scope": "diagnostic ratio to sampled recorded reference; undefined for zero reference rate; not exact population error"}
    return {"reference_N": nr, "prediction_N": np, "reference_is_sampled_not_exact_truth": True,
        "reference_unknown_mass": unknown_r, "prediction_unknown_mass": unknown_p,
        "interval_alpha": alpha, "outcome_differences": differences,
        "interval_notes": "Per-outcome weighted Hoeffding difference bounds for independently sampled bounded contributions; unknown lower/upper endpoints retained, no simultaneous all-outcome/calibration claim."}


def bind_independent_manifests(matched_path, independent_path, matched_ledger, independent_ledger):
    matched, independent = (json.loads(path.read_text()) for path in (matched_path, independent_path))
    for document, ledger in ((matched, matched_ledger), (independent, independent_ledger)):
        if (document.get("schema_version") != 1 or document.get("sampling") != "with_replacement"
                or document.get("algorithm") != "sara-sha256-rejection-v1"
                or document.get("trials") != ledger.manifest
                or fingerprint(document) != ledger.spec.get("identity", {}).get("manifest_fingerprint")):
            raise ValueError("independent comparison requires the exact original complete manifest bound by each FI ledger")
    if (not matched.get("population_fingerprint") or matched.get("population_fingerprint") != independent.get("population_fingerprint")
            or matched.get("population_contract") != independent.get("population_contract")
            or type(matched.get("seed")) is not int or type(independent.get("seed")) is not int
            or matched["seed"] == independent["seed"] or matched.get("stream") == independent.get("stream")
            or not matched.get("stream") or not independent.get("stream")):
        raise ValueError("independent reference must use the same population and distinct explicit seed/domain-separated stream")
    return {"matched_manifest_fingerprint": fingerprint(matched),
        "independent_manifest_fingerprint": fingerprint(independent),
        "population_fingerprint": matched["population_fingerprint"],
        "matched_seed": matched["seed"], "matched_stream": matched["stream"],
        "independent_seed": independent["seed"], "independent_stream": independent["stream"]}


def reference_unknown_summary(rows, manifest):
    if len(rows) != len(manifest) or not rows:
        raise ValueError("reference Unknown summary requires the complete same-N manifest")
    unknown = [(site, row) for site, row in zip(manifest, rows) if row["outcome"] == "Unknown"]
    return {"denominator": len(rows), "unknown_reference_count": len(unknown),
            "reference_truth_observed_count": len(rows) - len(unknown),
            "reference_unknown_truth": "unidentified", "truth_imputation_performed": False,
            "unknown_reasons": dict(Counter(str(row.get("reason", "unspecified")) for _, row in unknown)),
            "unknown_categories": dict(Counter(str(row.get("model_unknown", {}).get("category", "unspecified"))
                                               for _, row in unknown)),
            "unknown_trials": [{"trial_id": site["trial_id"], "site_id": site["site_id"],
                "attempt": row.get("attempt"), "log_sha256": row.get("log_sha256"), "reason": row.get("reason", "unspecified"),
                "model_unknown": {key: row.get("model_unknown", {}).get(key) for key in
                    ("category", "boundary", "reference_truth_observed", "policy_fingerprint", "witness_fingerprint",
                     "actual_wait4_exit_status", "identity", "independent_evidence_sha256")}}
                for site, row in unknown]}


def load_completed(directory, *, target_count=None):
    metadata = json.loads((directory / "campaign.json").read_text())
    if metadata["spec"].get("completion_contract") == "sara-method-probability-completion-v1":
        raise ValueError("probability ledger requires --gerem-method; it is not a hard-label campaign")
    ledger = CampaignLedger(directory, metadata["spec"], metadata["manifest"], resume=True, target_count=target_count)
    if metadata.get("fingerprint") != ledger.identity:
        raise ValueError("campaign identity is corrupt")
    ledger.summary(require_complete=True)
    rows = [ledger.read(row["trial_id"]) for row in ledger.manifest]
    retired = {"frozen_deployment", "pre_fi_prediction_contract", "completion_contract",
               "accepted_bound_inputs"}
    if any(ledger.spec.get(key) is not None for key in retired):
        raise ValueError("retired proof-wrapped ledger is not a current batch result")
    return ledger, rows


def completed_prefix(directory, budget):
    """Opt into a sealed checkpoint; preserve legacy full-run prefix analysis."""
    if budget is not None and type(budget) is int and budget > 0:
        checkpoint = Path(directory) / "checkpoints" / ("%08d" % budget)
        if checkpoint.is_dir():
            return budget
    return None
