"""Report the new aggregate-performance / post-window-validation protocol.

Run on B after all method workers have terminated.  This reader joins retained
draw records and computes descriptive statistics; it never collects, injects,
propagates, relabels predictions or measures a predictor.  Historical campaign
reporters and their sealed results are intentionally untouched.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from script.execution.campaign import atomic_json, fingerprint
from script.execution.campaign_analysis import marginal, paired, sdc_probability_scores
from script.execution.fault_manifest import FaultPopulation
from script.execution.validation_records import read_chunks


CLASSES = ("Masked", "SDC", "DUE", "Unknown")
KNOWN = CLASSES[:3]
WINDOW_SCHEMA = "sara-method-performance-window-v1"


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular retained report input required: " + str(path))
    return json.loads(path.read_text())


def local(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or not relative.parts or any(part in (".", "..") for part in relative.parts):
        raise ValueError("retained evidence path must remain local")
    path = root / relative
    if root.resolve() not in path.resolve(strict=True).parents:
        raise ValueError("retained evidence escaped its condition")
    return path


def natural(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("invalid integer: " + name)
    return value


def number(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid nonnegative measurement: " + name)
    return value


def _index(path, method):
    summary = read(path)
    if summary.get("method") != method or summary.get("validation_only") is not True:
        raise ValueError("declared post-window " + method + " validation index required")
    return summary, list(read_chunks(path))


def load_fi(directory):
    """Verify complete new-protocol FI chunks and retained complete raw logs."""
    directory = Path(directory)
    identity = read(directory / "campaign.json")
    if identity.get("schema") != "sara-FI-aggregate-with-untimed-evidence-v1":
        raise ValueError("new aggregate FI protocol required; old campaign is not interchangeable")
    total = natural(identity.get("target_count"), "FI target", 1)
    aggregate, seal = read(directory / "aggregate.json"), read(directory / "fi_completion.json")
    if (aggregate.get("schema") != "sara-FI-aggregate-v1" or aggregate.get("complete") is not True
            or aggregate.get("count") != total or aggregate.get("identity_fingerprint") != fingerprint(identity)
            or seal.get("status") != "complete" or seal.get("aggregate") != aggregate):
        raise ValueError("complete immutable FI aggregate/seal required")
    records, trials = {}, {}
    for path in sorted((directory / "checkpoints").glob("batch-*/index.json")):
        index, chunk = _index(path, "FI")
        if index.get("identity_fingerprint") != fingerprint(identity):
            raise ValueError("FI checkpoint belongs to another campaign identity")
        for record in chunk:
            trial, result = record["trial"], record["result"]
            tid = record.get("trial_id")
            if (tid != trial.get("trial_id") or tid in records or result.get("status") != "complete"
                    or result.get("outcome") not in KNOWN or result.get("site_id") != trial.get("site_id")):
                raise ValueError("foreign, duplicate or unfinished FI validation draw")
            site = {key: trial[key] for key in ("population_fingerprint", "component", "target", "cycle", "bit")}
            if fingerprint(site) != trial.get("site_id"):
                raise ValueError("FI site identity changed")
            log = local(directory, Path(result["attempt"]) / "run.log")
            if (not isinstance(result.get("log_sha256"), str)
                    or digest(log) != result["log_sha256"]):
                raise ValueError("FI original complete raw-output log changed")
            records[tid], trials[tid] = result, trial
    if len(records) != total or len({row["draw_index"] for row in trials.values()}) != total:
        raise ValueError("FI checkpoint set is incomplete or has duplicate draw indices")
    ordered = sorted(trials, key=lambda tid: trials[tid]["draw_index"])
    indices = [natural(trials[tid]["draw_index"], "draw index") for tid in ordered]
    if indices != list(range(indices[0], indices[0]+total)):
        raise ValueError("FI immutable draw prefix/segment has a gap")
    actual_counts = {name: sum(records[tid]["outcome"] == name for tid in ordered) for name in KNOWN}
    if aggregate.get("counts") != actual_counts:
        raise ValueError("FI aggregate differs from its original per-draw outcomes")
    components = {row["component"] for row in trials.values()}
    if len(components) != 1:
        raise ValueError("one original component required per condition")
    return dict(directory=directory, identity=identity, aggregate=aggregate, ordered=ordered,
                trials=trials, records=records, component=next(iter(components)))


def load_joined(fi, sara_index, gerem_index):
    sara_meta, sara_rows = _index(sara_index, "SARA")
    gerem_meta, gerem_rows = _index(gerem_index, "GEREM")
    maps = []
    for method, rows, key in (("SARA", sara_rows, "requested_draw_fingerprint"),
                               ("GEREM", gerem_rows, "manifest_fingerprint")):
        table = {}
        for row in rows:
            tid = row.get("trial_id")
            trial = fi["trials"].get(tid)
            if (trial is None or tid in table or row.get("status") != "complete"
                    or row.get("site_id") != trial["site_id"] or row.get(key) != fingerprint(trial)):
                raise ValueError(method + " lacks the same exact immutable FI draw/site identity")
            if method == "SARA":
                if row.get("outcome") not in CLASSES:
                    raise ValueError("SARA validation outcome is incomplete")
            else:
                unknown, probability = row.get("unknown_mass"), row.get("p_sdc")
                if type(unknown) is not int or unknown not in (0, 1):
                    raise ValueError("GEREM original Unknown indicator required")
                if unknown:
                    if probability is not None:
                        raise ValueError("GEREM unresolved probability must remain unidentified")
                elif type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1:
                    raise ValueError("GEREM original probability must lie in [0,1]")
                if row.get("independent_DUE_probability") is not None or row.get("hard_label_generated") is not False:
                    raise ValueError("GEREM must retain original probability-only semantics")
            table[tid] = row
        if set(table) != set(fi["trials"]):
            raise ValueError(method + " point set differs from the complete FI draw set")
        maps.append(table)
    actual = [fi["records"][tid]["outcome"] for tid in fi["ordered"]]
    predictions = [maps[0][tid]["outcome"] for tid in fi["ordered"]]
    probabilities = [{"SDC": maps[1][tid]["p_sdc"] if not maps[1][tid]["unknown_mass"] else 0.0,
                       "Unknown": maps[1][tid]["unknown_mass"]} for tid in fi["ordered"]]
    unknown = sum(row["Unknown"] for row in probabilities)
    known = len(actual) - unknown
    probability_sum = math.fsum(row["SDC"] for row in probabilities)
    return dict(FI=marginal(actual), SARA=marginal(predictions), paired=paired(actual, predictions),
        GEREM=dict(sdc_probability_scores(actual, probabilities), unknown_draws=unknown,
            known_draws=known, known_coverage=known/len(actual),
            original_p_sdc_mean_known=probability_sum/known if known else None,
            original_p_sdc_mean_full_N_bounds=[probability_sum/len(actual), (probability_sum+unknown)/len(actual)],
            independent_Masked_DUE_predictions_provided=False,
            hard_label_accuracy=None, original_probability_output_preserved=True),
        source_indexes=dict(SARA=dict(path=str(sara_index), sha256=digest(sara_index), identity=sara_meta["identity"]),
            GEREM=dict(path=str(gerem_index), sha256=digest(gerem_index), identity=gerem_meta["identity"])),
        DATA_TAG_sample_counts=site_kinds(fi))


def site_kinds(fi):
    if fi["component"] not in {"l1d", "l2"}:
        return None
    counts = Counter()
    for trial in fi["trials"].values():
        width = 57 + 8 * trial["target"]["line_size_bytes"]
        counts["TAG" if trial["bit"] % width < 57 else "DATA"] += 1
    return {kind: counts[kind] for kind in ("DATA", "TAG")}


def whole_space(aggregate, fi_marginal):
    mass = natural(aggregate.get("population_mass"), "SARA whole bit-cycle mass", 1)
    counts = aggregate.get("counts")
    if not isinstance(counts, dict) or set(counts) != set(CLASSES):
        raise ValueError("complete whole-space M/S/D/U counts required")
    for value in counts.values(): natural(value, "SARA whole class count")
    if sum(counts.values()) != mass:
        raise ValueError("SARA whole-space class mass is incomplete")
    rates = {key: counts[key]/mass for key in CLASSES}
    truth = fi_marginal["rates"]
    u = rates["Unknown"]
    low = max(0.0, (sum(abs(rates[key]-truth[key]) for key in KNOWN)-u)/2)
    high = min(1.0, max(sum(abs(rates[key]+(u if key == destination else 0)-truth[key])
        for key in KNOWN)/2 for destination in KNOWN))
    return dict(population_mass=mass, counts=counts, rates=rates,
        unknown_identification_bounds={key: [rates[key], rates[key]+u] for key in KNOWN},
        FI_sample_difference_percentage_points={key: 100*(rates[key]-truth[key]) for key in KNOWN},
        difference_identification_bounds_percentage_points={key:
            [100*(rates[key]-truth[key]), 100*(rates[key]+u-truth[key])] for key in KNOWN},
        total_variation_identification_bounds=[low, high],
        one_minus_TV_identification_bounds=[max(0.0, 1-high), min(1.0, 1-low)],
        one_minus_TV_is_not_paired_accuracy=True, sampling_confidence_interval=None,
        uncertainty_scope="whole-space approximate model counts; Unknown bounds only; FI sample uncertainty is reported separately",
        Unknown_mechanism_mass_attribution="not inferred from samples, tags, compatibility markers or generic reason strings")


def performance(directory, method):
    """Include immutable failed-attempt work; never reuse its scientific inputs."""
    directory = Path(directory)
    current_final = directory / 'performance-window.json'
    paths = [(path, False) for path in sorted(directory.glob('performance-partial*.json'))]
    # Runner restarts an unsealed G/S path into a fresh own capture. Only its
    # cost receipts and referenced aggregates are report inputs, not that old
    # capture, parsed state, model or predictions.
    prior = []
    if method in ('GEREM', 'SARA-rates'):
        job_root = directory.parents[1]
        for path in sorted(job_root.glob('attempt-*/previous-unsealed-path/performance-*.json')):
            if path.name == 'performance-window.json' or path.name.startswith('performance-partial'):
                prior.append((path, True))
    paths = prior + paths + [(current_final, False)]
    receipts = []
    for path, wasted in paths:
        row = read(path)
        if (row.get("schema") != WINDOW_SCHEMA or row.get("method") != method
                or row.get("performance_measurement") is not True
                or row.get("validation_export_included") is not False
                or row.get("paired_query_included") is not False):
            raise ValueError("new independent aggregate performance window required")
        if path.name == 'performance-window.json':
            if row.get("aggregate_fsynced") is not True or row.get("partial"):
                raise ValueError("successful durable aggregate performance window required")
            if not local(path.parent, row['aggregate_file']).is_file():
                raise ValueError("performance aggregate is missing")
        elif row.get("partial") is not True or row.get("complete") is not False:
            raise ValueError("partial attempt must remain explicitly incomplete")
        for key in ("wall_seconds", "cpu_user_seconds", "cpu_system_seconds"):
            number(row.get(key), key)
        receipts.append((path, row, wasted))
    peaks = [row.get("memory_peak_bytes") for _, row, _ in receipts]
    for peak in peaks:
        if peak is not None: number(peak, "inclusive cgroup peak")
    if any(row.get('component') != receipts[-1][1].get('component') for _, row, _ in receipts):
        raise ValueError('attempt costs belong to different storage components')
    return dict(method=method, attempts=len(receipts),
        partial_attempts=sum(row.get('partial') is True for _, row, _ in receipts),
        incomplete_attempts=sum(row.get('partial') is True for _, row, _ in receipts),
        failed_postwindow_export_attempts=sum(wasted and row.get('complete') is True
                                              for _, row, wasted in receipts),
        prior_unsealed_attempt_receipts=sum(wasted for _, _, wasted in receipts),
        active_wall_seconds=math.fsum(row["wall_seconds"] for _, row, _ in receipts),
        cpu_user_seconds=math.fsum(row["cpu_user_seconds"] for _, row, _ in receipts),
        cpu_system_seconds=math.fsum(row["cpu_system_seconds"] for _, row, _ in receipts),
        inclusive_cgroup_peak_bytes=max(peaks) if all(peak is not None for peak in peaks) else None,
        memory_scope="maximum reported worker/cgroup high-water counter across attempts; inclusive of validation checkpoints, not isolated collector slowdown",
        active_boundary="own acquisition/preparation/analysis through durable aggregate; explicitly quiescent validation checkpoints excluded",
        Docker_startup_queue_compilation_included=False, paired_costs_included=False,
        receipts=[dict(path=str(path), sha256=digest(path), phases=row.get("phases", {}),
            active_wall_seconds=row["wall_seconds"], wasted_prior_unsealed_attempt=wasted,
            completed_aggregate_before_export_failure=wasted and row.get('complete') is True,
            excluded_validation_checkpoints=row.get("excluded_validation_checkpoints", []))
            for path, row, wasted in receipts])


def inventory_mass_by_kind(inventory):
    population = FaultPopulation(inventory)
    kinds = dict(DATA=0, TAG=0)
    for row in inventory["spans"]:
        width = 57+8*row["target"]["line_size_bytes"]
        first, count = row.get("bit_start", 0) % width, row["bit_count"]
        if first+count > width:
            raise ValueError("cache inventory rectangle crosses its physical line")
        tag = max(0, min(first+count, 57)-first)
        ticks = row["cycle_stop"]-row["cycle_start"]
        kinds["TAG"] += ticks*tag
        kinds["DATA"] += ticks*(count-tag)
    if sum(kinds.values()) != population.mass:
        raise ValueError("DATA/TAG inventory mass lost")
    return population, kinds


def assemble(condition):
    condition = Path(condition).resolve(strict=True)
    locations = {key: condition / sub for key, sub in (
        ("FI", "FI/output/path/fi"), ("GEREM", "GEREM/output/path"),
        ("rates", "rates/output/path"), ("paired", "paired/output/path"))}
    fi = load_fi(locations["FI"])
    joined = load_joined(fi, locations["paired"] / "validation-points/index.json",
                         locations["GEREM"] / "validation-state/index.json")
    rates = read(locations["rates"] / "aggregate.json")
    sara_summary = read(locations["paired"] / "analysis.json")
    if (sara_summary.get("sampled_draws") != len(fi["ordered"])
            or sara_summary.get("same_rates_core_result") is not True
            or sara_summary.get("new_batch_propagation") is not False
            or any(sara_summary.get(key) != rates.get(key) for key in
                   ("population_mass", "counts", "classification_digest", "region_count"))):
        raise ValueError("paired validation must query this exact completed rates result")
    g_aggregate = read(locations["GEREM"] / "aggregate.json")
    if (g_aggregate.get("completed") != len(fi["ordered"])
            or g_aggregate.get("planned") != len(fi["ordered"])
            or g_aggregate.get("denominator") != len(fi["ordered"])
            or g_aggregate.get("unknown_draws") != joined["GEREM"]["unknown_draws"]
            or g_aggregate.get("hard_label_generated") is not False
            or g_aggregate.get("population_mass") != rates["population_mass"]
            or g_aggregate.get("population_fingerprint") != sara_summary.get("population_fingerprint")):
        raise ValueError("GEREM aggregate differs from original validation probabilities")
    expected_mean = joined["GEREM"]["original_p_sdc_mean_known"]
    if ((expected_mean is None and g_aggregate.get("p_sdc_mean_known") is not None)
            or (expected_mean is not None and (type(g_aggregate.get("p_sdc_mean_known")) not in (int, float)
                or not math.isclose(g_aggregate["p_sdc_mean_known"], expected_mean, rel_tol=1e-12, abs_tol=1e-15)))
            or g_aggregate.get("p_sdc_mean_full_N_bounds") != joined["GEREM"]["original_p_sdc_mean_full_N_bounds"]):
        raise ValueError("GEREM aggregate probability values differ from retained original draws")
    resources = {key: performance(locations[key], method) for key, method in
                 (("FI", "FI"), ("GEREM", "GEREM"), ("rates", "SARA-rates"))}
    fi_wall = resources["FI"]["active_wall_seconds"]
    ratios = {"FI_over_GEREM": fi_wall/resources["GEREM"]["active_wall_seconds"]
              if resources["GEREM"]["active_wall_seconds"] else None,
              "FI_over_SARA_rates": fi_wall/resources["rates"]["active_wall_seconds"]
              if resources["rates"]["active_wall_seconds"] else None}
    report = dict(schema="sara-fair-aggregate-comparison-v1", condition=str(condition),
        component=fi["component"], draws=len(fi["ordered"]), complete=True,
        original_population=joined, whole_population=whole_space(rates, joined["FI"]),
        performance=resources, allowed_speed_ratios=ratios,
        study_setup={"included_in_method_speed_ratios": False,
            "receipt_provided": (condition / "study-setup.json").is_file(),
            "receipt": read(condition / "study-setup.json") if (condition / "study-setup.json").is_file() else None,
            "scope": "once per SM; separately reported when its actual receipt is provided"},
        limitations=["one measured configuration; no repeats or isolated collector slowdown inferred",
            "resource peaks include validation checkpoints and are not phase-reset peaks",
            "GEREM supplies original SDC/non-SDC probabilities; no independent Masked/DUE hard predictions",
            "SARA model approximations, original known errors and full-denominator Unknown are retained",
            "ratios describe complete recorded aggregate tasks, not intrinsic algorithm advantage or controlled cold-disk execution"])
    valid_inventory = condition / "valid-inventory.json"
    valid_fi = condition / "valid-FI/output/path/fi"
    valid_sara = condition / "valid-paired/output/path"
    valid_gerem = locations["GEREM"] / "subset-validation/index.json"
    requested = valid_inventory.exists() or valid_fi.exists() or valid_sara.exists() or valid_gerem.exists()
    if requested:
        inventory = read(valid_inventory)
        if not inventory.get("spans"):
            if valid_fi.exists() or valid_sara.exists() or valid_gerem.exists():
                raise ValueError("empty valid-resident population must not contain sampled results")
            report["valid_resident"] = dict(status="N/A", population_mass=0, fraction_of_original=0)
        else:
            population, kinds = inventory_mass_by_kind(inventory)
            parent = inventory.get("selection", {})
            if (parent.get("original_component_population_mass") != rates["population_mass"]
                    or parent.get("original_population_fingerprint") != sara_summary.get("population_fingerprint")
                    or parent.get("future_consumer_filter") is not False
                    or parent.get("outcome_filter") is not False):
                raise ValueError("valid-resident population is not bound to the same original component domain")
            vfi = load_fi(valid_fi)
            if (vfi["component"] != fi["component"] or len(vfi["ordered"]) != len(fi["ordered"])
                    or vfi["identity"].get("performance_measurement") is not False):
                raise ValueError("valid-resident cohort must retain this condition's component and budget")
            for trial in vfi["trials"].values():
                if (trial.get("population_fingerprint") != population.identity
                        or population.resolve(trial["population_rank"])["site_id"] != trial["site_id"]):
                    raise ValueError("valid FI point changed its separate immutable subset draw")
            valid_summary = read(valid_sara / "analysis.json")
            if (valid_summary.get("sampled_draws") != len(vfi["ordered"])
                    or valid_summary.get("same_rates_core_result") is not True
                    or valid_summary.get("new_batch_propagation") is not False
                    or any(valid_summary.get(key) != rates.get(key) for key in
                           ("population_mass", "counts", "classification_digest", "region_count"))):
                raise ValueError("valid pairing must query the original frozen rates regions")
            projection = valid_summary.get("subset_projection", {})
            if (projection.get("selected_population_fingerprint") != population.identity
                    or projection.get("selected_population_mass") != population.mass
                    or projection.get("original_population_fingerprint") != parent["original_population_fingerprint"]
                    or projection.get("entire_selected_domain_contained") is not True):
                raise ValueError("valid SARA projection lacks its exact original-domain containment proof")
            g_subset = read(valid_gerem).get("identity", {}).get("subset_projection")
            if g_subset != projection:
                raise ValueError("GEREM/SARA valid subset proofs differ")
            report["valid_resident"] = dict(status="complete", population_mass=population.mass,
                fraction_of_original=population.mass/rates["population_mass"], DATA_TAG_bit_cycle_mass=kinds,
                definition=parent, joined=load_joined(vfi, valid_sara / "validation-points/index.json", valid_gerem),
                performance_measurement=False, performance_costs_or_resources=None,
                new_SARA_rates_or_GEREM_acquisition=False,
                scope="separate current VALID/MODIFIED resident DATA+TAG population; no future-use filter")
    return report


def _pct(value):
    return "N/A" if value is None else "%.4f%%" % (100*value)


def _bounds(values):
    return "N/A" if values is None else "[%s, %s]" % tuple(_pct(value) for value in values)


def markdown(report):
    lines = ["# Recorded comparison", "", "Component: **%s**; matched draws: **%d**." % (report["component"], report["draws"]), ""]
    def comparison(label, value):
        lines.extend(["## " + label, "", "| FI outcome | Count | Rate | Wilson 95% CI |",
            "|---|---:|---:|---|"])
        for key in KNOWN:
            lines.append("| %s | %d | %s | %s |" % (key, value["FI"]["counts"][key],
                _pct(value["FI"]["rates"][key]), _bounds(value["FI"]["sampling_wilson_95"][key])))
        p = value["paired"]
        lines.extend(["", "| SARA sampled outcome | Count | Full-N rate | Wilson 95% CI |",
                      "|---|---:|---:|---|"])
        for key in CLASSES:
            lines.append("| %s | %d | %s | %s |" % (key, value["SARA"]["counts"][key],
                _pct(value["SARA"]["rates"][key]), _bounds(value["SARA"]["sampling_wilson_95"][key])))
        lines.extend(["", "SARA known-pair accuracy %s (Wilson 95%% CI %s); coverage %s; full-N accuracy bounds %s."
            % (_pct(p["known_pair_accuracy"]), _bounds(p["known_pair_accuracy_wilson_95"]),
               _pct(p["jointly_known_coverage"]), _bounds(p["accuracy_identification_bounds_all_N"])),
            "", "| FI \\ SARA | Masked | SDC | DUE | Unknown |", "|---|---:|---:|---:|---:|"])
        for key in KNOWN:
            lines.append("| %s | %s |" % (key, " | ".join(str(p["confusion_matrix_reference_rows"][key][other]) for other in CLASSES)))
        g = value["GEREM"]
        lines.extend(["", "GEREM original mean p(SDC), known draws: %s; Unknown %d/%d; probability-match bounds %s; Brier bounds %s."
            % (_pct(g["original_p_sdc_mean_known"]), g["unknown_draws"], g["denominator"],
               _bounds(g["probability_match_identification_bounds_all_N"]),
               str(g["brier_identification_bounds_all_N"])),
            "GEREM scores use SDC/non-SDC probabilities; they are not hard three-class accuracy."])
        if value["DATA_TAG_sample_counts"] is not None:
            lines.extend(["", "Sampled cache point types: " + str(value["DATA_TAG_sample_counts"])])
        lines.append("")
    comparison("Original complete storage population", report["original_population"])
    whole = report["whole_population"]
    lines.extend(["## Whole-population SARA model", "", "| Class | Bit-cycles | Rate | Difference from FI sample (pp) |",
                  "|---|---:|---:|---:|"])
    for key in CLASSES:
        delta = whole["FI_sample_difference_percentage_points"].get(key)
        lines.append("| %s | %d | %s | %s |" % (key, whole["counts"][key], _pct(whole["rates"][key]),
            "N/A" if delta is None else "%.4f" % delta))
    lines.extend(["", "1−TV agreement bounds: %s. This is marginal distribution overlap, not paired accuracy."
        % _bounds(whole["one_minus_TV_identification_bounds"]),
        "Whole-space Unknown class bounds: " + str(whole["unknown_identification_bounds"]), "",
        "## Complete aggregate-task performance", "",
        "| Method | Active wall (s) | CPU user+system (s) | Inclusive peak GiB | Attempts |",
        "|---|---:|---:|---:|---:|"])
    for key in ("FI", "GEREM", "rates"):
        row = report["performance"][key]
        peak = row["inclusive_cgroup_peak_bytes"]
        lines.append("| %s | %.6f | %.6f | %s | %d |" % (row["method"], row["active_wall_seconds"],
            row["cpu_user_seconds"]+row["cpu_system_seconds"], "unmeasured" if peak is None else "%.6f" % (peak/1024**3), row["attempts"]))
    lines.extend(["", "FI/GEREM: %s; FI/SARA-rates: %s. Paired validation has no performance ratio."
        % tuple("N/A" if report["allowed_speed_ratios"][key] is None else "%.6f" % report["allowed_speed_ratios"][key]
                for key in ("FI_over_GEREM", "FI_over_SARA_rates")),
        "Active partial-attempt costs are included. Peak counters include validation checkpoints; Docker startup, queue and compilation are excluded.",
        "Per-SM study setup is separate; receipt provided: %s." % report["study_setup"]["receipt_provided"], ""])
    valid = report.get("valid_resident")
    if valid:
        lines.extend(["Valid-resident population fraction: %s; status: %s." % (_pct(valid["fraction_of_original"]), valid["status"]), ""])
        if valid["status"] == "complete":
            comparison("Separate current-valid-resident cache cohort (untimed)", valid["joined"])
    lines.extend(["## Limits", "", *["- " + item for item in report["limitations"]], ""])
    return "\n".join(lines)


def main(argv=None):
    from script.execution.policy import require_container_execution
    require_container_execution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--condition", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError("new report output required; never replace a retained report")
    report = assemble(args.condition)
    args.output.mkdir(parents=True, exist_ok=False)
    atomic_json(args.output / "report.json", report)
    (args.output / "report.md").write_text(markdown(report))
    print(json.dumps(dict(complete=True, report_json=str(args.output / "report.json"),
        report_markdown=str(args.output / "report.md")), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
