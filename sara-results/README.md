# Experiment results

This directory stores the tracked public result artifacts used by the paper.
`run_experiment.sh` writes final results here by default unless `RESULT_ROOT` is
overridden.

Final public results are organized as:

- `Turing-RTX2060/SARA`
- `Turing-RTX2060/FI`
- `Turing-RTX2060/GEREM-1000`
- `Turing-RTX2060/GEREM-5000`
- `Turing-RTX2060/GEREM-10000`
- `Ampere-RTX3070/SARA`
- `Ampere-RTX3070/FI`
- `Ampere-RTX3070/GEREM-1000`
- `Ampere-RTX3070/GEREM-5000`
- `Ampere-RTX3070/GEREM-10000`
- `paper-results/`

Large intermediate traces, scratch run directories, and build artifacts remain
outside this tree under `.work/` or other ignored locations.
