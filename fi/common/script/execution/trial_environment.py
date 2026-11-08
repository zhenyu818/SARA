"""Versioned FI child environment: inputs declared, private runtime preserved.

Parent PTX/app/observer settings never select an unmanifested computation.
SARA_* is preserved worker evidence; it is not caller-overridable.
"""
from pathlib import PurePosixPath

POLICY = "sara-fi-trial-environment-v1"
FORCED = {"PTX_SIM_MODE_FUNC": "0", "SARA_VALIDATE_CPU": "0"}
EXTERNAL_INPUT_FILES = frozenset(("SARA_DIJKSTRA_GRAPH", "SARA_MF_RATINGS"))
EXTERNAL_CODE = frozenset(("CUOBJDUMP_SIM_FILE", "PYTORCH_BIN", "PTX_JIT_PATH", "WYS_EXEC_PATH"))
LOADER_INJECTION = frozenset(("LD_PRELOAD", "LD_AUDIT"))
RUNTIME_NAMES = frozenset(("PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "GPGPUSIM_ROOT", "GPGPUSIM_CONFIG",
                           "CUDA_INSTALL_PATH", "PTXAS_CUDA_INSTALL_PATH", "CUDA_VERSION_NUMBER", "CC_VERSION"))
CLEAR_NAMES = EXTERNAL_CODE | LOADER_INJECTION | frozenset(("GPGPUSIM_DEBUG", "CUDA_LAUNCH_BLOCKING"))


def safe_asset_name(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("application input environment requires a safe manifest-relative asset path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in (".", "..") for part in path.parts) or str(path) != value or value == ".":
        raise ValueError("application input environment requires a canonical safe relative asset path")
    return value


def explicit_environment(spec):
    values = spec.get("environment", {})
    if not isinstance(values, dict) or any(not isinstance(key, str) or not key or "=" in key or "\0" in key or
            key.startswith("SARA_") or not isinstance(value, str) or "\0" in value for key, value in values.items()):
        raise ValueError("explicit environment must be string values and cannot override SARA_* certificates")
    for key, value in values.items():
        if key in LOADER_INJECTION and value:
            raise ValueError("FI child forbids loader injection: " + key)
        if key in RUNTIME_NAMES or key.startswith("GPGPUSIM_"):
            raise ValueError("FI private worker runtime environment cannot be overridden: " + key)
        if key.startswith("PTX_SIM_"):
            allowed = ("", "0") if key in ("PTX_SIM_MODE_FUNC", "PTX_SIM_USE_PTX_FILE") else ("",)
            if value not in allowed: raise ValueError("FI child forbids external PTX/functional/debug override: " + key)
        if key in EXTERNAL_CODE and value:
            raise ValueError("FI child forbids unbound executable/PTX override: " + key)
        if key.startswith("SARA_POPULATION_REFERENCE_") and value:
            raise ValueError("FI child cannot enable an unreviewed observer: " + key)
        if key == "SARA_VALIDATE_CPU" and value != "0":
            raise ValueError("FI CPU oracle must be disabled explicitly with zero")
        if key in EXTERNAL_INPUT_FILES:
            name = safe_asset_name(value)
            assets = spec.get("assets", {})
            if not isinstance(assets, dict) or name not in assets:
                raise ValueError("application input environment path must name an explicitly hashed deployed asset: " + key)
    return dict(values)


def normalized_explicit_environment(spec):
    values = explicit_environment(spec)
    return {key: value for key, value in values.items()
            if not key.startswith("PTX_SIM_") and key not in EXTERNAL_CODE | LOADER_INJECTION
            and not (key.startswith("SARA_POPULATION_REFERENCE_") and not value)}


def policy_descriptor(spec):
    return {"schema": POLICY, "forced_environment": dict(FORCED),
            "normalized_explicit_environment": normalized_explicit_environment(spec),
            "inherited_policy": "remove_PTX_SIM_external_code_SARA_computation_observers_preserve_execution_metadata_and_private_runtime"}


def trial_environment(spec, parent):
    values = dict(parent)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in values.items()):
        raise ValueError("worker parent environment must contain only string keys/values")
    for key in LOADER_INJECTION:
        if values.get(key): raise ValueError("inherited loader injection is forbidden even without capture: " + key)
    environment = {key: value for key, value in values.items() if key not in CLEAR_NAMES and
                   not key.startswith("PTX_SIM_") and not (key.startswith("SARA_") and not key.startswith("SARA_"))}
    environment.update(normalized_explicit_environment(spec))
    environment.update(FORCED)
    return environment


def environment_evidence(spec, parent, actual):
    """Retain approved inputs/runtime paths, never dump all inherited values."""
    return {"schema": POLICY, "explicit_environment": explicit_environment(spec),
            "normalized_explicit_environment": normalized_explicit_environment(spec), "forced_environment": dict(FORCED),
            "private_worker_runtime": {key: parent[key] for key in sorted(RUNTIME_NAMES) if key in parent},
            "private_runtime_preserved": all(actual.get(key) == value for key, value in parent.items() if key in RUNTIME_NAMES),
            "cleared_inherited_names": sorted(key for key in parent if key not in actual),
            "execution_metadata_preserved": all(actual.get(key) == value for key, value in parent.items() if key.startswith("SARA_"))}
