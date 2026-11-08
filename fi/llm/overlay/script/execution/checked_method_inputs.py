"""Shared own-input validation, independent of either method's analyzer imports.

The validation body is retained verbatim from sara_batch_campaign. This module
only removes an unused SARA analyzer import from the GEREM input path.
"""
from pathlib import Path

from script.execution.compact_population import DOMAIN_SCHEMA, SemanticPopulation, read_inventory

def checked_inputs(path, *, analysis=True):
    from script.execution.method_input_context import file_digest, read_json
    path = Path(path).resolve(strict=True)
    value = read_json(path)
    schemas = {"sara-batch-inputs-v1", "sara-batch-inputs-v2"} if analysis else {
        "sara-batch-inputs-v1", "sara-population-inputs-v1", "sara-batch-inputs-v2", "sara-population-inputs-v2"}
    if value.get("schema") not in schemas:
        raise ValueError("explicit batch input schema required")
    paths = {}
    required = {"inventory", "output_spec"} | ({"trace"} if analysis else set())
    allowed = required | {"trace", "cache_ledger", "trace_sidecar", "initial_global_image"}
    if not required.issubset(value["files"]) or set(value["files"]) - allowed:
        raise ValueError("unsupported or incomplete analysis input roles")
    for role in sorted(value["files"]):
        if not analysis and not value["schema"].endswith("-v2") and role not in required: continue
        item = value["files"][role]
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("portable input paths must remain within the input bundle")
        source = path.parent / relative
        if file_digest(source) != item["sha256"]:
            raise ValueError("input file hash changed: " + role)
        paths[role] = source
    inventory, population = read_inventory(paths["inventory"])
    if value["schema"].endswith("-v2"):
        if (not isinstance(population, SemanticPopulation)
                or value.get("population_identity_kind") != DOMAIN_SCHEMA
                or value.get("population_fingerprint") != population.identity
                or value.get("population_mass") != population.mass):
            raise ValueError("own compact population descriptor identity/mass disagreement")
    if value["schema"].endswith("-v2"):
        component = population.component
    else:
        if len({row["component"] for row in population.spans}) != 1:
            raise ValueError("one actual component per condition is required")
        component = population.spans[0]["component"]
    if analysis and component in ("l1d", "l2") and not {"cache_ledger", "trace_sidecar"}.issubset(paths):
        raise ValueError("actual cache state/transport and trace close inputs required")
    return value, paths, inventory, population
