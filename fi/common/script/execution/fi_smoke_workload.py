"""Fixed method workloads and complete typed observables for FI-only smoke.

The original fourteen registry is unchanged. The sole additional workload is
the retained trained Stories260K two-position complete forward. No model fetch,
sampling, predictor, simulator launch, or campaign admission happens on import.
"""
import math
from pathlib import Path
import re
import struct

from script.common.outcome_oracle import RAW_OUTPUT_RE, validate_raw_outputs
from script.execution.batch_workload import contract as original_contract
from script.execution.workload_contracts import MINIMAL


LLM_CASE = "llm-stories260k-prefix2"
LLM_APP = "LLM_TinyStories260K"
LLM_CHECKPOINT = "stories260K.bin"
LLM_GPU_MARKER = ("GPUFI_LLM_FORWARD version=2 model=Stories260K batch=1 tokens=2 "
    "input_tokens=1,42 positions=0,1 final_position=1 layers=5 "
    "expected_computational_launches=144 precision=fp32")
LLM_CPU_MARKER = ("GPUFI_LLM_CPU_FORWARD version=2 model=Stories260K batch=1 tokens=2 "
    "input_tokens=1,42 positions=0,1 final_position=1 layers=5 precision=fp32")
LLM_SCOPE_MARKER = ("GPUFI_LLM_OUTPUT_SCOPE logits=device_forward greedy_next=host_argmax "
    "final_position=1 intermediate_logits_output=0 feedback_to_gpu=0")
ORIGINAL_ORDER = ("spmm-empty-and-tail", "layernorm-full-gpu", "attention-full-gpu",
    "stencil-boundary", "convolution-boundary", "softmax-stable", "gelu-bias",
    "gemm-nonsquare", "matrixmul-edge-tiles", "adamw-independent-state",
    "pathfinder-multilaunch", "dijkstra-diamond", "mf-colliding-ratings", "render-ray-casting")
SMOKE_CASES = ORIGINAL_ORDER + (LLM_CASE,)


def contract(case):
    if case != LLM_CASE:
        if case not in MINIMAL:
            raise ValueError("one authorized original14 or final Stories260K smoke case required")
        row = original_contract(case)
    else:
        row = {"case": LLM_CASE, "app": LLM_APP, "arguments": [LLM_CHECKPOINT],
            "env_files": {}, "input_token_ids": [1, 42], "positions": [0, 1],
            "full_forward_calls": 2, "layers_per_forward": 5,
            "expected_computational_launches": 144,
            "outputs": [{"name": "logits", "dtype": "f32", "count": 512, "bytes": 2048},
                        {"name": "greedy_next", "dtype": "i32", "count": 1, "bytes": 4}]}
    row["typed_output_contract"] = typed_contract(case)
    return row


def typed_contract(case):
    rows = ([{"name": "logits", "dtype": "f32", "count": 512, "bytes": 2048},
             {"name": "greedy_next", "dtype": "i32", "count": 1, "bytes": 4}]
            if case == LLM_CASE else original_contract(case)["outputs"])
    return {"schema": "sara-typed-output-contract-v1", "outputs": [
        dict({key: row[key] for key in ("name", "dtype", "count", "bytes")},
             address_kind="host_derived" if case == LLM_CASE and row["name"] == "greedy_next"
             else "device_global") for row in rows]}


def environment(case):
    row = contract(case)
    return {"SARA_VALIDATE_CPU": "0", **{key: Path(value).name
        for key, value in row["env_files"].items()}}


def packet(log, case):
    """Complete raw tensors; host addresses never become GPU allocations."""
    valid = validate_raw_outputs(Path(log))
    if not valid["valid"]:
        raise ValueError("incomplete smoke raw output: " + str(valid))
    result = {}
    for line in Path(log).read_text().splitlines():
        match = RAW_OUTPUT_RE.fullmatch(line.strip())
        if match:
            name, dtype, count, payload = match.groups()
            if name in result:
                raise ValueError("duplicate complete smoke output")
            result[name] = {"dtype": dtype, "count": int(count), "hexbytes": payload.lower()}
    expected = {row["name"]: (row["dtype"], row["count"])
                for row in typed_contract(case)["outputs"]}
    if {name: (row["dtype"], row["count"]) for name, row in result.items()} != expected:
        raise ValueError("smoke requires every fixed final observable")
    return result


def output_spec(log, case):
    # Validate each tensor's declared byte size and exact dtype/count first.
    packet(log, case)
    found = [{"base": int(base, 16), "bytes": int(size), "name": name}
        for base, size, name in re.findall(
            r"^GPUFI_OUTPUT base=(0x[0-9a-fA-F]+) bytes=(\d+) name=(\S+)\s*$",
            Path(log).read_text(), re.MULTILINE)]
    rows = {row["name"]: row for row in typed_contract(case)["outputs"]}
    if len(found) != len(rows) or {row["name"] for row in found} != set(rows):
        raise ValueError("complete typed smoke declarations required")
    for row in found:
        expected = rows[row["name"]]
        if row["bytes"] != expected["bytes"]:
            raise ValueError("smoke declared output byte size changed")
        row.update(dtype=expected["dtype"], count=expected["count"],
            space="host_derived" if expected["address_kind"] == "host_derived" else "global")
    devices = [row for row in found if row["space"] == "global"]
    if any(a["base"] < b["base"] + b["bytes"] and b["base"] < a["base"] + a["bytes"]
           for index, a in enumerate(devices) for b in devices[index + 1:]):
        raise ValueError("smoke final device allocations overlap")
    return found


def compare_llm_cpu(cpu_log, gpu_log):
    """Registered CPU tolerance for golden admission only; not FI labels."""
    cpu_text, gpu_text = Path(cpu_log).read_text(), Path(gpu_log).read_text()
    if LLM_CPU_MARKER not in cpu_text or LLM_GPU_MARKER not in gpu_text or LLM_SCOPE_MARKER not in gpu_text:
        raise ValueError("actual complete fixed-prefix CPU/GPU scope markers required")
    cpu, gpu = packet(cpu_log, LLM_CASE), packet(gpu_log, LLM_CASE)
    expected = struct.unpack("<512f", bytes.fromhex(cpu["logits"]["hexbytes"]))
    observed = struct.unpack("<512f", bytes.fromhex(gpu["logits"]["hexbytes"]))
    for index, (want, got) in enumerate(zip(expected, observed)):
        if not math.isfinite(want) or not math.isfinite(got) or abs(got-want) > 2e-4 + 2e-4 * abs(want):
            raise ValueError("registered complete LLM CPU oracle mismatch at logit %d" % index)
    for label, values, result in (("CPU", expected, cpu), ("GPU", observed, gpu)):
        # Upstream sample_argmax uses strict greater-than; ties retain first.
        selected = max(range(512), key=lambda index: values[index])
        if struct.unpack("<i", bytes.fromhex(result["greedy_next"]["hexbytes"]))[0] != selected:
            raise ValueError(label + " complete LLM host argmax disagrees with its own logits")
    if cpu["greedy_next"]["hexbytes"] != gpu["greedy_next"]["hexbytes"]:
        raise ValueError("complete LLM CPU/GPU greedy token differs")
    return {"all_final_logits_checked": 512, "atol": 2e-4, "rtol": 2e-4,
        "host_greedy_next_checked": True, "FI_uses_CPU_tolerance": False}


def actual_llm_launches(log):
    text = Path(log).read_text()
    if LLM_GPU_MARKER not in text or LLM_SCOPE_MARKER not in text:
        raise ValueError("complete LLM scope markers absent")
    identifiers = set()
    for row in re.findall(r"^kernel_launch_uid\s*=\s*([^\n]*)", text, re.MULTILINE):
        words = row.split()
        if any(not word.isdecimal() for word in words):
            raise ValueError("invalid actual LLM launch UID statistics")
        identifiers.update(int(word) for word in words)
    if len(identifiers) != 144:
        raise ValueError("actual final LLM must retain all 144 computational launches")
    return sorted(identifiers)
