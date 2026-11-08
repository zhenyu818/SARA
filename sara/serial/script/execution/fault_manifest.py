"""Canonical, reproducible bit-by-cycle sampling with replacement.

An inventory is a declared simulator fault population, not a list of observed
consumers. Dead/unallocated storage must remain in that population if the fault
model includes it. Certification of coverage and hook identity is independent
of the sampler. In particular, this module never infers physical RF allocation
from a PTX register name.
"""
import argparse
from bisect import bisect_right
import json
import re
from pathlib import Path

from script.execution.campaign import atomic_json, fingerprint, safe_id

COMPONENTS = {"rf", "smem", "l1d", "l2"}
BIT_OPTION = {"rf": "-reg_bitflip_rand_n", "smem": "-shared_mem_bitflip_rand_n",
              "l1d": "-l1d_cache_bitflip_rand_n", "l2": "-l2_cache_bitflip_rand_n"}
COMPONENT_OPTION = {"rf": "0", "smem": "2", "l1d": "3", "l2": "6"}


def location_identity(component, target):
    """Identity fields only; descriptive metadata cannot create extra sites."""
    schemas = {
        "rf": ({"thread", "register", "register_uid", "width_bits", "kernel", "sm", "cta_slot"},
               {"cta_id"}, ("thread", "register_uid")),
        "smem": ({"sm", "cta_slot", "kernel", "byte_addr"}, {"cta_id"},
                 ("sm", "cta_slot", "kernel", "byte_addr")),
        "l1d": ({"cluster", "core", "sm", "line", "line_size_bytes", "tag_bits"}, set(),
                ("cluster", "core", "line")),
        "l2": ({"bank", "line", "line_size_bytes", "tag_bits", "lines_per_bank"}, set(),
               ("bank", "line")),
    }
    required, optional, identity = schemas[component]
    if not required.issubset(target) or not set(target).issubset(required | optional):
        raise ValueError("canonical target has missing identity or unsupported metadata fields")
    for key, value in target.items():
        if key == "register":
            if not isinstance(value, str) or not re.fullmatch(r"(?:[%$][A-Za-z0-9_$]+|[A-Za-z_][A-Za-z0-9_$]*)", value):
                raise ValueError("RF identity requires a valid PTX register identifier")
        else:
            integer(value, "target." + key)
    if component in {"l1d", "l2"}:
        if target["tag_bits"] != 57 or target["line_size_bytes"] <= 0:
            raise ValueError("inventory must match the injector's 57-bit tag-first layout")
        if component == "l2" and target["lines_per_bank"] <= 0:
            raise ValueError("positive L2 lines per bank required")
    return tuple(target[k] for k in identity)


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(name + " must be an integer >= " + str(minimum))
    return value


class FaultPopulation:
    def __init__(self, inventory):
        if not isinstance(inventory, dict) or inventory.get("schema_version") != 1:
            raise ValueError("unsupported fault inventory schema")
        for name in ("population_id", "fault_model", "coordinate_system", "time_basis"):
            if not isinstance(inventory.get(name), str) or not inventory[name]:
                raise ValueError("inventory requires " + name)
        if inventory["time_basis"] != "simulator_global_cycle":
            raise ValueError("only explicit simulator_global_cycle coordinates are supported")
        self.inventory = inventory
        self.identity = fingerprint(inventory)
        self.spans = inventory.get("spans")
        if not isinstance(self.spans, list) or not self.spans:
            raise ValueError("empty fault population")
        self.ends = []
        self.mass = 0
        groups = {}
        target_contracts = {}
        for span in self.spans:
            if not isinstance(span, dict) or span.get("component") not in COMPONENTS:
                raise ValueError("unknown storage component")
            start = integer(span.get("cycle_start"), "cycle_start")
            stop = integer(span.get("cycle_stop"), "cycle_stop", 1)
            first = integer(span.get("bit_start", 0), "bit_start")
            width = integer(span.get("bit_count"), "bit_count", 1)
            if stop <= start:
                raise ValueError("cycle intervals are half open and nonempty")
            target = span.get("target")
            if not isinstance(target, dict) or not target:
                raise ValueError("resolved storage target is required")
            if "cycle" in target or "bit" in target:
                raise ValueError("cycle/bit belong to span coordinates, not target")
            hooks = span.get("hook_selectors")
            if not isinstance(hooks, dict) or not hooks:
                raise ValueError("explicit verified hook selectors are required")
            if any(not isinstance(k, str) or not k.startswith("-") or
                   not isinstance(v, str) or any(c.isspace() for c in v)
                   for k, v in hooks.items()):
                raise ValueError("hook selectors must be single-token configuration options")
            forbidden = {"-total_cycle_rand", "-components_to_flip", *BIT_OPTION.values()}
            if forbidden.intersection(hooks):
                raise ValueError("dynamic cycle/component/bit options cannot be fixed selectors")
            if span["component"] == "rf":
                declared = integer(target.get("width_bits"), "RF declared width", 1)
                if declared not in {1, 8, 16, 32, 64, 128} or first + width > declared:
                    raise ValueError("RF bit range exceeds its declared simulator register width")
            key = (span["component"], location_identity(span["component"], target))
            if key in target_contracts and target_contracts[key] != target:
                raise ValueError("inconsistent metadata for the same canonical storage location")
            target_contracts[key] = target
            # Overlapping time AND bit ranges duplicate a site and bias sampling.
            # Different lifetimes of the same location may be adjacent.
            groups.setdefault(key, []).append((start, stop, first, first + width))
            self.mass += (stop - start) * width
            self.ends.append(self.mass)
        # Method inventories use one fixed bit window per physical location.
        # Check their time intervals once after sorting, without repeatedly
        # scanning the growing history. Keep the original span order, mass,
        # fingerprint and sampler unchanged. Mixed bit windows retain the
        # literal rectangle-overlap check used by the general interface.
        for prior in groups.values():
            if len(prior) < 2:
                continue
            bits = prior[0][2:]
            if all(row[2:] == bits for row in prior):
                previous_stop = None
                for start, stop, _, _ in sorted(prior):
                    if previous_stop is not None and start < previous_stop:
                        raise ValueError("overlapping canonical fault population spans")
                    previous_stop = stop
            else:
                for i, (start, stop, first, last) in enumerate(prior):
                    for j in range(i):
                        a, b, c, d = prior[j]
                        if max(a, start) < min(b, stop) and max(c, first) < min(d, last):
                            raise ValueError("overlapping canonical fault population spans")
        if self.mass > 2 ** 256:
            raise ValueError("population exceeds sampler range")

    def resolve(self, rank):
        integer(rank, "rank")
        if rank >= self.mass:
            raise ValueError("rank outside fault population")
        index = bisect_right(self.ends, rank)
        span = self.spans[index]
        local = rank - (self.ends[index - 1] if index else 0)
        cycle_delta, bit_delta = divmod(local, span["bit_count"])
        cycle = span["cycle_start"] + cycle_delta
        bit = span.get("bit_start", 0) + bit_delta
        site = {"population_fingerprint": self.identity, "component": span["component"],
                "target": span["target"], "cycle": cycle, "bit": bit}
        hooks = dict(span["hook_selectors"])
        hooks.update({"-total_cycle_rand": str(cycle),
                      "-components_to_flip": COMPONENT_OPTION[span["component"]],
                      BIT_OPTION[span["component"]]: str(bit + 1)})
        acknowledgement = dict(span.get("ack_expected", {}), cycle=str(cycle), bit=str(bit + 1))
        return dict(site, site_id=fingerprint(site), population_rank=rank, hook_params=hooks,
                    ack_expected=acknowledgement)

    def sample(self, count, seed, stream):
        integer(count, "count", 1)
        if type(seed) is not int or not -(2 ** 63) <= seed < 2 ** 63:
            raise ValueError("seed must be a signed 64-bit integer")
        safe_id(stream)
        # SHA-256 counter mode plus rejection is fully specified across Python
        # versions. Modulo reduction without rejection would bias the domain.
        limit = (2 ** 256 // self.mass) * self.mass
        trials = []
        for draw in range(count):
            rejection = 0
            while True:
                payload = {"algorithm": "sara-sha256-rejection-v1", "population": self.identity,
                           "seed": seed, "stream": stream, "draw": draw, "rejection": rejection}
                value = int(fingerprint(payload), 16)
                if value < limit:
                    break
                rejection += 1
            trials.append(dict(self.resolve(value % self.mass), trial_id="trial-%08d" % draw,
                               draw_index=draw))
        return {"schema_version": 1, "sampling": "with_replacement",
                "algorithm": "sara-sha256-rejection-v1", "seed": seed, "stream": stream,
                "population_fingerprint": self.identity, "population_size": self.mass,
                "population_contract": {k: self.inventory[k] for k in
                                        ("population_id", "fault_model", "coordinate_system", "time_basis")},
                "coverage_certified": self.inventory.get("coverage_certified") is True,
                "trials": trials}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--site-manifest", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--stream", required=True)
    parser.add_argument("--count", type=int, required=True)
    args = parser.parse_args()
    if args.site_manifest.exists():
        raise FileExistsError("never overwrite a published site manifest")
    population = FaultPopulation(json.loads(args.inventory.read_text()))
    atomic_json(args.site_manifest, population.sample(args.count, args.seed, args.stream))


if __name__ == "__main__":
    main()
