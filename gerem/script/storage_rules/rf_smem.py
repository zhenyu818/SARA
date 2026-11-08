"""Independent, deliberately linear GEREM storage-EFM reproduction.

The method's III-A and IV allow one profiling run and reuse of its raw traces.
They do not describe interval indexes, query reuse, SIC memoization, branch
weights, loop bounds, or a multiple-consumer probability rule.  This module
therefore retains the decoded input once and scans it afresh for every draw.
No current/legacy GEREM answer or SIC helper is imported.

The user subsequently authorized a plain implementation of details not stated
in the method, following its method and principles, without claiming access to
the unpublished original code.  The explicit reproduction choices are: use the
first effective future shared reader, begin SIC at its next static instruction,
multiply by 0.5 at min/max and potentially data-dependent conditional branches,
give multiple CFG successors equal weight, and solve the resulting equations
by ordinary fixed-point iteration.  With no source/destination metadata, the
static syntactic mask rule is used; unrelated dynamic dataflow is not inferred.
These are declared reproduction choices, not rules specified by the authors.
There is no matrix exponentiation, fixed 256-step path truncation, persistent
SIC cache, precomputed lifetime index, or warm query reuse.

Cycle coordinates denote the storage state after accesses at that cycle.  Thus
accesses at the fault cycle establish its current value but are not future
consumers.  The caller must supply the same convention as its canonical FI
manifest.  Allocator-birth records supplied by the own-input reader establish
valid lifetimes even before the first PTX write.
"""

from collections.abc import Mapping
import json
from pathlib import Path


SUPPORTED_SUBSET = {
    "lookup": "fresh_linear_raw_event_scan_per_trial",
    "rf": "valid_future_read_before_overwrite",
    "smem": "valid_future_read_before_overwrite",
    "sic": "plain_static_CFG_fixed_point_v1",
    "masking_probability": 0.5,
    "known_masking_opcodes": ["min", "max", "potentially_data_dependent_conditional_branch"],
    "reproduction_choices_not_stated_in_method": {
        "consumer": "first_effective_future_read_before_overwrite",
        "start": "instruction_after_the_first_shared_load",
        "dependency": "syntactic_static_masking_without_inferred_taint",
        "branch_paths": "equal_weight_per_distinct_CFG_successor",
        "unconditional_single_successor_branch": "coefficient_one",
        "cycles": "plain_lower_upper_fixed_point_iteration",
        "termination": "all_reachable_regions_must_have_a_path_to_explicit_return",
    },
    "independent_due_prediction": False,
}

SIC_RESIDUAL_TOLERANCE = 1e-12
SIC_MAX_ITERATIONS = 1_000_000


def _coordinate(value):
    """No float truncation or bool-as-integer in physical coordinates."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError:
            return None
        return result if result >= 0 else None
    return None


def _required_coordinate(value, label):
    result = _coordinate(value)
    if result is None:
        raise ValueError("invalid " + label)
    return result


def _answer(efm, probability, status, reason):
    return {
        "efm": efm, "p_sdc": probability, "support_status": status,
        "reason": reason,
        "outcome": ("Unknown" if probability is None else
                    "Masked" if probability == 0.0 else
                    "SDC" if probability == 1.0 else None),
        # The method ignores rare crashes for these storage predictions.  It
        # does not independently demonstrate a zero physical DUE probability.
        "independent_due_prediction": False,
    }


def _unmapped(reason):
    return _answer(None, None, "unmapped", reason)


def _bounds(space):
    window = space.get("window", space.get("cycle_bounds"))
    if window is not None:
        first = _required_coordinate(window.get("first_cycle"), "first cycle")
        stop = _required_coordinate(window.get("cycle_stop"), "cycle stop")
    else:
        rows = space.get("cycles")
        if rows is None:
            path = space.get("cycles_file")
            if not isinstance(path, (str, Path)):
                raise ValueError("explicit complete storage cycle bounds required")
            path = Path(path)
            text = path.read_text(encoding="utf-8")  # Once per model, never per draw.
            if path.suffix.lower() == ".json":
                value = json.loads(text)
                rows = value.get("cycles") if isinstance(value, Mapping) else value
            else:
                rows = [{"cycle": line.split()[0]} for line in text.splitlines()
                        if line.strip() and not line.lstrip().startswith("#")]
        if not isinstance(rows, list) or not rows:
            raise ValueError("nonempty explicit storage cycle rows required")
        cycles = []
        for row in rows:
            value = row.get("cycle") if isinstance(row, Mapping) else row[0] if isinstance(row, list) and row else row
            cycles.append(_required_coordinate(value, "storage cycle"))
        first, stop = min(cycles), max(cycles) + 1
    if stop <= first:
        raise ValueError("empty or reversed storage cycle window")
    return first, stop


class NaiveStorageEFM:
    """Raw own trace + canonical sites, with no precomputed lifetime index.

    ``trace['events']`` uses the decoded own RF def/use or shared access schema.
    ``static_trace`` optionally uses ``{'events': [pc/kind/opcode/CFG/...]} ``.
    No simulation outcome, FI label, sampler, SARA result, or prepared GEREM
    answer is accepted.  Own capture identity/completeness belongs to the input
    reader; this class checks event order, coordinates, and mapped lifetimes.
    """

    def __init__(self, trace, sampling_space, static_trace=None):
        if not isinstance(trace, Mapping) or not isinstance(trace.get("events"), list):
            raise ValueError("decoded raw own events required")
        if not isinstance(sampling_space, Mapping):
            raise ValueError("sampling_space must be an object")
        self.trace, self.sampling_space = trace, sampling_space
        self.events = trace["events"]
        self.first_cycle, self.cycle_stop = _bounds(sampling_space)
        previous = -1
        for row in self.events:
            if not isinstance(row, Mapping):
                raise ValueError("raw event must be an object")
            cycle = _required_coordinate(row.get("cycle"), "event cycle")
            if cycle < previous:
                raise ValueError("own trace lost its chronological order")
            previous = cycle
        if static_trace is not None and (not isinstance(static_trace, Mapping)
                                        or not isinstance(static_trace.get("events"), list)):
            raise ValueError("static_trace must contain raw static events")
        self.static_trace = static_trace
        self.sic_tolerance = SIC_RESIDUAL_TOLERANCE
        self.sic_max_iterations = SIC_MAX_ITERATIONS

    def query(self, trial):
        # Deliberately do not catch exceptions around scientific code.  Invalid
        # user coordinates are mapping failures; corrupt profiles/programming
        # errors must remain visible to the controller and preserve evidence.
        if not isinstance(trial, Mapping) or not isinstance(trial.get("target"), Mapping):
            return _unmapped("canonical_trial_target_required")
        cycle, bit = _coordinate(trial.get("cycle")), _coordinate(trial.get("bit"))
        if cycle is None or bit is None:
            return _unmapped("invalid_fault_coordinate")
        if not self.first_cycle <= cycle < self.cycle_stop:
            return _unmapped("fault_outside_explicit_storage_window")
        if trial.get("component") == "rf":
            return self._rf(trial["target"], cycle, bit)
        if trial.get("component") == "smem":
            return self._smem(trial["target"], cycle, bit)
        return _unmapped("unsupported_storage_component")

    @staticmethod
    def _same_kernel(row, target):
        actual, expected = row.get("kernel_uid"), target.get("kernel")
        return actual is None or expected is None or _required_coordinate(actual, "event kernel") == _required_coordinate(expected, "target kernel")

    def _rf(self, target, cycle, bit):
        thread, width = _coordinate(target.get("thread")), _coordinate(target.get("width_bits"))
        name = target.get("register", target.get("reg"))
        uid_value = target.get("register_uid", target.get("reg_uid"))
        uid = _coordinate(uid_value) if uid_value is not None else None
        if thread is None or width is None or width == 0 or not isinstance(name, str) or not name:
            return _unmapped("missing_register_identity_or_width")
        if uid_value is not None and uid is None:
            return _unmapped("invalid_register_uid")
        if bit >= width:
            return _unmapped("bit_outside_declared_register")
        current, first_consumer = None, None
        for row in self.events:
            if row.get("thread_id") != thread or not self._same_kernel(row, target):
                continue
            event_cycle = _required_coordinate(row["cycle"], "event cycle")
            if event_cycle >= self.cycle_stop:
                break
            source_names = row.get("src_regs", [])
            source_uids = row.get("src_reg_uids", [])
            if not isinstance(source_names, list) or not isinstance(source_uids, list):
                raise ValueError("RF source identity arrays required")
            if source_uids and len(source_uids) != len(source_names):
                raise ValueError("RF source names/UIDs have different lengths")
            writes = row.get("dst_reg") == name
            if event_cycle <= cycle:
                if writes:
                    current = row
                continue
            if current is None:
                return _unmapped("missing_register_lifetime_at_fault")
            actual_uid = current.get("dst_reg_uid")
            if uid is not None and (actual_uid is None or _coordinate(actual_uid) != uid):
                return _unmapped("register_uid_mismatch_or_unrecorded")
            # For an instruction which both reads and writes the register, the
            # read consumes the old value before that instruction overwrites it.
            for offset, source in enumerate(source_names):
                if source == name:
                    if uid is not None and (not source_uids or _coordinate(source_uids[offset]) != uid):
                        return _unmapped("future_register_consumer_uid_mismatch_or_unrecorded")
                    first_consumer = row
                    break
            if first_consumer is not None or writes:
                break
        if current is None:
            return _unmapped("missing_register_lifetime_at_fault")
        if uid is not None and _coordinate(current.get("dst_reg_uid")) != uid:
            return _unmapped("register_uid_mismatch_or_unrecorded")
        if first_consumer is not None:
            return _answer("dcr", 1.0, "method_supported", "valid_register_value_consumed_before_overwrite")
        return _answer("benign", 0.0, "method_supported", "register_value_not_consumed_before_overwrite_or_end")

    @staticmethod
    def _shared_access(row, target, address):
        if row.get("mem_space") not in ("shared", "smem"):
            return None
        if row.get("sm_id") != target["sm"] or row.get("cta_id") != target["cta_id"]:
            return None
        # The own shared-input reader verifies the persistent allocator object
        # and (SM, CTA, byte) scope.  target.kernel is canonical fault metadata,
        # not a lifetime reset: a value written in one kernel can remain in the
        # same actual object and be consumed by another.  SIC below separately
        # uses the selected consumer's kernel UID to resolve its static PC.
        kind = row.get("kind")
        if kind not in ("load", "store"):
            raise ValueError("shared access must be an explicit load or store")
        start = _required_coordinate(row.get("mem_addr"), "shared access address")
        size_key = "load_size_bytes" if kind == "load" else "store_size_bytes"
        size = _required_coordinate(row.get(size_key, row.get("mem_access_size_bytes")), "shared access size")
        if size == 0:
            raise ValueError("zero-length shared access")
        return kind if start <= address < start + size else None

    def _smem(self, target, cycle, bit):
        scope = {key: _coordinate(target.get(key)) for key in ("sm", "cta_id", "byte_addr")}
        if any(value is None for value in scope.values()):
            return _unmapped("missing_shared_scope_or_byte_identity")
        if bit // 8 != scope["byte_addr"]:
            return _unmapped("shared_bit_and_byte_identity_disagree")
        canonical_target = dict(target, **scope)
        current, first_consumer = None, None
        for row in self.events:
            event_cycle = _required_coordinate(row["cycle"], "event cycle")
            if event_cycle >= self.cycle_stop:
                break
            kind = self._shared_access(row, canonical_target, scope["byte_addr"])
            if kind is None:
                continue
            if event_cycle <= cycle:
                if kind == "store":
                    current = row
                continue
            if current is None:
                return _unmapped("missing_shared_lifetime_at_fault")
            if kind == "store":
                break
            first_consumer = row
            break
        if current is None:
            return _unmapped("missing_shared_lifetime_at_fault")
        if first_consumer is None:
            return _answer("benign", 0.0, "method_supported", "shared_value_not_consumed_before_overwrite_or_end")
        # A first-reader EFM is an explicit reproduction choice.  Do not union
        # reader probabilities or infer cancellation among later consumers.
        probability, reason, details, status = self._sic(first_consumer)
        answer = _answer("dcr", probability, status, reason)
        answer["sic_diagnostics"] = dict(details,
            consumer_selection="first_effective_future_read_before_overwrite",
            selected_consumer_cycle=first_consumer["cycle"],
            selected_consumer_pc=first_consumer.get("pc"))
        return answer

    def _instruction(self, pc, consumer):
        found = None
        for row in self.static_trace["events"]:
            if not isinstance(row, Mapping):
                raise ValueError("static instruction must be an object")
            if _required_coordinate(row.get("pc"), "static PC") != pc:
                continue
            if not self._same_kernel(row, {"kernel": consumer.get("kernel_uid")}):
                continue
            if found is not None:
                raise ValueError("ambiguous static PC in the own program")
            found = row
        return found

    def _sic(self, consumer):
        if self.static_trace is None:
            return None, "complete_static_program_not_supplied_for_SMEM_SIC", {}, "unmapped"
        start = _coordinate(consumer.get("pc"))
        if start is None:
            return None, "shared_consumer_static_PC_not_recorded", {}, "unmapped"
        load = self._instruction(start, consumer)
        if load is None:
            return None, "shared_consumer_missing_from_static_program", {}, "unmapped"
        if load.get("next_pc") is None:
            return None, "shared_load_has_no_explicit_next_static_instruction", {}, "unsupported_static_program"
        start = _required_coordinate(load["next_pc"], "shared-load successor")
        # Build only a per-query reachable raw CFG list.  Every PC resolution
        # is a linear search; this is not a stored answer/index for later draws.
        pending, nodes = [start], []
        while pending:
            pc = pending.pop()
            if any(node["pc"] == pc for node in nodes):
                continue
            row = self._instruction(pc, consumer)
            if row is None:
                return None, "static_path_has_missing_successor", {}, "unsupported_static_program"
            kind = row.get("kind", "inst")
            opcode = row.get("opcode", "")
            if not isinstance(opcode, str):
                raise ValueError("static opcode must be a string")
            base = opcode.lower().split(".", 1)[0]
            is_branch = kind == "branch" or base in ("bra", "brx")
            if kind == "ret" or base in ("ret", "exit"):
                nodes.append({"pc": pc, "terminal": True, "coefficient": 1.0, "successors": []})
                continue
            if base in ("call", "callp", "retp", "brx", "trap"):
                return None, "interprocedural_or_indirect_static_path_not_supported", {}, "unsupported_static_program"
            keys = ("taken_target_pc", "fallthrough_pc") if is_branch else ("next_pc",)
            successors = []
            for key in keys:
                if row.get(key) is not None:
                    successor = _required_coordinate(row[key], "static successor")
                    if successor not in successors:
                        successors.append(successor)
            if not successors:
                return None, "static_path_has_no_explicit_termination", {}, "unsupported_static_program"
            conditional = is_branch and (len(successors) > 1 or row.get("has_predicate") is True)
            coefficient = 0.5 if base in ("min", "max") or conditional else 1.0
            nodes.append({"pc": pc, "terminal": False, "coefficient": coefficient,
                          "successors": successors})
            for successor in successors:
                pending.append(successor)
        terminal_pcs = [node["pc"] for node in nodes if node["terminal"]]
        if not terminal_pcs:
            return None, "reachable_static_program_has_no_explicit_terminal", {}, "unsupported_static_program"
        reaches_terminal = list(terminal_pcs)
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node["pc"] not in reaches_terminal and any(pc in reaches_terminal for pc in node["successors"]):
                    reaches_terminal.append(node["pc"])
                    changed = True
        if len(reaches_terminal) != len(nodes):
            return None, "reachable_static_region_has_no_terminal_path", {}, "unsupported_static_program"
        if (type(self.sic_max_iterations) is not int or self.sic_max_iterations < 1
                or not isinstance(self.sic_tolerance, (int, float))
                or isinstance(self.sic_tolerance, bool) or not 0 < self.sic_tolerance < 1):
            raise ValueError("invalid explicit SIC numerical controls")

        def previous_value(values, wanted_pc):
            for offset, node in enumerate(nodes):
                if node["pc"] == wanted_pc:
                    return values[offset]
            raise ValueError("reachable CFG lost an explicit successor")

        # Monotone lower/upper bounds exclude premature success at a small
        # iterate residual.  Requiring both their gap and residual <= tolerance
        # makes the returned probability error explicit even for slow loops.
        lower = [1.0 if node["terminal"] else 0.0 for node in nodes]
        upper = [1.0 for _node in nodes]
        residual, gap = 1.0, 1.0
        for iteration in range(1, self.sic_max_iterations + 1):
            next_lower, next_upper = [], []
            for node in nodes:
                if node["terminal"]:
                    lo = hi = 1.0
                else:
                    count = len(node["successors"])
                    lo = node["coefficient"] * sum(previous_value(lower, pc) for pc in node["successors"]) / count
                    hi = node["coefficient"] * sum(previous_value(upper, pc) for pc in node["successors"]) / count
                next_lower.append(lo)
                next_upper.append(hi)
            residual = max(max(abs(a - b) for a, b in zip(next_lower, lower)),
                           max(abs(a - b) for a, b in zip(next_upper, upper)))
            gap = max(hi - lo for lo, hi in zip(next_lower, next_upper))
            lower, upper = next_lower, next_upper
            if residual <= self.sic_tolerance and gap <= self.sic_tolerance:
                lo, hi = previous_value(lower, start), previous_value(upper, start)
                details = {"iterations": iteration, "residual": residual,
                    "solution_bound_width": gap, "start_lower_bound": lo,
                    "start_upper_bound": hi, "tolerance": self.sic_tolerance,
                    "max_iterations": self.sic_max_iterations, "reachable_static_nodes": len(nodes),
                    "branch_successor_weights": "equal", "converged": True}
                return (lo + hi) / 2.0, "declared_naive_static_SIC_reproduction_choices", details, "method_guided_naive_reproduction"
        details = {"iterations": self.sic_max_iterations, "residual": residual,
            "solution_bound_width": gap, "tolerance": self.sic_tolerance,
            "max_iterations": self.sic_max_iterations, "reachable_static_nodes": len(nodes),
            "branch_successor_weights": "equal", "converged": False}
        return None, "static_SIC_fixed_point_did_not_converge", details, "numerical_unconverged"
