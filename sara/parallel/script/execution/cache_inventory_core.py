"""Complete actual physical cache population; no per-origin planner or predictor."""
import re
from script.execution.memory_effect_records import integer
from script.execution.fault_manifest import FaultPopulation


def _configuration_records(text):
    """Read scalar records with the actual option_parser.cc lexical rules.

    ParseFile strips each physical line at its FIRST # even inside quotes;
    ParseStringStream collapses whitespace and groups only double-quoted
    tokens. Shell escapes/single quotes are not a second config language.
    Raw spans are retained so filtering never reserializes scientific values.
    """
    if not isinstance(text, str) or "\0" in text:
        raise ValueError("ordinary configuration text required")
    raw = "\n".join(text.splitlines()) + "\n"
    masked = []
    for line in raw.splitlines(keepends=True):
        active, marker, comment = line.partition("#")
        masked.append(active + (" " * (len(marker) + len(comment.rstrip("\n"))) + "\n" if marker else ""))
    words = list(re.finditer(r"\S+", "".join(masked)))
    tokens, position = [], 0
    while position < len(words):
        first = words[position]; value = first.group(); last = first; position += 1
        quoted = value.startswith('"')
        if quoted:
            # The C++ parser cannot safely consume a standalone quote token.
            if value == '"': raise ValueError("ambiguous configuration quote")
            while not last.group().endswith('"') and position < len(words):
                last = words[position]; value += " " + last.group(); position += 1
            if len(value) < 2 or not value.endswith('"') or '"' in value[1:-1]:
                raise ValueError("unclosed or ambiguous configuration quote")
            value = value[1:-1]
        elif '"' in value:
            raise ValueError("ambiguous configuration quote")
        tokens.append((value, first.start(), last.end(), quoted))
    records, seen = [], set()
    for position in range(0, len(tokens), 2):
        key, start, _stop, quoted = tokens[position]
        if quoted or re.fullmatch(r"-[A-Za-z_][A-Za-z0-9_:.-]*", key) is None or key in seen:
            raise ValueError("ambiguous or duplicate effective configuration option")
        if position + 1 == len(tokens):
            raise ValueError("incomplete effective configuration option")
        value, _start, stop, quoted_value = tokens[position + 1]
        if not quoted_value and re.fullmatch(r"-[A-Za-z_][A-Za-z0-9_:.-]*", value):
            raise ValueError("incomplete effective configuration option")
        seen.add(key); records.append((key, value, start, stop))
    return raw, records


def _options(text):
    return {key: value for key, value, _start, _stop in _configuration_records(text)[1]}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def topology_from_config(text):
    # Reuse the actual option-parser-compatible record reader, including the
    # shipped multiline DRAM values. No expected arch label supplies topology.
    options = _options(text)
    values = []
    for name in ("-gpgpu_n_clusters", "-gpgpu_n_cores_per_cluster", "-gpgpu_n_mem",
                 "-gpgpu_n_sub_partition_per_mchannel"):
        value = options.get(name)
        require(isinstance(value, str) and value.isdecimal() and int(value) > 0,
                "actual_explicit_cache_topology_required:" + name)
        values.append(int(value))
    return dict(clusters=values[0], cores_per_cluster=values[1], l2_banks=values[2]*values[3])


def _owner_at(residencies, key, cycle):
    rows = [row for row in residencies["owner_views"] if row["owner_key"] == key
            and row["start_cycle"] <= cycle < row["end_cycle"]]
    require(len(rows) == 1, "unique_actual_owner_view_required")
    return rows[0]["view"]


def _inventory(residencies, topology, *, execution_metadata=True, component=None):
    if type(execution_metadata) is not bool or (component is not None and
            (execution_metadata or component not in {"l1d", "l2"})):
        raise ValueError("explicit compact per-component population mode required")
    for key in ("clusters", "cores_per_cluster", "l2_banks"):
        integer(topology.get(key), positive=True)
    expected = {"l1d:"+str(i) for i in range(topology["clusters"]*topology["cores_per_cluster"])}
    expected |= {"l2:"+str(i) for i in range(topology["l2_banks"])}
    require({row["owner_key"] for row in residencies["owner_views"]} == expected,
            "all_actual_owners_must_match_explicit_config_topology")
    owners={}
    def owner_at(key,cycle):
        token=(key,cycle)
        if token not in owners: owners[token]=_owner_at(residencies,key,cycle)
        return owners[token]
    # Geometry belongs to the owner, not every per-line state change. Check
    # every owner transition once, including disabled and otherwise empty time.
    for cycle in sorted({row["start_cycle"] for row in residencies["owner_views"]
                         if row["view"]["component"] == "l2"}):
        views=[owner_at("l2:"+str(bank),cycle) for bank in range(topology["l2_banks"])]
        if all(row["disabled"] for row in views): continue
        require(all(not row["disabled"] and row["active_lines"] == views[0]["active_lines"]
                    and row["line_bytes"] == views[0]["line_bytes"] for row in views),
                "actual_L2_hook_geometry_not_uniform")
    spans = []
    for row in residencies["residency_spans"]:
        current, owner, copy = row["component"], row["scope"], row["copy"]
        if component is not None and current != component:
            continue
        view = owner_at(row["owner_key"], row["start_cycle"])
        bits = 57 + copy["line_bytes"]*8
        if current == "l1d":
            cluster, core = divmod(owner, topology["cores_per_cluster"])
            target = dict(cluster=cluster, core=core, sm=owner, line=copy["line"],
                          line_size_bytes=copy["line_bytes"], tag_bits=57)
            first = copy["line"]*bits
            if execution_metadata:
                hooks = {"-l1d_shader_rand_n": str(owner)}
                ack = dict(component=current, cluster=str(cluster), core=str(core), line=str(copy["line"]))
        else:
            # L2's actual hook decodes one flattened bank/line bit index. All
            # banks must use this same active geometry at this original hook.
            target = dict(bank=owner, line=copy["line"], lines_per_bank=view["active_lines"],
                          line_size_bytes=copy["line_bytes"], tag_bits=57)
            first = (owner*view["active_lines"] + copy["line"])*bits
            if execution_metadata:
                hooks = {"-kernel_n": "0"}  # same unrestricted all-kernel hook
                ack = dict(component=current, bank=str(owner), line=str(copy["line"]))
        # NO validity/future-use filter. State changes may split intervals but
        # every allocated physical line still contributes every tag+data bit.
        span = dict(component=current, target=target, cycle_start=row["start_cycle"],
                    cycle_stop=row["end_cycle"], bit_start=first, bit_count=bits)
        if execution_metadata:
            span.update(hook_selectors=hooks, ack_expected=ack)
        spans.append(span)
    inventory = dict(schema_version=1, population_id="neutral-actual-cache-hook-storage-v1",
        fault_model="all-active-physical-cache-tag57-and-data-single-bit-v1",
        coordinate_system="simulator_physical_cache_slots", time_basis="simulator_global_cycle",
        coverage_certified=False, mapping_certified=False, spans=spans)
    # The existing canonical sampler validates overlaps and metadata. The
    # first pilot deliberately refuses variable geometry metadata, rather than
    # changing that contract or dropping epochs until a separate reviewed delta.
    if execution_metadata:
        population = FaultPopulation(inventory)
        require(population.mass == residencies["bit_cycles"], "physical_population_raw_mass_disagrees")
    else:
        from script.execution.compact_population import semantic_population
        population = semantic_population(inventory)
        raw_mass = sum((row["end_cycle"] - row["start_cycle"]) *
                       (57 + 8 * row["copy"]["line_bytes"])
                       for row in residencies["residency_spans"])
        require(raw_mass == residencies["bit_cycles"], "physical_population_raw_mass_disagrees")
        selected_mass = sum((row["cycle_stop"] - row["cycle_start"]) * row["bit_count"] for row in spans)
        require(population.mass == selected_mass, "compact_physical_population_mass_disagrees")
    return inventory, population
