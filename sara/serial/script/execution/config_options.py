"""Deterministic GPGPU-Sim option replacement, without execution side effects."""


def config_text(base, options):
    lines = [line for line in base.splitlines()
             if not (line.strip() and line.split()[0] in options)]
    lines.extend("{} {}".format(key, value) for key, value in options.items())
    return "\n".join(lines) + "\n"
