"""Bind reusable CUDA artifacts to all benchmark sources and compiler flags."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from script.execution.campaign import atomic_json, fingerprint
from script.execution.policy import require_container_execution

ROOT = Path(__file__).resolve().parents[2]
SOURCE_SUFFIXES = {".cu", ".cuh", ".h", ".hpp", ".cc", ".cpp", ".c", ".py", ".json"}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_spec(apps_root, app, arch, nvcc="nvcc"):
    if Path(app).name != app or not (Path(apps_root) / app).is_dir():
        raise ValueError("invalid application directory")
    files = {}
    for directory in (Path(apps_root) / app, Path(apps_root) / "common"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in SOURCE_SUFFIXES and not set(path.parts).intersection(
                    {"result", ".local", "__pycache__"}):
                files[str(path.relative_to(apps_root))] = digest(path)
    files["extract_registers.py"] = digest(ROOT / "extract_registers.py")
    require_container_execution()
    compiler = subprocess.check_output([nvcc, "--version"], text=True)
    return {"app": app, "gpu_arch": arch, "sources": files, "compiler_version": compiler,
            "binary_flags": ["-std=c++14", "--cudart=shared", "-g", "-lcudart", "-arch=" + arch],
            "ptx_flags": ["-std=c++14", "-ptx", "-g", "-lineinfo", "-arch=" + arch]}


def outputs(cache, app):
    required = [Path(cache) / app, Path(cache) / (app + ".ptx"), Path(cache) / "register_used.txt"]
    required.extend(sorted((Path(cache) / "result_generators").glob("gen_*")))
    return {str(path.relative_to(cache)): digest(path) for path in required}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["write", "verify"])
    parser.add_argument("--apps-root", type=Path, default=ROOT / "test_apps")
    parser.add_argument("--app", required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--gpu-arch", required=True)
    args = parser.parse_args()
    expected = build_spec(args.apps_root, args.app, args.gpu_arch)
    metadata = {"schema_version": 1, "build": expected, "build_fingerprint": fingerprint(expected),
                "artifacts": outputs(args.cache, args.app)}
    target = args.cache / "build_identity.json"
    if args.action == "write":
        atomic_json(target, metadata)
    elif not target.is_file() or json.loads(target.read_text()) != metadata:
        raise ValueError("stale or unverified benchmark prebuild; rebuild before use")


if __name__ == "__main__":
    main()
