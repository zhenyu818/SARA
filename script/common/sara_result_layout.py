#!/usr/bin/env python3
"""Utilities for the public SARA/FI/GEREM-all result layout.

Some internal SARA tools still produce ``exact_*`` artifact names because the
analysis was originally implemented under that prefix. This tool converts the
public result tree to SARA naming and migrates historical flat Turing result
folders into the open-source layout:

    test_result/<Architecture>/<SARA|FI|GEREM-all>/<Application>/...
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Iterable, List

ARCHITECTURES = ("Turing-RTX2060", "Ampere-RTX3070")
METHODS = ("SARA", "FI", "GEREM-all")
PUBLIC_METHODS = ("SARA", "FI", "GEREM-all")
PUBLIC_TEXT_EXTENSIONS = {".csv", ".txt", ".md", ".tsv", ".json", ".jsonl"}


def _is_app_result_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    if path.name in ARCHITECTURES or path.name in METHODS or path.name == "compare":
        return False
    return any(child.is_file() for child in path.iterdir())


def _iter_flat_app_dirs(result_root: Path) -> Iterable[Path]:
    if not result_root.exists():
        return []
    return sorted(path for path in result_root.iterdir() if _is_app_result_dir(path))


def _public_sara_name(name: str) -> str:
    return name.replace("Exact", "SARA").replace("exact", "sara").replace("EXACT", "SARA")


def _public_sara_text(text: str) -> str:
    # Keep replacement intentionally token/prefix oriented: public result files
    # often contain legacy exact_* field names, but normal English words such as
    # "exactly" must not be rewritten.
    replacements = (
        ("canonical_proof_exact_v2", "canonical_proof_sara_v2"),
        ("exact_", "sara_"),
        ("Exact_", "SARA_"),
        ("EXACT_", "SARA_"),
        ("_exact", "_sara"),
        ("_Exact", "_SARA"),
        ("_EXACT", "_SARA"),
        (" exact ", " sara "),
        (" Exact ", " SARA "),
        (" EXACT ", " SARA "),
        ("canonical exact", "canonical SARA"),
        ("Canonical Exact", "Canonical SARA"),
    )
    for old, new in replacements:
        text = text.replace(old, new)
    return text


def _copy_public_file(src: Path, dst: Path, *, force: bool) -> bool:
    if dst.exists() and not force:
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def _publicize_sara_file(path: Path) -> None:
    if path.suffix.lower() not in PUBLIC_TEXT_EXTENSIONS:
        return
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    new_text = _public_sara_text(text)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")


def normalize_sara_tree(sara_root: Path, *, remove_legacy: bool = True) -> List[Path]:
    """Rename/copy legacy exact-named SARA result files to public SARA names."""
    changed: List[Path] = []
    if not sara_root.exists():
        return changed
    legacy_files = sorted(
        path
        for path in sara_root.rglob("*")
        if path.is_file() and any(token in path.name for token in ("exact", "Exact", "EXACT"))
    )
    for src in legacy_files:
        dst = src.with_name(_public_sara_name(src.name))
        if dst == src:
            continue
        if dst.exists():
            dst.unlink()
        src.rename(dst)
        _publicize_sara_file(dst)
        changed.append(dst)
    for path in sorted(sara_root.rglob("*")):
        if path.is_file():
            _publicize_sara_file(path)
    if remove_legacy:
        for leftover in sorted(
            path
            for path in sara_root.rglob("*")
            if path.is_file() and any(token in path.name for token in ("exact", "Exact", "EXACT"))
        ):
            leftover.unlink()
    return changed


def init_layout(result_root: Path) -> None:
    for arch in ARCHITECTURES:
        for method in PUBLIC_METHODS:
            target = result_root / arch / method
            target.mkdir(parents=True, exist_ok=True)
            gitkeep = target / ".gitkeep"
            if not gitkeep.exists():
                try:
                    gitkeep.touch()
                except PermissionError:
                    pass
        compare_dir = result_root / arch / "compare"
        compare_dir.mkdir(parents=True, exist_ok=True)
        compare_gitkeep = compare_dir / ".gitkeep"
        if not compare_gitkeep.exists():
            try:
                compare_gitkeep.touch()
            except PermissionError:
                pass
    readme = result_root / "README.md"
    if not readme.exists():
        readme.write_text(
            "# Experiment results\n\n"
            "Final public results are organized as:\n\n"
            "- `Turing-RTX2060/SARA`\n"
            "- `Turing-RTX2060/FI`\n"
            "- `Turing-RTX2060/GEREM-all`\n"
            "- `Ampere-RTX3070/SARA`\n"
            "- `Ampere-RTX3070/FI`\n"
            "- `Ampere-RTX3070/GEREM-all`\n\n"
            "Intermediate traces, PTXAS outputs, simulator logs, and scratch run "
            "directories are intentionally excluded from this tree.\n",
            encoding="utf-8",
        )


def migrate_flat_turing(result_root: Path, *, force: bool = False, remove_flat: bool = False) -> None:
    """Move historical flat per-app result folders into Turing-RTX2060."""
    init_layout(result_root)
    copied = {"SARA": 0, "FI": 0, "GEREM-all": 0}
    skipped = 0
    flat_dirs = list(_iter_flat_app_dirs(result_root))
    for app_dir in flat_dirs:
        app = app_dir.name
        recognized = 0
        for src in sorted(path for path in app_dir.iterdir() if path.is_file()):
            lower = src.name.lower()
            if "exact" in lower:
                dst_name = _public_sara_name(src.name)
                dst = result_root / "Turing-RTX2060" / "SARA" / app / dst_name
                if _copy_public_file(src, dst, force=force):
                    _publicize_sara_file(dst)
                    copied["SARA"] += 1
                recognized += 1
            elif lower.startswith("gerem"):
                dst = result_root / "Turing-RTX2060" / "GEREM-all" / app / src.name
                if _copy_public_file(src, dst, force=force):
                    copied["GEREM-all"] += 1
                recognized += 1
            elif lower.startswith("test_result"):
                dst = result_root / "Turing-RTX2060" / "FI" / app / src.name
                if _copy_public_file(src, dst, force=force):
                    copied["FI"] += 1
                recognized += 1
            else:
                skipped += 1
        if remove_flat and recognized:
            shutil.rmtree(app_dir)
    normalize_sara_tree(result_root / "Turing-RTX2060" / "SARA")
    print(
        "migrated flat Turing results: "
        f"SARA={copied['SARA']} FI={copied['FI']} GEREM-all={copied['GEREM-all']} skipped={skipped}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", default="test_result", type=Path)
    parser.add_argument("--init", action="store_true", help="create the public result directory skeleton")
    parser.add_argument("--migrate-flat-turing", action="store_true", help="migrate old flat app folders into Turing-RTX2060")
    parser.add_argument("--remove-flat", action="store_true", help="remove old flat app folders after migrating recognized files")
    parser.add_argument("--force", action="store_true", help="overwrite already migrated files")
    parser.add_argument("--normalize-sara-root", type=Path, help="publicize one SARA result root")
    args = parser.parse_args()

    if args.init:
        init_layout(args.result_root)
    if args.migrate_flat_turing:
        migrate_flat_turing(args.result_root, force=args.force, remove_flat=args.remove_flat)
    if args.normalize_sara_root:
        changed = normalize_sara_tree(args.normalize_sara_root)
        print(f"normalized SARA files under {args.normalize_sara_root}: {len(changed)} renamed")
    if not (args.init or args.migrate_flat_turing or args.normalize_sara_root):
        parser.error("select at least one action")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
