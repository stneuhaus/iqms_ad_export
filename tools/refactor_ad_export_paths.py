#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


PATHS_MODULE_TEMPLATE = """from pathlib import Path

# Root of the embedded ad_export project folder.
PROJECT_ROOT = Path(__file__).resolve().parent


def project_path(*parts: str) -> Path:
    \"\"\"Build an absolute path inside ad_export.\"\"\"
    return PROJECT_ROOT.joinpath(*parts)
"""


@dataclass
class FileChange:
    path: Path
    before: str
    after: str


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Refactor ad_export relative-path patterns with dry-run/apply modes."
    )
    p.add_argument(
        "--repo-root",
        default=".",
        help="Root of iqms_user_role_assignment_review (default: current directory).",
    )
    p.add_argument(
        "--subdir",
        default="ad_export",
        help="Embedded project folder name (default: ad_export).",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Write changes to disk.")
    mode.add_argument("--dry-run", action="store_true", help="Preview changes only (default).")
    return p.parse_args()


def ensure_paths_module(
    paths_module: Path, apply: bool
) -> Tuple[bool, str]:
    """
    Returns: (changed_or_would_change, message)
    """
    if not paths_module.exists():
        if apply:
            paths_module.parent.mkdir(parents=True, exist_ok=True)
            paths_module.write_text(PATHS_MODULE_TEMPLATE, encoding="utf-8")
            return True, f"[WRITE] created {paths_module}"
        return True, f"[DRY-RUN] would create {paths_module}"
    existing = paths_module.read_text(encoding="utf-8")
    if existing != PATHS_MODULE_TEMPLATE:
        if apply:
            paths_module.write_text(PATHS_MODULE_TEMPLATE, encoding="utf-8")
            return True, f"[WRITE] updated {paths_module}"
        return True, f"[DRY-RUN] would update {paths_module}"
    return False, f"[OK] {paths_module} already up to date"


def inject_import_if_needed(text: str) -> str:
    import_line = "from ad_export.paths import PROJECT_ROOT\n"

    if import_line in text:
        return text

    # If PROJECT_ROOT is used after replacements, add import.
    if "PROJECT_ROOT" not in text:
        return text

    lines = text.splitlines(keepends=True)
    insert_idx = 0

    # Skip shebang
    if lines and lines[0].startswith("#!"):
        insert_idx = 1

    # Skip encoding comment
    if insert_idx < len(lines) and re.match(r"^#.*coding[:=]\s*[-\w.]+", lines[insert_idx]):
        insert_idx += 1

    # Skip module docstring (simple handling)
    if insert_idx < len(lines):
        m = re.match(r'^\s*([ruRU]{0,2}["\']){3}', lines[insert_idx])
        if m:
            quote = m.group(1)[-3:]
            insert_idx += 1
            while insert_idx < len(lines) and quote not in lines[insert_idx]:
                insert_idx += 1
            if insert_idx < len(lines):
                insert_idx += 1

    # Insert before first import block if present
    while insert_idx < len(lines) and lines[insert_idx].strip() == "":
        insert_idx += 1

    lines.insert(insert_idx, import_line)
    return "".join(lines)


def transform_python_content(text: str) -> str:
    new_text = text

    # Conservative replacements only
    new_text = re.sub(r"\bos\.getcwd\(\)", "str(PROJECT_ROOT)", new_text)
    new_text = re.sub(r"\bPath\.cwd\(\)", "PROJECT_ROOT", new_text)
    new_text = re.sub(r"\bPath\(\s*['\"]\.\s*['\"]\s*\)", "PROJECT_ROOT", new_text)

    new_text = inject_import_if_needed(new_text)
    return new_text


def collect_changes(py_files: List[Path]) -> List[FileChange]:
    changes: List[FileChange] = []
    for f in py_files:
        before = f.read_text(encoding="utf-8")
        after = transform_python_content(before)
        if before != after:
            changes.append(FileChange(path=f, before=before, after=after))
    return changes


def print_diff(change: FileChange) -> None:
    diff = difflib.unified_diff(
        change.before.splitlines(),
        change.after.splitlines(),
        fromfile=str(change.path),
        tofile=str(change.path),
        lineterm="",
    )
    print("\n".join(diff))


def main() -> int:
    args = parse_args()
    apply = bool(args.apply) and not bool(args.dry_run)

    repo_root = Path(args.repo_root).resolve()
    subdir = repo_root / args.subdir
    paths_module = subdir / "paths.py"

    if not subdir.exists():
        print(f"[ERROR] Subdir does not exist: {subdir}")
        return 1

    changed, msg = ensure_paths_module(paths_module, apply=apply)
    print(msg)

    py_files = [
        p for p in subdir.rglob("*.py")
        if "__pycache__" not in p.parts and p.name != "paths.py"
    ]

    changes = collect_changes(py_files)

    if not changes and not changed:
        print("[OK] No changes needed.")
        return 0

    print(f"[INFO] Files to change: {len(changes)}")
    for c in changes:
        print_diff(c)
        if apply:
            c.path.write_text(c.after, encoding="utf-8")
            print(f"[WRITE] {c.path}")
        else:
            print(f"[DRY-RUN] would update {c.path}")

    print("[DONE] Apply mode completed." if apply else "[DONE] Dry-run completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())