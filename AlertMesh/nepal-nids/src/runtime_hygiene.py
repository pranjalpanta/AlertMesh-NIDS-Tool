"""
List or clean runtime artifacts before sharing the project.

Default mode is read-only. Use:
    python src/runtime_hygiene.py

To clean generated runtime files/directories:
    python src/runtime_hygiene.py --clean --confirm CLEAN_RUNTIME
"""

import argparse
import shutil
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RUNTIME_PATTERNS = (
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*.pcap",
    "*.pcapng",
    "*.cap",
)
RUNTIME_DIRS = (
    "logs",
    ".cache",
    ".pytest_cache",
    "__pycache__",
)


def runtime_artifacts():
    artifacts = []
    for pattern in RUNTIME_PATTERNS:
        artifacts.extend(path for path in BASE_DIR.glob(pattern) if path.is_file())
    for directory in RUNTIME_DIRS:
        path = BASE_DIR / directory
        if path.exists():
            artifacts.append(path)
    return sorted(set(artifacts), key=lambda path: str(path).lower())


def remove_artifact(path):
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True, None
    except PermissionError as exc:
        return False, exc


def main():
    parser = argparse.ArgumentParser(description="List or clean AlertMesh runtime artifacts.")
    parser.add_argument("--clean", action="store_true", help="Remove runtime artifacts.")
    parser.add_argument(
        "--confirm",
        default="",
        help="Required value CLEAN_RUNTIME when using --clean.",
    )
    args = parser.parse_args()

    artifacts = runtime_artifacts()
    if not artifacts:
        print("No runtime artifacts found.")
        return 0

    print("Runtime artifacts:")
    for path in artifacts:
        kind = "dir " if path.is_dir() else "file"
        print(f"  [{kind}] {path.relative_to(BASE_DIR)}")

    if not args.clean:
        print("\nRead-only mode. Nothing was deleted.")
        return 0

    if args.confirm != "CLEAN_RUNTIME":
        print("\nRefusing to clean without --confirm CLEAN_RUNTIME.")
        return 2

    removed = 0
    skipped = []
    for path in artifacts:
        ok, error = remove_artifact(path)
        if ok:
            removed += 1
        else:
            skipped.append((path, error))
    print(f"\nRemoved {removed} runtime artifact(s).")
    if skipped:
        print("Skipped locked/inaccessible artifact(s):")
        for path, error in skipped:
            print(f"  {path.relative_to(BASE_DIR)} ({error})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
