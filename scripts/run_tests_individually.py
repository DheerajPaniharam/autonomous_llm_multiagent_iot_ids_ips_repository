"""Run each collected pytest item in its own process and preserve its evidence."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from datetime import datetime, timezone


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")[:120]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="run only the first N collected items (for a smoke test)")
    parser.add_argument("--nodeid", help="run exactly one collected pytest node ID")
    parser.add_argument("--workers", type=int, default=4, help="maximum concurrent isolated pytest processes")
    parser.add_argument("--run-dir", type=Path, help="evidence directory; defaults to a new timestamped path")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    repo_root = Path(__file__).resolve().parent.parent
    python = Path(sys.executable)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = args.run_dir or repo_root / "logs" / "test_cases" / f"run-{run_id}-{os.getpid()}"
    if not run_dir.is_absolute():
        run_dir = repo_root / run_dir
    if run_dir.exists() and any(run_dir.iterdir()):
        parser.error(f"refusing to write into non-empty run directory: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    console_dir = run_dir / "console"
    console_dir.mkdir(exist_ok=True)

    collected = subprocess.run(
        [str(python), "-m", "pytest", "--collect-only", "-q"],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    (run_dir / "collection.log").write_text(
        collected.stdout + ("\n--- stderr ---\n" + collected.stderr if collected.stderr else ""),
        encoding="utf-8",
    )
    if collected.returncode:
        print(f"Collection failed; see {run_dir / 'collection.log'}", file=sys.stderr)
        return collected.returncode

    node_ids = [line.strip() for line in collected.stdout.splitlines() if line.startswith("tests/") and "::" in line]
    if not node_ids:
        print(f"No pytest node IDs found; see {run_dir / 'collection.log'}", file=sys.stderr)
        return 2
    if args.nodeid:
        if args.nodeid not in node_ids:
            parser.error(f"node ID was not collected: {args.nodeid}")
        node_ids = [args.nodeid]
    if args.limit is not None:
        if args.limit < 1:
            parser.error("--limit must be at least 1")
        node_ids = node_ids[:args.limit]

    child_env = os.environ.copy()
    child_env["PYTEST_CASE_LOG_DIR"] = str(run_dir)
    summary_path = run_dir / "summary.csv"
    suite_started = time.perf_counter()
    failed = 0
    skipped = 0

    def run_one(item: tuple[int, str]) -> dict[str, object]:
        index, node_id = item
        digest = hashlib.sha256(node_id.encode("utf-8")).hexdigest()[:10]
        stem = f"{safe_name(node_id)}-{digest}"
        console_path = console_dir / f"{stem}.log"
        phase_path = run_dir / f"{stem}.log"
        started = time.perf_counter()
        result = subprocess.run(
            [str(python), "-m", "pytest", "-q", node_id],
            cwd=repo_root,
            env=child_env,
            text=True,
            capture_output=True,
        )
        wall_seconds = time.perf_counter() - started
        phase_text = phase_path.read_text(encoding="utf-8", errors="replace") if phase_path.is_file() else ""
        if result.returncode:
            status = "FAIL"
        elif re.search(r"\[(setup|call|teardown)\] outcome=skipped", phase_text):
            status = "SKIP"
        else:
            status = "PASS"
        console_path.write_text(
            f"COMMAND: {python} -m pytest -q {node_id}\n"
            f"EXIT CODE: {result.returncode}\nWALL SECONDS: {wall_seconds:.6f}\n\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}",
            encoding="utf-8",
        )
        return {
            "index": index,
            "nodeid": node_id,
            "status": status,
            "exit_code": result.returncode,
            "wall_seconds": f"{wall_seconds:.6f}",
            "console_log": console_path.relative_to(repo_root).as_posix(),
            "phase_log": phase_path.relative_to(repo_root).as_posix(),
        }

    with summary_path.open("w", newline="", encoding="utf-8") as summary_file:
        writer = csv.DictWriter(
            summary_file,
            fieldnames=["index", "nodeid", "status", "exit_code", "wall_seconds", "console_log", "phase_log"],
        )
        writer.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            for result in executor.map(run_one, enumerate(node_ids, start=1)):
                writer.writerow(result)
                summary_file.flush()
                failed += result["exit_code"] != 0
                skipped += result["status"] == "SKIP"
                print(
                    f"[{result['index']}/{len(node_ids)}] {result['status']} "
                    f"{result['nodeid']} ({float(result['wall_seconds']):.2f}s)",
                    flush=True,
                )

    elapsed = time.perf_counter() - suite_started
    (run_dir / "summary.txt").write_text(
        f"Collected and individually executed: {len(node_ids)}\n"
        f"Passed: {len(node_ids) - failed - skipped}\nFailed: {failed}\nSkipped: {skipped}\n"
        f"Execution wall time: {elapsed:.3f}s\n"
        f"Each node ID ran in its own pytest subprocess.\n",
        encoding="utf-8",
    )
    print(f"Run evidence: {run_dir.relative_to(repo_root)}")
    print(
        f"Passed: {len(node_ids) - failed - skipped}; failed: {failed}; "
        f"skipped: {skipped}; wall time: {elapsed:.1f}s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())