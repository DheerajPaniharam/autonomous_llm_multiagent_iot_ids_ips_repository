"""Generate a Markdown report from per-test pytest execution logs."""
from __future__ import annotations

import argparse
import ast
import csv
import re
from pathlib import Path

PHASE_RE = re.compile(
    r"^\[(setup|call|teardown)\] outcome=(\w+) duration=([\d.]+)s$",
    re.MULTILINE,
)
LOG_SUFFIX_RE = re.compile(r"-[0-9a-f]{10}$")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def describe_check(assertion: str) -> str:
    try:
        expression = ast.parse(assertion).body[0].test
    except (SyntaxError, AttributeError):
        return f"`{assertion}`"

    if isinstance(expression, ast.Compare) and len(expression.ops) == 1:
        left = expression.left
        right = expression.comparators[0]
        if (
            isinstance(left, ast.Attribute)
            and left.attr == "status_code"
            and isinstance(expression.ops[0], ast.Eq)
            and isinstance(right, ast.Constant)
        ):
            return f"HTTP response status was {right.value}"
        if (
            isinstance(expression.ops[0], ast.In)
            and isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and isinstance(right, ast.Call)
            and isinstance(right.func, ast.Attribute)
            and right.func.attr == "json"
        ):
            return f"response JSON contained the `{left.value}` key"

    return f"`{ast.unparse(expression)}`"


def latex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(character, character) for character in value)


def find_test_definitions(tests_root: Path) -> list[dict[str, object]]:
    definitions: list[dict[str, object]] = []

    def visit(nodes: list[ast.stmt], path: Path, classes: tuple[str, ...] = ()) -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                visit(node.body, path, classes + (node.name,))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                parts = [path.as_posix(), *classes, node.name]
                definitions.append(
                    {
                        "slug": safe_name("::".join(parts)),
                        "path": path,
                        "line": node.lineno,
                        "name": node.name,
                        "class": "::".join(classes),
                        "doc": ast.get_docstring(node),
                        "arguments": [arg.arg for arg in node.args.args if arg.arg != "self"],
                        "assertions": [
                            ast.unparse(child)
                            for child in ast.walk(node)
                            if isinstance(child, ast.Assert)
                        ],
                    }
                )

    for path in sorted(tests_root.rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        visit(tree.body, path.relative_to(tests_root.parent))
    return definitions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", nargs="?", type=Path, help="pytest log run directory")
    parser.add_argument("--output", type=Path, help="report path")
    parser.add_argument("--latex-output", type=Path, help="also write a LaTeX testcasebox report")
    parser.add_argument("--retry-run-dir", type=Path, help="separate run directory containing retry evidence")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    logs_root = repo_root / "logs" / "test_cases"
    run_dir = args.run_dir or max(
        (path for path in logs_root.glob("run-*") if path.is_dir()),
        key=lambda path: path.name,
    )
    if not run_dir.is_absolute():
        run_dir = repo_root / run_dir
    if not run_dir.is_dir():
        parser.error(f"pytest run directory does not exist: {run_dir}")

    retry_records = {}
    retry_run_dir = args.retry_run_dir
    if retry_run_dir:
        if not retry_run_dir.is_absolute():
            retry_run_dir = repo_root / retry_run_dir
        retry_summary_path = retry_run_dir / "summary.csv"
        if not retry_summary_path.is_file():
            parser.error(f"retry summary does not exist: {retry_summary_path}")
        with retry_summary_path.open(newline="", encoding="utf-8") as summary_file:
            retry_records = {
                row["nodeid"]: row for row in csv.DictReader(summary_file)
            }

    definitions = find_test_definitions(repo_root / "tests")
    log_files = sorted(run_dir.glob("*.log"))
    if not log_files:
        parser.error(f"no per-test log files found in {run_dir}")
    summary_path = run_dir / "summary.csv"
    execution_records = {}
    if summary_path.is_file():
        with summary_path.open(newline="", encoding="utf-8") as summary_file:
            execution_records = {
                row["phase_log"]: row for row in csv.DictReader(summary_file)
            }
        log_files = sorted(
            repo_root / path for path in execution_records
        )

    output_path = args.output or repo_root / "TEST_EXECUTION_RESULTS.md"
    if not output_path.is_absolute():
        output_path = repo_root / output_path

    latex_path = args.latex_output
    if latex_path and not latex_path.is_absolute():
        latex_path = repo_root / latex_path

    case_statuses = []
    status_by_log = {}
    for log_path in log_files:
        execution = execution_records.get(log_path.relative_to(repo_root).as_posix())
        text = log_path.read_text(encoding="utf-8", errors="replace")
        phase_outcomes = [outcome for _, outcome, _ in PHASE_RE.findall(text)]
        if (execution and int(execution["exit_code"]) != 0) or "failed" in phase_outcomes:
            status = "FAIL"
        elif "skipped" in phase_outcomes:
            status = "SKIP"
        else:
            status = "PASS"
        case_statuses.append(status)
        status_by_log[log_path.relative_to(repo_root).as_posix()] = status
    if summary_path.is_file():
        for log_name, execution in execution_records.items():
            execution["status"] = status_by_log.get(log_name, execution["status"])
        with summary_path.open(newline="", encoding="utf-8") as summary_file:
            fieldnames = csv.DictReader(summary_file).fieldnames
        with summary_path.open("w", newline="", encoding="utf-8") as summary_file:
            writer = csv.DictWriter(summary_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(execution_records.values())
    run_summary_path = run_dir / "summary.txt"
    run_summary_text = (
        run_summary_path.read_text(encoding="utf-8", errors="replace")
        if run_summary_path.is_file()
        else ""
    )
    elapsed_match = re.search(r"Execution wall time: ([\d.]+)s", run_summary_text)
    run_wall_time = float(elapsed_match.group(1)) if elapsed_match else None
    status_counts = {status: case_statuses.count(status) for status in ("PASS", "FAIL", "SKIP")}
    if run_summary_path.is_file() and run_wall_time is not None:
        run_summary_path.write_text(
            f"Collected and individually executed: {len(log_files)}\n"
            f"Passed: {status_counts['PASS']}\nFailed: {status_counts['FAIL']}\n"
            f"Skipped: {status_counts['SKIP']}\n"
            f"Execution wall time: {run_wall_time:.3f}s\n"
            "Each node ID ran in its own pytest subprocess.\n",
            encoding="utf-8",
        )

    latex_lines = []
    if latex_path:
        latex_lines = [
            r"\documentclass[11pt,a4paper]{article}",
            r"\usepackage[utf8]{inputenc}",
            r"\usepackage[margin=0.8in]{geometry}",
            r"\usepackage{xcolor}",
            r"\usepackage[most]{tcolorbox}",
            r"\usepackage{hyperref}",
            r"\definecolor{primaryblue}{RGB}{14,116,144}",
            r"\definecolor{darkslate}{RGB}{30,41,59}",
            r"\definecolor{darkgreen}{RGB}{21,128,61}",
            r"\definecolor{darkred}{RGB}{185,28,28}",
            r"\hypersetup{colorlinks=true,linkcolor=primaryblue,urlcolor=primaryblue}",
            r"\newtcolorbox{testcasebox}[2][]{enhanced,breakable,colback=white,colframe=primaryblue,colbacktitle=white,coltitle=darkslate,fonttitle=\bfseries,title={#2},boxrule=0.7pt,arc=2pt,left=7pt,right=7pt,top=5pt,bottom=5pt,#1}",
            r"\begin{document}",
            r"\section*{Individual Pytest Execution Results}",
            f"Run evidence: \\texttt{{\\detokenize{{{run_dir.relative_to(repo_root).as_posix()}}}}}\\\\",
            f"Executed: {len(log_files)}; PASS: {status_counts['PASS']}; FAIL: {status_counts['FAIL']}; SKIP: {status_counts['SKIP']}.",
            f"Total isolated-batch wall time: {run_wall_time:.3f} s." if run_wall_time is not None else "",
            r"Each box represents one collected pytest node run in its own subprocess. Call timing is pytest test-function time; process wall time includes pytest startup and is not system response latency.",
            r"\bigskip",
            "",
        ]

    lines = [
        "# Per-Test Execution Results",
        "",
        f"- **Run:** `{run_dir.relative_to(repo_root).as_posix()}`",
        f"- **Executed pytest items:** {len(log_files)}",
        f"- **Results:** {status_counts['PASS']} passed, {status_counts['FAIL']} failed, {status_counts['SKIP']} skipped",
        f"- **Total isolated-batch wall time:** {run_wall_time:.3f} s" if run_wall_time is not None else "",
        "- **Execution mode:** Each collected node ID ran in its own pytest subprocess." if execution_records else "",
        "- **Timing:** Call duration is the individual pytest test-function time, not end-to-end IDS/IPS latency or throughput.",
        "- **Evidence:** Each case links to pytest phase timings and, for isolated runs, a full console transcript with process exit code and wall time.",
        f"- **Separate retry evidence:** `{retry_run_dir.relative_to(repo_root).as_posix()}`; retry outcomes are not included in the original run totals." if retry_run_dir else "",
        "",
        "**How to read results:** PASS means pytest completed the test call successfully, so every assertion reached in that run passed. Plain-language checks are derived from the test source; they are not a transcript of response output. Assertions inside unselected branches are not evaluated.",
        "",
    ]

    for index, log_path in enumerate(log_files, start=1):
        stem = LOG_SUFFIX_RE.sub("", log_path.stem)
        definition = max(
            (item for item in definitions if stem.startswith(str(item["slug"]))),
            key=lambda item: len(str(item["slug"])),
            default=None,
        )
        text = log_path.read_text(encoding="utf-8", errors="replace")
        log_relative = log_path.relative_to(repo_root).as_posix()
        execution = execution_records.get(log_relative)
        retry = retry_records.get(execution["nodeid"]) if execution else None
        phases = {
            name: (outcome, float(duration))
            for name, outcome, duration in PHASE_RE.findall(text)
        }
        outcomes = [outcome for outcome, _ in phases.values()]
        process_exit_code = int(execution["exit_code"]) if execution else None
        status = (
            "FAIL" if process_exit_code not in (None, 0) or "failed" in outcomes
            else "SKIP" if "skipped" in outcomes
            else "PASS"
        )

        if definition:
            source_path = Path(str(definition["path"]))
            source_line = definition["line"]
            source_link = f"[{source_path.as_posix()}#L{source_line}]({source_path.as_posix()}#L{source_line})"
            class_name = str(definition["class"])
            test_name = str(definition["name"])
            test_scope = f"{class_name}::{test_name}" if class_name else test_name
            description = str(
                definition["doc"] or test_name.removeprefix("test_").replace("_", " ").capitalize()
            )
            arguments = definition["arguments"]
            inputs = ", ".join(f"`{argument}`" for argument in arguments) if arguments else "No pytest fixture arguments."
            assertions = definition["assertions"]
            checks = "; ".join(describe_check(assertion) for assertion in assertions)
            if not checks:
                checks = "No direct assert statement found; see the linked test source for the checked behavior."
        else:
            source_link = "Test definition not resolved; inspect the case log and test tree."
            test_scope = stem
            description = stem
            inputs = "See the case-specific test source and log."
            checks = "Not extracted; see the case-specific test source."

        call_outcome, call_duration = phases.get("call", ("not recorded", 0.0))
        if status == "PASS":
            actual = f"PASS: the test call completed successfully and its executed assertions passed. Checks defined in the test: {checks}. The response body was not captured in the execution log."
        elif status == "FAIL":
            actual = "FAIL: pytest recorded a failed phase; see the individual log for failure details."
        else:
            actual = "SKIP: pytest did not execute the test call; see the individual log for the reason."

        phase_summary = "; ".join(
            f"{name}={outcome} ({duration * 1000:.3f} ms)"
            for name, (outcome, duration) in phases.items()
        ) or "No phase records found"
        log_link = log_relative
        process_summary = (
            f"**Independent process:** exit code {process_exit_code}; wall time {float(execution['wall_seconds']):.3f} s."
            if execution
            else ""
        )
        console_summary = (
            f" **Console transcript:** [{execution['console_log']}]({execution['console_log']})."
            if execution
            else ""
        )
        retry_summary = ""
        if retry:
            retry_summary = (
                f" **Separate retry:** {retry['status']}, exit code {retry['exit_code']}, "
                f"wall time {float(retry['wall_seconds']):.3f} s. "
                f"[Phase log]({retry['phase_log']}); [console transcript]({retry['console_log']})."
            )
        lines.extend(
            [
                f"## Case {index:03d}: {test_scope}",
                f"**Test objective:** {description}",
                f"**Subsystem / test scope:** {source_link}",
                f"**Preconditions and inputs:** {inputs}. See the linked test for fixture values and setup details.",
                "**Execution:** Pytest ran this test as one independent item.",
                f"**Expected result / checks:** {checks}",
                f"**Actual result:** {actual}",
                f"**Status and timing:** **{status}**; call={call_outcome}, {call_duration * 1000:.3f} ms. Setup/teardown: {phase_summary}.",
                f"**Independent execution log:** [{log_link}]({log_link}). {process_summary}{console_summary}{retry_summary}",
                "",
            ]
        )

        if latex_path:
            if status == "PASS":
                status_tex = r"\textcolor{darkgreen}{\textbf{PASS}}"
                actual_tex = "The test call completed successfully; assertions reached during this run passed."
            elif status == "FAIL":
                status_tex = r"\textcolor{darkred}{\textbf{FAIL}}"
                actual_tex = "A pytest phase failed; see the execution log for failure details."
            else:
                status_tex = r"\textbf{SKIP}"
                actual_tex = "Pytest did not execute the test call; see the console transcript for the skip reason."
            if definition:
                source_path = Path(str(definition["path"]))
                source_ref = (
                    rf"\href{{{source_path.as_posix()}}}"
                    rf"{{\texttt{{{latex_escape(source_path.as_posix())}}}}}"
                    rf" (line {definition['line']})"
                )
                raw_assertions = definition["assertions"]
                checks_tex = "; ".join(str(assertion) for assertion in raw_assertions)
                checks_tex = latex_escape(checks_tex) if checks_tex else "See source test for its assertions."
                objective_tex = latex_escape(description)
                inputs_tex = latex_escape(", ".join(str(value) for value in definition["arguments"]))
                if not inputs_tex:
                    inputs_tex = "No pytest fixture arguments."
            else:
                source_ref = "Test definition not resolved; inspect the source tree."
                checks_tex = "See the source test and execution log."
                objective_tex = latex_escape(description)
                inputs_tex = "See the source test and execution log."
            phase_log_link = rf"\href{{{log_relative}}}{{pytest phase log}}"
            console_link = ""
            if execution:
                console_path = str(execution["console_log"])
                console_link = rf"; \href{{{console_path}}}{{full console transcript}}"
                process_result = (
                    f"exit code {process_exit_code}; process wall time "
                    f"{float(execution['wall_seconds']):.3f} s"
                )
            else:
                process_result = "process exit code not recorded"
            retry_tex = ""
            if retry:
                retry_tex = (
                    rf"\\ \textbf{{Separate retry:}} {latex_escape(str(retry['status']))}; "
                    rf"exit code {retry['exit_code']}; wall time {float(retry['wall_seconds']):.3f} s; "
                    rf"\href{{{retry['phase_log']}}}{{retry phase log}}; "
                    rf"\href{{{retry['console_log']}}}{{retry console transcript}}."
                )
            phase_tex = latex_escape(phase_summary)
            node_tex = latex_escape(str(execution["nodeid"]) if execution else stem)
            latex_lines.extend(
                [
                    rf"\begin{{testcasebox}}{{Case {index:03d}: {latex_escape(test_scope)}}}",
                    rf"\textbf{{Pytest node ID:}} \texttt{{{node_tex}}}\\",
                    rf"\textbf{{Test objective:}} {objective_tex}\\",
                    rf"\textbf{{Source code reference:}} {source_ref}\\",
                    rf"\textbf{{Preconditions / inputs:}} {inputs_tex}\\",
                    r"\textbf{Execution:} The named pytest node was run independently.\\",
                    rf"\textbf{{Expected result / checks:}} \texttt{{{checks_tex}}}\\",
                    rf"\textbf{{Actual result:}} {status_tex}; {actual_tex}\\",
                    rf"\textbf{{Timing:}} pytest call={call_duration * 1000:.3f} ms; setup/teardown: {phase_tex}; {latex_escape(process_result)}.",
                    rf"\textbf{{Evidence:}} {phase_log_link}{console_link}.{retry_tex}",
                    r"\end{testcasebox}",
                    r"\medskip",
                    "",
                ]
            )

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(log_files)} per-test records to {output_path}")
    if latex_path:
        latex_lines.extend([r"\end{document}", ""])
        latex_path.write_text("\n".join(latex_lines), encoding="utf-8")
        print(f"Wrote LaTeX testcase report to {latex_path}")


if __name__ == "__main__":
    main()