import json

from dataclasses import asdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

from .models import Finding, HttpMetadata

console = Console()

def status_style(status: str) -> str:

    if status == "OK":
        return "green"

    if status == "WEAK":
        return "yellow"

    if status == "MISSING":
        return "red"

    return "white"

def severity_style(severity: str) -> str:

    if severity == "HIGH":
        return "red"

    if severity == "MEDIUM":
        return "yellow"

    if severity == "LOW":
        return "cyan"

    return "white"

def grade_style(grade: str) -> str:

    if grade == "A":
        return "green"

    if grade == "B":
        return "green"

    if grade == "C":
        return "yellow"

    if grade == "D":
        return "dark_orange"

    return "red"

def http_status_style(
    status_code: int
) -> str:

    if 200 <= status_code < 300:
        return "green"

    if 300 <= status_code < 400:
        return "cyan"

    if 400 <= status_code < 500:
        return "yellow"

    if status_code >= 500:
        return "red"

    return "white"

def truncate_text(
    text: str,
    max_length: int = 250
) -> str:

    if len(text) <= max_length:
        return text

    return text[:max_length] + "..."

def print_target_info(
    url: str,
    status_code: int,
    final_url: str
) -> None:

    status_color = http_status_style(
        status_code
    )

    console.print()

    console.print(
        f"[bold]Target:[/bold]    "
        f"{escape(url)}"
    )

    console.print(
        f"[bold]Status:[/bold]    "
        f"[{status_color}]"
        f"{status_code}"
        f"[/{status_color}]"
    )

    console.print(
        f"[bold]Final URL:[/bold] "
        f"{escape(final_url)}"
    )

def print_report(
    findings: list[Finding],
    score: float,
    grade: str
) -> None:

    table = Table(
        title="Security Headers",
        show_header=True,
        header_style="bold"
    )

    table.add_column(
        "Header",
        no_wrap=True
    )

    table.add_column(
        "Status",
        no_wrap=True
    )

    table.add_column(
        "Severity",
        no_wrap=True
    )

    table.add_column(
        "Note",
        overflow="fold"
    )

    for finding in findings:

        status_color = status_style(
            finding.status
        )

        severity_color = severity_style(
            finding.severity
        )

        table.add_row(
            finding.header,
            (
                f"[{status_color}]"
                f"{finding.status}"
                f"[/{status_color}]"
            ),
            (
                f"[{severity_color}]"
                f"{finding.severity}"
                f"[/{severity_color}]"
            ),
            finding.note,
        )

    console.print(table)

    grade_color = grade_style(
        grade
    )

    result_text = (
        f"Score: {score:.1f} / 100\n"
        f"Grade: "
        f"[{grade_color}]"
        f"{grade}"
        f"[/{grade_color}]"
    )

    console.print(
        Panel(
            result_text,
            title="Result",
            expand=False,
        )
    )

    problem_findings = [
        finding
        for finding in findings
        if finding.status != "OK"
    ]

    if problem_findings:

        console.print(
            "\n[bold]Findings[/bold]"
        )

        for finding in problem_findings:

            status_color = status_style(
                finding.status
            )

            severity_color = severity_style(
                finding.severity
            )

            evidence_preview = escape(
                truncate_text(
                    finding.evidence
                )
            )

            reason_text = escape(
                finding.note
            )

            attack_text = escape(
                finding.attack
            )

            console.print()

            console.print(
                f"[bold]"
                f"[{severity_color}]"
                f"[{finding.severity}]"
                f"[/{severity_color}] "
                f"{finding.header}"
                f"[/bold]"
            )

            console.print(
                f"[bold]Status:[/bold] "
                f"[{status_color}]"
                f"{finding.status}"
                f"[/{status_color}]"
            )

            console.print(
                f"[bold]Attack:[/bold] "
                f"{attack_text}"
            )

            console.print(
                f"[bold]Reason:[/bold] "
                f"{reason_text}"
            )

            console.print(
                f"[bold]Evidence:[/bold] "
                f"{evidence_preview}"
            )
def build_report_data(
    target: str,
    final_url: str,
    status_code: int,
    metadata: HttpMetadata,
    findings: list[Finding],
    score: float,
    grade: str,
) -> dict:

    return {
        "target": target,
        "final_url": final_url,
        "status_code": status_code,
        "http": asdict(metadata),
        "score": score,
        "grade": grade,
        "findings": [
            asdict(finding)
            for finding in findings
        ],
    }

def write_json_report(
    data: dict,
    file_path: str,
) -> None:

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False,
        )

def print_http_metadata(
    metadata: HttpMetadata
) -> None:

    table = Table(
        title="HTTP Information",
        show_header=False,
    )

    table.add_column(
        "Field",
        style="bold",
        no_wrap=True,
    )

    table.add_column(
        "Value",
    )

    table.add_row(
        "HTTP Version",
        metadata.http_version,
    )

    table.add_row(
        "Response Time",
        f"{metadata.response_time_ms:.1f} ms",
    )

    table.add_row(
        "Content-Type",
        metadata.content_type,
    )

    table.add_row(
        "Content-Length",
        metadata.content_length,
    )

    console.print(table)
