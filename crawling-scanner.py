#!/usr/bin/env python3

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.text import Text


# ============================================================
# CONFIG
# ============================================================

VERSION = "1.1.0"

console = Console()

TOOLS = {
    "waybackurls": shutil.which("waybackurls"),
    "gospider": shutil.which("gospider"),
    "katana": shutil.which("katana"),
}


# ============================================================
# BANNER
# ============================================================

BANNER = r"""
[bold cyan]
 ██████╗██████╗  █████╗ ██╗    ██╗██╗     ██╗███╗   ██╗ ██████╗
██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██║████╗  ██║██╔════╝
██║     ██████╔╝███████║██║ █╗ ██║██║     ██║██╔██╗ ██║██║  ███╗
██║     ██╔══██╗██╔══██║██║███╗██║██║     ██║██║╚██╗██║██║   ██║
╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗██║██║ ╚████║╚██████╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝
[/bold cyan]

[bold white]WEB RECONNAISSANCE & URL DISCOVERY[/bold white]
[dim]Waybackurls + GoSpider + Katana[/dim]
"""


# ============================================================
# ARGUMENT PARSER
# ============================================================

def build_parser():
    parser = argparse.ArgumentParser(
        prog="crawling-scan.py",
        description="Fast web reconnaissance using Waybackurls, GoSpider and Katana.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:

  Single target:
    python3 crawling-scan.py -u example.com

  Multiple targets:
    python3 crawling-scan.py -l targets.txt

  Custom output:
    python3 crawling-scan.py -u example.com -o results

  Deeper crawl:
    python3 crawling-scan.py -u example.com -d 5

  Enable subdomain crawling:
    python3 crawling-scan.py -u example.com --subs

  Enable external sources:
    python3 crawling-scan.py -u example.com --other-source

  Show help:
    python3 crawling-scan.py -h
""",
    )

    # --------------------------------------------------------
    # TARGET
    # --------------------------------------------------------

    target = parser.add_argument_group("TARGET")

    target.add_argument(
        "-u",
        "--url",
        help="Target domain or URL",
    )

    target.add_argument(
        "-l",
        "--list",
        help="File containing targets",
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    output = parser.add_argument_group("OUTPUT")

    output.add_argument(
        "-o",
        "--output-dir",
        default="crawling_results",
        help="Output directory (default: crawling_results)",
    )

    output.add_argument(
        "--combined",
        default="all_urls.txt",
        help="Combined output filename (default: all_urls.txt)",
    )

    # --------------------------------------------------------
    # CRAWLING
    # --------------------------------------------------------

    crawl = parser.add_argument_group("CRAWLING")

    crawl.add_argument(
        "-d",
        "--depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )

    crawl.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=10,
        help="Maximum concurrent requests (default: 10)",
    )

    crawl.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        help="Number of GoSpider threads (default: 5)",
    )

    crawl.add_argument(
        "--subs",
        action="store_true",
        help="Enable subdomain crawling",
    )

    crawl.add_argument(
        "--other-source",
        action="store_true",
        help="Use third-party sources with GoSpider",
    )

    # --------------------------------------------------------
    # INFORMATION
    # --------------------------------------------------------

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


# ============================================================
# TARGET NORMALIZATION
# ============================================================

def normalize_domain(target):
    """
    Return bare domain for Waybackurls.
    """

    target = target.strip()

    if not target:
        return ""

    target = re.sub(r"^https?://", "", target, flags=re.I)
    target = target.split("/")[0]
    target = target.strip()

    return target


def normalize_url(target):
    """
    Return a URL suitable for GoSpider/Katana.
    """

    target = target.strip()

    if not target:
        return ""

    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target

    return target.rstrip("/")


# ============================================================
# READ TARGETS
# ============================================================

def read_targets(args):
    targets = []

    if args.url:
        targets.append(args.url)

    if args.list:
        list_path = Path(args.list)

        if not list_path.exists():
            console.print(
                f"[bold red][!] Target list not found:[/bold red] {list_path}"
            )
            sys.exit(1)

        with list_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if line and not line.startswith("#"):
                    targets.append(line)

    if not targets:
        console.print(
            "[bold red][!] You must provide -u or -l.[/bold red]"
        )
        sys.exit(1)

    # Remove duplicates while preserving order
    unique = []

    for target in targets:
        if target not in unique:
            unique.append(target)

    return unique


# ============================================================
# DEPENDENCY CHECK
# ============================================================

def check_dependencies():
    console.print("\n[bold cyan][*] Checking dependencies...[/bold cyan]\n")

    missing = []

    table = Table(
        title="Required Tools",
        show_header=True,
    )

    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Path")

    for tool, path in TOOLS.items():

        if path:
            table.add_row(
                tool,
                "[bold green]FOUND[/bold green]",
                path,
            )
        else:
            table.add_row(
                tool,
                "[bold red]MISSING[/bold red]",
                "-",
            )
            missing.append(tool)

    console.print(table)

    if missing:
        console.print(
            "\n[bold red][!] Missing tools:[/bold red] "
            + ", ".join(missing)
        )
        sys.exit(1)


# ============================================================
# RUN COMMAND
# ============================================================

def run_process(command, stdin_data=None):
    try:

        result = subprocess.run(
            command,
            input=stdin_data,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return result.returncode, result.stdout, result.stderr

    except FileNotFoundError:
        return 127, "", "Command not found"

    except Exception as exc:
        return 1, "", str(exc)


# ============================================================
# WAYBACKURLS
# ============================================================

def run_wayback(targets, output_file):

    console.print(
        "\n[bold cyan][*] Running Waybackurls...[/bold cyan]"
    )

    # Waybackurls expects domains, not full URLs.
    domains = []

    for target in targets:
        domain = normalize_domain(target)

        if domain:
            domains.append(domain)

    stdin_data = "\n".join(domains) + "\n"

    command = [
        TOOLS["waybackurls"],
    ]

    code, stdout, stderr = run_process(
        command,
        stdin_data=stdin_data,
    )

    urls = []

    if stdout:
        for line in stdout.splitlines():
            line = line.strip()

            if line.startswith(("http://", "https://")):
                urls.append(line)

    urls = sorted(set(urls))

    output_file.write_text(
        "\n".join(urls) + ("\n" if urls else ""),
        encoding="utf-8",
    )

    if code != 0:

        console.print(
            f"[bold red][!] Waybackurls failed "
            f"(exit code {code})[/bold red]"
        )

        if stderr:
            console.print(
                f"[red]{stderr.strip()}[/red]"
            )

    else:

        console.print(
            f"[bold green][+] Waybackurls: "
            f"{len(urls)} URLs[/bold green]"
        )

    return urls


# ============================================================
# GOSPIDER
# ============================================================

def run_gospider(targets, output_dir, output_file, args):

    console.print(
        "\n[bold cyan][*] Running GoSpider v1.1.6...[/bold cyan]"
    )

    # IMPORTANT:
    # GoSpider receives FULL URLs.
    crawler_targets = []

    for target in targets:

        url = normalize_url(target)

        if url:
            crawler_targets.append(url)

    target_file = output_dir / "_gospider_targets.txt"

    target_file.write_text(
        "\n".join(crawler_targets) + "\n",
        encoding="utf-8",
    )

    raw_dir = output_dir / "gospider_raw"

    raw_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # GoSpider v1.1.6 command
    # --------------------------------------------------------

    command = [
        TOOLS["gospider"],
        "-S",
        str(target_file),
        "-o",
        str(raw_dir),
        "-d",
        str(args.depth),
        "-c",
        str(args.concurrency),
        "-t",
        str(args.threads),
        "--js",
        "--sitemap",
        "--robots",
        "-q",
    ]

    # Optional subdomains
    if args.subs:
        command.append("--subs")

    # Optional third-party sources
    if args.other_source:
        command.append("-a")

    code, stdout, stderr = run_process(command)

    # --------------------------------------------------------
    # Extract URLs
    # --------------------------------------------------------

    urls = set()

    url_regex = re.compile(
        r"https?://[^\s\"'<>]+",
        re.I,
    )

    # GoSpider can write results to files.
    for file_path in raw_dir.rglob("*"):

        if not file_path.is_file():
            continue

        try:

            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            for match in url_regex.findall(content):

                url = match.rstrip(
                    ".,;:)]}\"'"
                )

                urls.add(url)

        except Exception:
            continue

    # Some versions/output modes may return URLs through stdout.
    if stdout:

        for match in url_regex.findall(stdout):

            url = match.rstrip(
                ".,;:)]}\"'"
            )

            urls.add(url)

    urls = sorted(urls)

    output_file.write_text(
        "\n".join(urls) + ("\n" if urls else ""),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    if code != 0:

        console.print(
            f"[bold red][!] GoSpider failed "
            f"(exit code {code})[/bold red]"
        )

        if stderr.strip():

            console.print(
                Panel(
                    stderr.strip(),
                    title="GoSpider stderr",
                    border_style="red",
                )
            )

        if stdout.strip() and not urls:

            console.print(
                Panel(
                    stdout.strip(),
                    title="GoSpider stdout",
                    border_style="yellow",
                )
            )

    else:

        console.print(
            f"[bold green][+] GoSpider: "
            f"{len(urls)} URLs[/bold green]"
        )

    return urls


# ============================================================
# KATANA
# ============================================================

def run_katana(targets, output_file, args):

    console.print(
        "\n[bold cyan][*] Running Katana...[/bold cyan]"
    )

    crawler_targets = []

    for target in targets:

        url = normalize_url(target)

        if url:
            crawler_targets.append(url)

    target_file = output_file.parent / "_katana_targets.txt"

    target_file.write_text(
        "\n".join(crawler_targets) + "\n",
        encoding="utf-8",
    )

    command = [
        TOOLS["katana"],
        "-list",
        str(target_file),
        "-d",
        str(args.depth),
        "-jc",
        "-kf",
        "all",
        "-c",
        str(args.concurrency),
        "-o",
        str(output_file),
        "-silent",
    ]

    code, stdout, stderr = run_process(command)

    urls = set()

    # Katana output file
    if output_file.exists():

        try:

            content = output_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            for line in content.splitlines():

                line = line.strip()

                if line.startswith(("http://", "https://")):
                    urls.add(line)

        except Exception:
            pass

    # Fallback stdout
    if stdout:

        for line in stdout.splitlines():

            line = line.strip()

            if line.startswith(("http://", "https://")):
                urls.add(line)

    urls = sorted(urls)

    output_file.write_text(
        "\n".join(urls) + ("\n" if urls else ""),
        encoding="utf-8",
    )

    if code != 0:

        console.print(
            f"[bold red][!] Katana failed "
            f"(exit code {code})[/bold red]"
        )

        if stderr:
            console.print(
                Panel(
                    stderr.strip(),
                    title="Katana stderr",
                    border_style="red",
                )
            )

    else:

        console.print(
            f"[bold green][+] Katana: "
            f"{len(urls)} URLs[/bold green]"
        )

    return urls


# ============================================================
# COMBINE RESULTS
# ============================================================

def combine_results(
    wayback_urls,
    gospider_urls,
    katana_urls,
    output_file,
):

    combined = set()

    for collection in (
        wayback_urls,
        gospider_urls,
        katana_urls,
    ):

        for url in collection:

            url = url.strip()

            if url.startswith(
                ("http://", "https://")
            ):
                combined.add(url)

    combined = sorted(combined)

    output_file.write_text(
        "\n".join(combined)
        + ("\n" if combined else ""),
        encoding="utf-8",
    )

    return combined


# ============================================================
# RESULTS TABLE
# ============================================================

def show_results(
    wayback_urls,
    gospider_urls,
    katana_urls,
    combined_urls,
):

    table = Table(
        title="URL Discovery Results",
        show_header=True,
    )

    table.add_column("Source")
    table.add_column("URLs", justify="right")

    table.add_row(
        "Waybackurls",
        str(len(wayback_urls)),
    )

    table.add_row(
        "GoSpider",
        str(len(gospider_urls)),
    )

    table.add_row(
        "Katana",
        str(len(katana_urls)),
    )

    table.add_row(
        "Combined Unique",
        f"[bold green]{len(combined_urls)}[/bold green]",
    )

    console.print("\n")
    console.print(table)


# ============================================================
# MAIN SCAN
# ============================================================

def run_scan(args):

    console.print(BANNER)

    # --------------------------------------------------------
    # Dependencies
    # --------------------------------------------------------

    check_dependencies()

    # --------------------------------------------------------
    # Targets
    # --------------------------------------------------------

    targets = read_targets(args)

    output_dir = Path(args.output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Save original targets
    target_file = output_dir / "_targets.txt"

    target_file.write_text(
        "\n".join(targets) + "\n",
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    config = Table(
        title="Scan Configuration",
        show_header=False,
    )

    config.add_row(
        "Targets",
        str(len(targets)),
    )

    config.add_row(
        "Depth",
        str(args.depth),
    )

    config.add_row(
        "Concurrency",
        str(args.concurrency),
    )

    config.add_row(
        "GoSpider Threads",
        str(args.threads),
    )

    config.add_row(
        "Subdomains",
        "ON" if args.subs else "OFF",
    )

    config.add_row(
        "External Sources",
        "ON" if args.other_source else "OFF",
    )

    config.add_row(
        "Output",
        str(output_dir),
    )

    console.print(config)

    # --------------------------------------------------------
    # Output files
    # --------------------------------------------------------

    wayback_file = output_dir / "waybackurls.txt"
    gospider_file = output_dir / "gospider.txt"
    katana_file = output_dir / "katana.txt"
    combined_file = output_dir / args.combined

    # --------------------------------------------------------
    # Run tools
    # --------------------------------------------------------

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:

        task = progress.add_task(
            "[cyan]Reconnaissance...",
            total=3,
        )

        wayback_urls = run_wayback(
            targets,
            wayback_file,
        )

        progress.advance(task)

        gospider_urls = run_gospider(
            targets,
            output_dir,
            gospider_file,
            args,
        )

        progress.advance(task)

        katana_urls = run_katana(
            targets,
            katana_file,
            args,
        )

        progress.advance(task)

    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    console.print(
        "\n[bold cyan][*] Combining results...[/bold cyan]"
    )

    combined_urls = combine_results(
        wayback_urls,
        gospider_urls,
        katana_urls,
        combined_file,
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    show_results(
        wayback_urls,
        gospider_urls,
        katana_urls,
        combined_urls,
    )

    console.print(
        Panel(
            f"[bold green]Scan completed successfully[/bold green]\n\n"
            f"Results directory:\n"
            f"[cyan]{output_dir.resolve()}[/cyan]\n\n"
            f"Combined URLs:\n"
            f"[cyan]{combined_file.resolve()}[/cyan]",
            title="COMPLETE",
            border_style="green",
        )
    )


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    if args.depth < 0:
        parser.error("Depth cannot be negative.")

    if args.concurrency < 1:
        parser.error("Concurrency must be >= 1.")

    if args.threads < 1:
        parser.error("Threads must be >= 1.")

    run_scan(args)


if __name__ == "__main__":
    main()
