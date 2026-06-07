"""
ShadowScan - Terminal Output
Rich CLI output with colors, progress tracking, and finding display.
"""

from datetime import datetime
from core.context import ScanContext, Finding, Severity

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
GRAY = "\033[90m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED,
    Severity.HIGH: ORANGE,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: GRAY,
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "💀",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

BANNER = f"""
{RED}{BOLD}
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{GRAY}                    Intelligent Vulnerability Chaining Engine v1.0
                         by Akshat Singh | github.com/saksht{RESET}
"""


class TerminalOutput:
    """Handles all terminal output for ShadowScan."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._finding_count = 0

    def banner(self):
        print(BANNER)

    def scan_start(self, target: str, scan_id: str):
        print(f"\n{BOLD}{CYAN}[*] ShadowScan Starting{RESET}")
        print(f"    {WHITE}Target   : {BOLD}{target}{RESET}")
        print(f"    {WHITE}Scan ID  : {scan_id}{RESET}")
        print(f"    {WHITE}Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        print(f"\n{GRAY}{'─' * 70}{RESET}\n")

    def module_start(self, module: str):
        icons = {
            "recon": "🔍",
            "exposure": "🔑",
            "auth": "🔐",
            "api": "🌐",
            "injection": "💉",
        }
        icon = icons.get(module.lower(), "⚡")
        print(f"{BOLD}{BLUE}[→] Running module: {icon}  {module.upper()}{RESET}")

    def module_done(self, module: str, finding_count: int):
        if finding_count > 0:
            print(f"{GREEN}[✓] {module.upper()} — {finding_count} finding(s){RESET}\n")
        else:
            print(f"{GRAY}[✓] {module.upper()} — nothing found{RESET}\n")

    def finding(self, f: Finding):
        self._finding_count += 1
        color = SEVERITY_COLORS.get(f.severity, GRAY)
        icon = SEVERITY_ICONS.get(f.severity, "⚪")

        print(f"\n  {color}{BOLD}{icon} [{f.severity.value}] {f.title}{RESET}")
        print(f"  {GRAY}  URL    : {WHITE}{f.url}{RESET}")
        print(f"  {GRAY}  Module : {f.module}  |  ID: {f.id}{RESET}")

        if f.chained_from:
            print(f"  {MAGENTA}  ⛓ Chained from finding: {f.chained_from}{RESET}")

        if self.verbose and f.evidence:
            evidence_lines = f.evidence.split("\n")
            print(f"  {GRAY}  Evidence:{RESET}")
            for line in evidence_lines[:4]:
                print(f"  {DIM}    {line}{RESET}")

    def chain_triggered(self, trigger: str, next_module: str, reason: str):
        print(f"\n  {MAGENTA}[⛓] Chain triggered: {BOLD}{trigger}{RESET}{MAGENTA} → {next_module}{RESET}")
        print(f"  {GRAY}      Reason: {reason}{RESET}")

    def llm_analysis(self, message: str):
        print(f"\n  {CYAN}[🤖] LLM Analysis:{RESET}")
        for line in message.split("\n"):
            print(f"  {CYAN}    {line}{RESET}")

    def probe(self, url: str, status: int):
        if not self.verbose:
            return
        color = GREEN if status == 200 else (YELLOW if status == 403 else GRAY)
        print(f"  {color}  [{status}] {url}{RESET}")

    def scan_complete(self, ctx: ScanContext):
        summary = ctx.summary()
        print(f"\n{GRAY}{'─' * 70}{RESET}")
        print(f"\n{BOLD}{WHITE}[★] SCAN COMPLETE{RESET}")
        print(f"    Duration  : {summary['duration']}")
        print(f"    Target    : {ctx.target}")
        print(f"    Endpoints : {summary['endpoints_discovered']}")
        print(f"    Modules   : {', '.join(summary['modules_run'])}")
        print()

        # Severity summary
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = summary['severity_counts'].get(sev.value, 0)
            if count > 0:
                color = SEVERITY_COLORS[sev]
                icon = SEVERITY_ICONS[sev]
                print(f"    {color}{icon} {sev.value:<10}: {count}{RESET}")

        print(f"\n    {BOLD}Total Findings: {self._finding_count}{RESET}")

    def info(self, message: str):
        print(f"  {GRAY}[·] {message}{RESET}")

    def error(self, message: str):
        print(f"  {RED}[!] {message}{RESET}")

    def success(self, message: str):
        print(f"  {GREEN}[+] {message}{RESET}")
