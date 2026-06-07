#!/usr/bin/env python3
"""
ShadowScan - Intelligent Vulnerability Chaining Engine
Main orchestrator. Runs modules, feeds findings into chaining engine,
triggers LLM analysis on complex findings, generates report.

Usage:
    python shadowscan.py -t https://target.com
    python shadowscan.py -t https://target.com -o report.html --llm
    python shadowscan.py -t https://target.com --proxy http://127.0.0.1:8080 -v

Author: Akshat Singh | github.com/saksht
"""

import argparse
import os
import sys

from core.scanner import Scanner
from core.context import ScanContext, Severity
from core.chainer import ChainEngine
from core.llm_advisor import LLMAdvisor

from modules.recon import ReconModule
from modules.exposure import ExposureModule
from modules.auth import AuthModule
from modules.api import APIModule
from modules.injection import InjectionModule

from output.terminal import TerminalOutput
from output.reporter import Reporter


# Module registry
MODULE_MAP = {
    "recon": ReconModule,
    "exposure": ExposureModule,
    "auth": AuthModule,
    "api": APIModule,
    "injection": InjectionModule,
}

# Default execution order (before chaining kicks in)
DEFAULT_PIPELINE = ["recon", "exposure", "auth", "api", "injection"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="ShadowScan — Intelligent Vulnerability Chaining Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shadowscan.py -t https://example.com
  python shadowscan.py -t https://api.example.com --llm -v
  python shadowscan.py -t https://target.com --proxy http://127.0.0.1:8080
  python shadowscan.py -t https://app.com -o report.html --modules recon,exposure
        """,
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL (include scheme)")
    parser.add_argument("-o", "--output", default="shadowscan_report.html", help="Output report path")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    parser.add_argument("--headers", help='Custom headers as JSON (e.g. \'{"Authorization": "Bearer tok"}\')')
    parser.add_argument("--cookies", help='Cookies as JSON (e.g. \'{"session": "abc123"}\')')
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests")
    parser.add_argument("--modules", help="Comma-separated modules to run (default: all)")
    parser.add_argument("--llm", action="store_true", help="Enable LLM-augmented analysis (requires ANTHROPIC_API_KEY)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    return parser.parse_args()


def build_config(args) -> dict:
    import json
    config = {
        "target": args.target,
        "timeout": args.timeout,
        "delay": args.delay,
        "proxy": args.proxy,
        "retries": 2,
    }

    if args.headers:
        try:
            config["headers"] = json.loads(args.headers)
        except json.JSONDecodeError:
            print("[!] Invalid --headers JSON. Ignoring.")

    if args.cookies:
        try:
            config["cookies"] = json.loads(args.cookies)
        except json.JSONDecodeError:
            print("[!] Invalid --cookies JSON. Ignoring.")

    return config


def run_module(name: str, scanner: Scanner, ctx: ScanContext, term: TerminalOutput):
    """Instantiate and run a module by name."""
    module_class = MODULE_MAP.get(name)
    if not module_class:
        term.error(f"Unknown module: {name}")
        return []

    term.module_start(name)
    try:
        module = module_class(scanner, ctx)
        findings = module.run()
        term.module_done(name, len(findings))

        # Print each finding
        for f in findings:
            term.finding(f)

        return findings
    except Exception as e:
        term.error(f"Module {name} crashed: {e}")
        if term.verbose:
            import traceback
            traceback.print_exc()
        return []


def main():
    args = parse_args()
    term = TerminalOutput(verbose=args.verbose)
    term.banner()

    # Build config
    config = build_config(args)

    # Init core components
    ctx = ScanContext(target=args.target, config=config)
    scanner = Scanner(config)
    chainer = ChainEngine()
    llm = LLMAdvisor() if args.llm else LLMAdvisor(api_key="")

    term.scan_start(args.target, ctx.scan_id)

    # Determine modules to run
    if args.modules:
        pipeline = [m.strip() for m in args.modules.split(",")]
    else:
        pipeline = DEFAULT_PIPELINE.copy()

    # Track what's been queued
    queued = set(pipeline)
    executed = []

    # Main scan loop
    while pipeline:
        module_name = pipeline.pop(0)
        executed.append(module_name)

        findings = run_module(module_name, scanner, ctx, term)

        # === CHAINING ENGINE ===
        if findings:
            chains = chainer.get_next_modules(ctx, module_name)
            for chain in chains:
                next_mod = chain["module"]
                # Only add modules we know and haven't run
                if next_mod in MODULE_MAP and next_mod not in queued and next_mod not in ctx.completed_modules:
                    term.chain_triggered(chain["trigger"], next_mod, chain["reason"])
                    pipeline.append(next_mod)
                    queued.add(next_mod)

        # === LLM ANALYSIS ===
        # Trigger LLM if we have multiple high-severity findings and LLM is enabled
        if args.llm and llm.enabled:
            critical_count = len(ctx.get_findings_by_severity(Severity.CRITICAL))
            high_count = len(ctx.get_findings_by_severity(Severity.HIGH))

            if (critical_count >= 1 or high_count >= 2) and module_name == "exposure":
                term.llm_analysis("Analyzing finding combinations...")
                analysis = llm.analyze_findings(ctx)
                if analysis:
                    chains_found = analysis.get("chained_attacks", [])
                    if chains_found:
                        term.llm_analysis(f"Found {len(chains_found)} potential attack chains:")
                        for chain in chains_found[:3]:
                            term.llm_analysis(
                                f"  [{chain.get('combined_severity')}] {chain.get('chain_name')}\n"
                                f"  → {chain.get('attack_narrative', '')[:120]}"
                            )

                    for probe in analysis.get("next_probes", [])[:3]:
                        term.info(f"LLM suggests: {probe.get('probe')} → {probe.get('reason')}")

    # === FINAL REPORT ===
    term.scan_complete(ctx)

    if not args.no_report:
        term.info("Generating HTML report...")
        exec_summary = ""
        if args.llm and llm.enabled:
            exec_summary = llm.generate_report_summary(ctx)

        reporter = Reporter(ctx, output_path=args.output)
        report_path = reporter.generate(exec_summary)
        term.success(f"Report saved: {report_path}")


if __name__ == "__main__":
    main()
