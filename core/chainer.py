"""
ShadowScan - Chaining Engine
The brain of ShadowScan. Reads findings from context, matches them against
rules.yaml, and returns an ordered list of next modules to execute.
"""

import yaml
import os
from typing import List, Dict, Any, Set
from core.context import ScanContext, FindingType, Severity


RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "chains", "rules.yaml")


class ChainEngine:
    """
    Rule-based chaining engine.
    After each module runs, the orchestrator calls `get_next_modules()`
    to determine what to run next based on findings so far.
    """

    def __init__(self):
        self.rules = self._load_rules()
        self._queued: Set[str] = set()

    def _load_rules(self) -> List[Dict[str, Any]]:
        with open(RULES_PATH, "r") as f:
            data = yaml.safe_load(f)
        return data.get("chains", [])

    def get_next_modules(
        self, ctx: ScanContext, just_completed: str
    ) -> List[str]:
        """
        Called after a module finishes.
        Returns prioritized list of next modules to run.
        """
        triggered: List[Dict] = []
        finding_types = {f.type.value for f in ctx.findings}
        flags = ctx.flags

        for rule in self.rules:
            trigger = rule["trigger"]
            condition = rule.get("condition")

            # Check if trigger matches a finding type
            trigger_matched = trigger in finding_types

            # Check if trigger matches a flag
            flag_trigger_map = {
                "secret_found": flags.get("secret_found"),
                "unauthenticated_access": flags.get("unauthenticated_access"),
                "jwt_found": flags.get("jwt_found"),
                "has_auth_token": flags.get("has_auth_token"),
                "has_graphql": flags.get("has_graphql"),
                "has_login": flags.get("has_login"),
                "has_sqli_candidate": flags.get("has_sqli_candidate"),
            }
            if not trigger_matched and trigger in flag_trigger_map:
                trigger_matched = bool(flag_trigger_map[trigger])

            if not trigger_matched:
                continue

            # Check optional condition
            if condition:
                if not self._evaluate_condition(condition, ctx):
                    continue

            # Add modules not already queued or completed
            for module in rule["next_modules"]:
                if (
                    module not in self._queued
                    and module not in ctx.completed_modules
                ):
                    triggered.append({
                        "module": module,
                        "priority": rule.get("priority", 3),
                        "reason": rule.get("reason", ""),
                        "trigger": trigger,
                    })
                    self._queued.add(module)

        # Sort by priority (1 = highest)
        triggered.sort(key=lambda x: x["priority"])

        return triggered

    def _evaluate_condition(self, condition: str, ctx: ScanContext) -> bool:
        """Evaluate special conditions beyond simple flag checks."""

        if condition == "tech_contains_graphql":
            return any("graphql" in t.lower() for t in ctx.technologies)

        if condition == "tech_contains_wordpress":
            return any("wordpress" in t.lower() or "wp" in t.lower() for t in ctx.technologies)

        if condition == "has_multiple_criticals":
            criticals = ctx.get_findings_by_severity(Severity.CRITICAL)
            return len(criticals) >= 2

        return False

    def explain_chain(self, ctx: ScanContext) -> List[Dict]:
        """
        Returns a human-readable explanation of all triggered chains.
        Used for terminal output and LLM context.
        """
        return self.get_next_modules(ctx, "")

    def reset(self):
        """Reset queued state for a fresh scan."""
        self._queued = set()
