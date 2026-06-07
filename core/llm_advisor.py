"""
ShadowScan - LLM Advisor
Calls Claude API to reason about complex finding combinations,
suggest next attack vectors, and generate vuln chain narratives.
Kicks in when rule-based chaining hits ambiguous territory.
"""

import os
import json
import requests
from typing import Dict, Any, Optional, List
from core.context import ScanContext, Severity


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-20250514"

SYSTEM_PROMPT = """You are ShadowScan's AI reasoning engine — an expert offensive security analyst.
You receive a structured summary of findings from an ongoing penetration test or bug bounty scan.
Your job is to:
1. Identify non-obvious attack chains between findings
2. Suggest the highest-impact next probes to run
3. Assess combined severity if findings are chained together
4. Flag any patterns that suggest a bigger vulnerability class

Be concise, technical, and actionable. Think like a senior pentester, not a compliance tool.
Output ONLY valid JSON with the schema defined in the user prompt. No markdown, no preamble."""


class LLMAdvisor:
    """
    Wraps Claude API calls for security reasoning.
    Used selectively — only when rule engine needs deeper analysis.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.enabled = bool(self.api_key)

    def analyze_findings(self, ctx: ScanContext) -> Optional[Dict[str, Any]]:
        """
        Send current findings to Claude for chain analysis.
        Returns structured recommendations.
        """
        if not self.enabled:
            return None

        findings_summary = self._build_findings_summary(ctx)

        prompt = f"""Current scan state for target: {ctx.target}

FINDINGS:
{json.dumps(findings_summary, indent=2)}

FLAGS:
{json.dumps(ctx.flags, indent=2)}

TECHNOLOGIES DETECTED:
{json.dumps(ctx.technologies, indent=2)}

ENDPOINTS DISCOVERED ({len(ctx.endpoints)} total):
{json.dumps(ctx.endpoints[:20], indent=2)}

Analyze these findings and return JSON with this exact schema:
{{
  "chained_attacks": [
    {{
      "chain_name": "string",
      "findings_involved": ["finding_id1", "finding_id2"],
      "combined_severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "attack_narrative": "string - step by step how to chain these",
      "impact": "string"
    }}
  ],
  "next_probes": [
    {{
      "probe": "string - specific action to take",
      "target_url": "string - URL or endpoint to probe",
      "reason": "string",
      "priority": 1
    }}
  ],
  "pattern_flags": [
    {{
      "pattern": "string - vulnerability class or pattern spotted",
      "confidence": "high|medium|low",
      "explanation": "string"
    }}
  ],
  "overall_assessment": "string - 2-3 sentence summary of the security posture"
}}"""

        response = self._call_api(prompt)
        if response:
            ctx.llm_log.append({
                "type": "finding_analysis",
                "input_findings": len(ctx.findings),
                "response": response,
            })
        return response

    def reason_about_response(
        self, url: str, response_snippet: str, context: str
    ) -> Optional[str]:
        """
        Quick single-shot reasoning about a specific HTTP response.
        Used when a module isn't sure if something is a finding.
        """
        if not self.enabled:
            return None

        prompt = f"""Target URL: {url}
Context: {context}

HTTP Response snippet:
{response_snippet[:2000]}

Is this a security finding? If yes, what type and severity? 
If it's interesting but not confirmed, what additional probe would confirm it?
Answer in 2-3 sentences, be direct."""

        return self._call_raw(prompt)

    def generate_report_summary(self, ctx: ScanContext) -> str:
        """Generate executive summary for the HTML report."""
        if not self.enabled:
            return self._fallback_summary(ctx)

        summary = ctx.summary()
        findings_list = [f.to_dict() for f in ctx.findings]

        prompt = f"""Generate an executive summary for a penetration test report.

Target: {ctx.target}
Scan Summary: {json.dumps(summary, indent=2)}
Findings: {json.dumps(findings_list[:30], indent=2)}

Write 3-4 paragraphs covering:
1. Overall security posture
2. Most critical findings and their business impact  
3. Attack chain potential
4. Top 3 remediation priorities

Use professional pentest report language. Be specific, not generic."""

        result = self._call_raw(prompt)
        return result or self._fallback_summary(ctx)

    def _build_findings_summary(self, ctx: ScanContext) -> List[Dict]:
        return [
            {
                "id": f.id,
                "type": f.type.value,
                "severity": f.severity.value,
                "title": f.title,
                "url": f.url,
                "evidence_snippet": f.evidence[:200] if f.evidence else "",
            }
            for f in ctx.findings
        ]

    def _call_api(self, prompt: str) -> Optional[Dict]:
        """Call Claude API and parse JSON response."""
        raw = self._call_raw(prompt)
        if not raw:
            return None
        try:
            # Strip markdown fences if present
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean.strip())
        except (json.JSONDecodeError, IndexError):
            return None

    def _call_raw(self, prompt: str) -> Optional[str]:
        """Raw API call, returns text."""
        if not self.enabled:
            return None

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": MODEL,
            "max_tokens": 1500,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            resp = requests.post(
                ANTHROPIC_API_URL,
                headers=headers,
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data.get("content", [])
            for block in content:
                if block.get("type") == "text":
                    return block["text"]
        except Exception:
            pass
        return None

    def _fallback_summary(self, ctx: ScanContext) -> str:
        s = ctx.summary()
        criticals = len(ctx.get_findings_by_severity(Severity.CRITICAL))
        highs = len(ctx.get_findings_by_severity(Severity.HIGH))
        return (
            f"ShadowScan completed against {ctx.target} in {s['duration']}. "
            f"Discovered {s['endpoints_discovered']} endpoints across {len(s['modules_run'])} modules. "
            f"Total findings: {s['total_findings']} "
            f"({criticals} Critical, {highs} High). "
            f"Review findings below for details."
        )
