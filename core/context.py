"""
ShadowScan - Scan Context & Finding Graph
Shared state passed between all modules. Stores findings, discovered endpoints,
and metadata needed by the chaining engine.
"""

import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    # Recon
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    SUBDOMAIN_FOUND = "subdomain_found"
    TECH_DETECTED = "tech_detected"

    # Auth
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    TOKEN_EXPOSED = "token_exposed"
    USER_ENUMERATION = "user_enumeration"
    WEAK_AUTH = "weak_auth"

    # Injection
    SQLI = "sqli"
    SSTI = "ssti"
    XSS = "xss"
    OPEN_REDIRECT = "open_redirect"
    LFI = "lfi"
    CMDI = "cmdi"
    SSRF = "ssrf"

    # Exposure
    SECRET_EXPOSED = "secret_exposed"
    API_KEY_LEAKED = "api_key_leaked"
    ERROR_DISCLOSURE = "error_disclosure"
    SENSITIVE_ENDPOINT = "sensitive_endpoint"

    # API
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    UNAUTHENTICATED_API = "unauthenticated_api"
    MASS_ASSIGNMENT = "mass_assignment"
    RATE_LIMIT_MISSING = "rate_limit_missing"

    # Chained
    CHAINED_FINDING = "chained_finding"


@dataclass
class Finding:
    """A single vulnerability or observation found during scanning."""

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: FindingType = FindingType.ENDPOINT_DISCOVERED
    severity: Severity = Severity.INFO
    title: str = ""
    url: str = ""
    description: str = ""
    evidence: str = ""
    request: Optional[str] = None
    response_snippet: Optional[str] = None
    module: str = ""
    chained_from: Optional[str] = None  # ID of parent finding
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "module": self.module,
            "chained_from": self.chained_from,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class ScanContext:
    """
    Central state object for a ShadowScan run.
    All modules read from and write to this context.
    The chaining engine uses it to decide next steps.
    """

    def __init__(self, target: str, config: Dict[str, Any]):
        self.target = target
        self.config = config
        self.scan_id = str(uuid.uuid4())[:12]
        self.start_time = datetime.now()

        # Discovered assets
        self.endpoints: List[str] = []
        self.subdomains: List[str] = []
        self.parameters: Dict[str, List[str]] = {}  # endpoint -> [params]
        self.technologies: List[str] = []
        self.forms: List[Dict] = []

        # Findings
        self.findings: List[Finding] = []

        # Flags for chainer — what has been confirmed
        self.flags: Dict[str, bool] = {
            "has_login": False,
            "has_api": False,
            "has_graphql": False,
            "has_auth_token": False,
            "has_sqli_candidate": False,
            "has_idor_candidate": False,
            "jwt_found": False,
            "secret_found": False,
            "unauthenticated_access": False,
        }

        # Modules completed
        self.completed_modules: List[str] = []

        # LLM reasoning log
        self.llm_log: List[Dict] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_endpoint(self, url: str):
        if url not in self.endpoints:
            self.endpoints.append(url)

    def add_subdomain(self, subdomain: str):
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)

    def set_flag(self, flag: str, value: bool = True):
        self.flags[flag] = value

    def get_flag(self, flag: str) -> bool:
        return self.flags.get(flag, False)

    def mark_complete(self, module: str):
        if module not in self.completed_modules:
            self.completed_modules.append(module)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_type(self, finding_type: FindingType) -> List[Finding]:
        return [f for f in self.findings if f.type == finding_type]

    def summary(self) -> Dict[str, Any]:
        severity_counts = {}
        for s in Severity:
            severity_counts[s.value] = len(self.get_findings_by_severity(s))

        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "duration": str(datetime.now() - self.start_time).split(".")[0],
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "endpoints_discovered": len(self.endpoints),
            "modules_run": self.completed_modules,
            "flags": self.flags,
        }
