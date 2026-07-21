"""Validated coverage metadata used to ground per-technique explanations."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CoverageCapability:
    technique_id: str
    technique_name: str
    tactic: str
    tier: str
    signal: str
    limitation: str


_CAPABILITIES = (
    CoverageCapability("T1595", "Active Scanning", "Reconnaissance", "covered", "A source has an unusually high blocked-request ratio.", "This identifies proxy-visible probing, not scans that bypass the proxy."),
    CoverageCapability("T1190", "Exploit Public-Facing Application", "Initial Access", "covered", "A rare or known exploitation-tool user agent appears in proxy traffic.", "A tool signature is evidence of attempted exploitation, not proof that exploitation succeeded."),
    CoverageCapability("T1110", "Brute Force", "Credential Access", "covered", "One source sends at least five requests within ten seconds.", "The burst is compatible with credential attacks but can also be scripted automation."),
    CoverageCapability("T1071", "Application Layer Protocol", "Command and Control", "covered", "VirusTotal marks a contacted destination malicious or suspicious.", "Coverage depends on VirusTotal configuration and verdict availability."),
    CoverageCapability("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "covered", "Transferred bytes are an extreme outlier relative to the upload's baseline.", "Volume alone cannot prove that the transferred content was sensitive."),
    CoverageCapability("T1046", "Network Service Discovery", "Discovery", "covered", "A scripted client rapidly contacts at least four distinct hosts.", "Only discovery visible through web-proxy traffic is detectable."),
    CoverageCapability("T1105", "Ingress Tool Transfer", "Command and Control", "covered", "A scripted client downloads a substantial executable or script payload.", "The proxy can identify the transfer pattern but cannot establish execution on the endpoint."),
    CoverageCapability("T1567", "Exfiltration Over Web Service", "Exfiltration", "covered", "At least 10 MB is uploaded to a recognized cloud-storage service.", "Large legitimate cloud uploads can resemble exfiltration and require analyst validation."),
    CoverageCapability("T1566", "Phishing", "Initial Access", "partial", "URLs, verdicts and user activity can contain phishing indicators.", "No dedicated phishing detector currently evaluates message delivery or user intent."),
    CoverageCapability("T1189", "Drive-by Compromise", "Initial Access", "partial", "Proxy logs show web destinations, response sizes and browser user agents.", "They do not prove that browser exploitation or code execution occurred."),
    CoverageCapability("T1133", "External Remote Services", "Initial Access", "partial", "Proxy destinations can reveal access to web-based remote services.", "Non-web remote protocols and successful remote access are outside this telemetry."),
    CoverageCapability("T1071.004", "DNS", "Command and Control", "partial", "Proxy URLs expose hostnames that may support DNS-related investigation.", "Raw DNS query and response telemetry is not present."),
    CoverageCapability("T1573", "Encrypted Channel", "Command and Control", "partial", "HTTPS destinations and transfer patterns are visible.", "Encrypted payload contents and cryptographic intent are not visible."),
    CoverageCapability("T1090", "Proxy", "Command and Control", "partial", "Destination and client metadata may indicate proxy-like services.", "The logs cannot reliably prove traffic forwarding or multi-hop proxy use."),
    CoverageCapability("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "partial", "Outbound volume and suspicious destinations can provide supporting evidence.", "The existing detectors cannot establish that a transfer used an active C2 channel."),
    CoverageCapability("T1102", "Web Service", "Command and Control", "partial", "Traffic to common web services is visible in proxy destinations.", "Ordinary service use cannot be reliably separated from C2 without additional context."),
)

COVERAGE_CAPABILITIES = {item.technique_id: item for item in _CAPABILITIES}


def coverage_capability(technique_id: str) -> CoverageCapability | None:
    return COVERAGE_CAPABILITIES.get(technique_id)
