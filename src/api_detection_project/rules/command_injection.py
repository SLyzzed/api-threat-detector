import re

from ..models import APIRequest, DetectionFinding
from .request_fields import request_strings


_SHELL_COMMAND = re.compile(
    r"(?:&&|\|\||[;|]|\$\()\s*"
    r"(?:/(?:[^\s/;&|()]+/)*)?"
    r"(?P<command>whoami|id|cat|curl|wget|bash|sh|cmd(?:\.exe)?|powershell(?:\.exe)?)"
    r"(?=\s|[;|&)]|$)",
    re.IGNORECASE,
)


def detect(request: APIRequest) -> list[DetectionFinding]:
    findings = []
    for field, value in request_strings(request):
        match = _SHELL_COMMAND.search(value)
        if match:
            findings.append(
                DetectionFinding(
                    rule_id="CMD_001",
                    technique="command_injection",
                    signal="shell_operator_with_command",
                    field=field,
                    explanation="A shell operator is followed by a recognized command.",
                    evidence={"command": match["command"].lower()},
                )
            )
    return findings
