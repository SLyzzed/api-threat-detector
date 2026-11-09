
from collections.abc import Callable

from .models import APIRequest, DetectionFinding
from .rules import command_injection, path_traversal, sql_injection


Rule = Callable[[APIRequest], list[DetectionFinding]]

RULES: dict[str, Rule] = {
    "path_traversal": path_traversal.detect,
    "sql_injection": sql_injection.detect,
    "command_injection": command_injection.detect,
}


def run_rules(request: APIRequest) -> list[DetectionFinding]:
    findings = []

    for rule in RULES.values():
        results = rule(request)
        findings.extend(results)

    return findings
