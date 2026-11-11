import re

from ..models import APIRequest, DetectionFinding
from .request_fields import request_strings


_SQL_SPACE = r"(?:\s|/\*[\s\S]*?\*/)"

_TAUTOLOGY = re.compile(
    rf"\b(?:or|and){_SQL_SPACE}+(?:(?P<number>[0-9]+){_SQL_SPACE}*={_SQL_SPACE}*(?P=number)\b(?!\.[0-9])"
    r"|(?P<quote>['\"])(?P<literal>[^'\"\r\n]+)(?P=quote)"
    rf"{_SQL_SPACE}*={_SQL_SPACE}*(?P=quote)(?P=literal)(?P=quote))",
    re.IGNORECASE,
)

_UNION_SELECT = re.compile(rf"\bunion\b{_SQL_SPACE}+\bselect\b", re.IGNORECASE)


def detect(request: APIRequest) -> list[DetectionFinding]:
    findings = []
    for field, value in request_strings(request):
        tautology = _TAUTOLOGY.search(value)
        if not tautology and not _UNION_SELECT.search(value):
            continue
        findings.append(DetectionFinding(
            rule_id="SQL_001",
            technique="sql_injection",
            signal="boolean_tautology" if tautology else "union_select",
            field=field,
            explanation=(
                "A SQL boolean operator is followed by a self-equality comparison."
                if tautology else "SQL UNION is followed by SELECT."
            ),
        ))
    return findings
