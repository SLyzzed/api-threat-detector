import re

from ..models import APIRequest, DetectionFinding
from .request_fields import request_strings


_TAUTOLOGY = re.compile(
    r"\b(?:or|and)\s+(?:(?P<number>[0-9]+)\s*=\s*(?P=number)\b(?!\.[0-9])"
    r"|(?P<quote>['\"])(?P<literal>[^'\"\r\n]+)(?P=quote)"
    r"\s*=\s*(?P=quote)(?P=literal)(?P=quote))",
    re.IGNORECASE,
)


def detect(request: APIRequest) -> list[DetectionFinding]:
    return [
        DetectionFinding(
            rule_id="SQL_001",
            technique="sql_injection",
            signal="boolean_tautology",
            field=field,
            explanation="A SQL boolean operator is followed by a self-equality comparison.",
        )
        for field, value in request_strings(request)
        if _TAUTOLOGY.search(value)
    ]
