
from typing import Any
from pydantic import BaseModel, Field, ConfigDict


class APIRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    method: str
    path: str

    source_ip: str | None = Field(default=None, alias="sourceIp")
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    body: Any = None


class DetectionFinding(BaseModel):
    rule_id: str
    technique: str
    signal: str
    field: str
    explanation: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    explanation: str
    findings: list[DetectionFinding]


if __name__ == "__main__":
    sample_request = {
        "method": "POST",
        "path": "/api/v1/users/search",
        "sourceIp": "185.199.110.25",
        "body": {
            "username": "admin"
        }
    }

    request = APIRequest.model_validate(sample_request)
    print(request.model_dump_json(indent=2, by_alias=True))

    finding = DetectionFinding(
        rule_id="SQL_001",
        technique="sql_injection",
        signal="boolean_tautology",
        field="body.username",
        explanation="Possible SQL injection attempt",
        evidence={"contains_comment": True}
    )

    print(finding.model_dump_json(indent=2))
