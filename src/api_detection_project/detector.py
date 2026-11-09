from .models import APIRequest, DetectionResult
from .registry import run_rules
from .scoring import calculate_risk, classify_risk


def analyze_request(request: APIRequest) -> DetectionResult:
    findings = run_rules(request)
    score = calculate_risk(findings)
    explanation = "No registered rule matched."
    if findings:
        techniques = ", ".join(dict.fromkeys(finding.technique for finding in findings))
        explanation = f"Matched techniques: {techniques}. Risk score: {score}/100."

    return DetectionResult(
        verdict=classify_risk(score),
        risk_score=score,
        explanation=explanation,
        findings=findings,
    )
