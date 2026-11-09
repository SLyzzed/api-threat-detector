
from .models import DetectionFinding


# Scoring configuration
SIGNAL_WEIGHTS = {
    ("PATH_001", "parent_directory_segment"): 65,
    ("SQL_001", "boolean_tautology"): 70,
    ("CMD_001", "shell_operator_with_command"): 75,
}


def calculate_risk(findings: list[DetectionFinding]) -> int:
    score = 0
    counted = set()

    for finding in findings:
        key = (finding.rule_id, finding.signal, finding.field)

        if key in counted:
            continue

        weight_key = (finding.rule_id, finding.signal)

        if weight_key not in SIGNAL_WEIGHTS:
            raise ValueError(f"Missing score for {weight_key}")

        score += SIGNAL_WEIGHTS[weight_key]
        counted.add(key)

    return min(score, 100)


def classify_risk(score: int) -> str:
    if score >= 80:
        return "Malicious"
    elif score >= 30:
        return "Suspicious"
    else:
        return "Benign"
