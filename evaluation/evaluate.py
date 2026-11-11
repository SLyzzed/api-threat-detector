"""Run the detector against a small, synthetic set of labeled requests."""

import argparse
import json
from collections import Counter
from pathlib import Path

from api_detection_project.detector import analyze_request
from api_detection_project.models import APIRequest


DEFAULT_FIXTURES = Path(__file__).with_name("requests.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", nargs="?", type=Path, default=DEFAULT_FIXTURES)
    args = parser.parse_args()

    cases = json.loads(args.fixtures.read_text(encoding="utf-8"))
    totals = Counter()
    expected_hits = Counter()
    matched_hits = Counter()
    unexpected_hits = Counter()

    for case in cases:
        result = analyze_request(APIRequest.model_validate(case["request"]))
        expected = set(case["expected_rules"])
        observed = {finding.rule_id for finding in result.findings}
        matched = expected & observed
        missed = expected - observed
        flagged = result.verdict in {"Suspicious", "Malicious"}

        if expected:
            outcome = "true positive" if flagged else "false negative"
        else:
            outcome = "false positive" if flagged else "true negative"
        totals[outcome] += 1

        expected_hits.update(expected)
        matched_hits.update(matched)
        unexpected_hits.update(observed - expected)

        expected_text = ", ".join(sorted(expected)) or "-"
        observed_text = ", ".join(sorted(observed)) or "-"
        matched_text = ", ".join(sorted(matched)) or "-"
        missed_text = ", ".join(sorted(missed)) or "-"
        print(
            f"{case['id']:<36} {result.verdict:<10} {result.risk_score:>3} "
            f"{outcome:<14} expected={expected_text} observed={observed_text} "
            f"matched={matched_text} missed={missed_text}"
        )

    print(f"\nRequest-level totals ({len(cases)} cases)")
    for outcome in ("true positive", "false positive", "true negative", "false negative"):
        print(f"  {outcome}: {totals[outcome]}")

    print("\nRule-level totals")
    for rule in sorted(expected_hits.keys() | unexpected_hits.keys()):
        print(
            f"  {rule}: {matched_hits[rule]}/{expected_hits[rule]} expected matches, "
            f"{expected_hits[rule] - matched_hits[rule]} missed, "
            f"{unexpected_hits[rule]} unexpected"
        )


if __name__ == "__main__":
    main()
