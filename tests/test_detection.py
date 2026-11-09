import unittest

from api_detection_project.detector import analyze_request
from api_detection_project.models import APIRequest, DetectionFinding
from api_detection_project.registry import run_rules
from api_detection_project.scoring import calculate_risk, classify_risk


class DetectionTests(unittest.TestCase):
    def test_benign_request(self):
        request = APIRequest(
            method="GET",
            path="/api/files/report..pdf",
            query={"page": 1, "enabled": True, "labels": ["research and development"]},
            body={"notes": ["or 1=10", "or 1=1.5", "formats; category"]},
        )
        self.assertEqual(
            analyze_request(request).model_dump(),
            {
                "verdict": "Benign",
                "risk_score": 0,
                "explanation": "No registered rule matched.",
                "findings": [],
            },
        )

    def test_path_traversal_regression(self):
        for path in ("/api/files/../secrets", "/api/files/%2e%2e/secrets"):
            with self.subTest(path=path):
                result = analyze_request(APIRequest(method="GET", path=path))
                self.assertEqual((result.risk_score, result.verdict), (65, "Suspicious"))
                self.assertEqual(len(result.findings), 1)
                self.assertEqual(
                    result.findings[0].model_dump(),
                    {
                        "rule_id": "PATH_001",
                        "technique": "path_traversal",
                        "signal": "parent_directory_segment",
                        "field": "path",
                        "explanation": "Path contains parent-directory navigation.",
                        "evidence": {"decoded_path": "/api/files/../secrets"},
                    },
                )

    def test_sql_tautology_in_a_nested_array(self):
        request = APIRequest(
            method="POST",
            path="/search",
            body={"user.name": [None, {"value": "admin' oR 'x' = 'x' --"}]},
        )
        result = analyze_request(request)
        self.assertEqual((result.risk_score, result.verdict), (70, "Suspicious"))
        self.assertEqual(
            [(f.rule_id, f.signal, f.field) for f in result.findings],
            [("SQL_001", "boolean_tautology", 'body["user.name"][1].value')],
        )

    def test_command_rule_in_string_body(self):
        request = APIRequest(method="POST", path="/ping", body="localhost && WHOAMI")
        result = analyze_request(request)
        self.assertEqual((result.risk_score, result.verdict), (75, "Suspicious"))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].field, "body")
        self.assertEqual(result.findings[0].evidence, {"command": "whoami"})

    def test_registry_combines_rules_and_distinguishes_fields(self):
        request = APIRequest(
            method="POST",
            path="/api/files/%2E%2E/secrets",
            query={"q": "a OR 1=1 OR 1=1"},
            headers={"X-Trace": "x; powershell.exe -NoProfile"},
            body={"q": "a OR 1=1"},
        )
        findings = run_rules(request)
        self.assertEqual(
            [(f.rule_id, f.field) for f in findings],
            [
                ("PATH_001", "path"),
                ("SQL_001", "query.q"),
                ("SQL_001", "body.q"),
                ("CMD_001", 'headers["X-Trace"]'),
            ],
        )
        result = analyze_request(request)
        self.assertEqual((result.risk_score, result.verdict), (100, "Malicious"))
        for technique in ("path_traversal", "sql_injection", "command_injection"):
            self.assertIn(technique, result.explanation)


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.finding = DetectionFinding(
            rule_id="PATH_001",
            technique="path_traversal",
            signal="parent_directory_segment",
            field="path",
            explanation="Traversal detected.",
        )

    def test_duplicates_do_not_add_weight_but_other_fields_do(self):
        duplicate = self.finding.model_copy(update={"evidence": {"decoded_path": "../a"}})
        different_field = self.finding.model_copy(update={"field": "query.file"})
        self.assertEqual(calculate_risk([self.finding, duplicate]), 65)
        self.assertEqual(calculate_risk([self.finding, different_field]), 100)

    def test_unknown_signal_fails_even_after_score_reaches_cap(self):
        another_field = self.finding.model_copy(update={"field": "query.file"})
        unknown = self.finding.model_copy(update={"signal": "unconfigured"})
        with self.assertRaisesRegex(ValueError, "Missing score"):
            calculate_risk([self.finding, another_field, unknown])

    def test_classification_boundaries(self):
        for score, expected in [
            (0, "Benign"),
            (29, "Benign"),
            (30, "Suspicious"),
            (79, "Suspicious"),
            (80, "Malicious"),
            (100, "Malicious"),
        ]:
            with self.subTest(score=score):
                self.assertEqual(classify_risk(score), expected)
