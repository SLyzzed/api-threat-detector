import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "main.py"


class CLITests(unittest.TestCase):
    def run_cli(self, *args, data=b""):
        return subprocess.run(
            [sys.executable, str(_SCRIPT), *args],
            input=data,
            capture_output=True,
            timeout=10,
        )

    def test_unseen_file_returns_complete_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unseen request.json"
            path.write_text(
                json.dumps({
                    "method": "POST",
                    "path": "/exports/%2e%2e/internal",
                    "sourceIp": "192.0.2.15",
                    "body": {"filter": "public' OR 42=42 --"},
                    "requestId": "example-42",
                }),
                encoding="utf-8-sig",
            )
            process = self.run_cli(str(path))

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, b"")
        output = json.loads(process.stdout)
        self.assertEqual(set(output), {"verdict", "risk_score", "explanation", "findings"})
        self.assertEqual((output["verdict"], output["risk_score"]), ("Malicious", 100))
        self.assertEqual(
            [finding["field"] for finding in output["findings"]],
            ["path", "body.filter"],
        )

    def test_stdin_explicit_and_default(self):
        for args in [("-",), ()]:
            with self.subTest(args=args):
                process = self.run_cli(*args, data=b'{"method":"GET","path":"/status"}')
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertEqual(json.loads(process.stdout)["verdict"], "Benign")

    def test_rejects_invalid_json_and_schema_without_writing_stdout(self):
        for data, message in [
            (b"{", b"invalid JSON"),
            (b'{"method":"GET","path":"/","body":NaN}', b"invalid JSON"),
            (b'{"method":"GET","path":"/\\ud800/../secret"}', b"invalid JSON"),
            (b"[]", b"invalid API request"),
            (b'{"path":"/status"}', b"invalid API request"),
            (b'{"method":"GET","path":"/","headers":{"x":123}}', b"invalid API request"),
        ]:
            with self.subTest(data=data):
                process = self.run_cli("-", data=data)
                self.assertEqual(process.returncode, 2)
                self.assertEqual(process.stdout, b"")
                self.assertIn(message, process.stderr)

    def test_missing_file_reports_read_error(self):
        with tempfile.TemporaryDirectory() as directory:
            process = self.run_cli(str(Path(directory) / "missing.json"))
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertIn(b"could not read input", process.stderr)
