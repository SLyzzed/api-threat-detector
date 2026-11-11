# API Threat Detector

A Python command-line tool for examining captured API requests and explaining potentially malicious input. It uses independent, technique-focused rules and a deterministic 0–100 risk score. This project was developed with AI assistance, with the long-term goal of integrating it into my cybersecurity homelab as an additional API threat-detection layer.

The goal is to make detection logic **understandable, testable, and extensible**, rather than to present a production-ready WAF. The tool analyzes JSON requests offline: it does **not** intercept live traffic, execute payloads, or block requests.

## Quick start

Requirements: Python 3.14 and [uv](https://docs.astral.sh/uv/). From the repository root:

~~~powershell
uv sync --locked
~~~

Create a `request.json` file:

~~~json
{
  "method": "POST",
  "path": "/api/tools/lookup",
  "body": {
    "filter": "a' OR 8=8 --",
    "host": "example.com; /usr/bin/id"
  }
}
~~~

Analyze the request:

~~~powershell
uv run --locked api-detection-project request.json
~~~

The same request can be analyzed with `uv run --locked python src/main.py request.json`. To read standard input, pass `-` or omit the argument:

~~~powershell
'{"method":"GET","path":"/health"}' | uv run --locked api-detection-project -
~~~

The CLI takes **one JSON request per invocation** and emits one structured JSON result. Invalid input produces a diagnostic on stderr and exits with status 2; a valid request exits with status 0 regardless of its verdict.

## How it works

~~~text
JSON file or stdin
        |
  Validate APIRequest (Pydantic)
        |
  Extract request string fields
        |
  Run independent detection rules
        |
  Collect structured findings
        |
  Deduplicate and add risk weights (max 100)
        |
  Return verdict, score, explanation and findings
~~~

The detector examines request paths, query parameters, header values, and nested body strings. Traversal detection inspects the path only. The `method` and optional `sourceIp` are retained as metadata, not used to determine risk. Fields are recorded in findings so a reviewer can locate a match.

| Technique | Rule / signal | Example | Weight |
| --- | --- | --- | ---: |
| Path traversal | `PATH_001` · `parent_directory_segment` | `/files/%2e%2e/private` | 65 |
| SQL injection | `SQL_001` · `boolean_tautology` | `OR 1=1` | 70 |
| SQL injection | `SQL_001` · `union_select` | `UNION SELECT` | 70 |
| Shell command injection | `CMD_001` · `shell_operator_with_command` | `&& whoami` | 75 |

The SQL rules recognize supported whitespace and block-comment separators. The command rule handles selected shell operators and command names, including Unix absolute command paths. Traversal applies up to two URL-decoding passes. These are **syntax indicators**, not proof that the backend executed the payload.

The score adds each distinct (rule ID, signal, field) contribution once and caps the result at 100. Verdicts are:

| Score | Verdict |
| --- | --- |
| 0–29 | Benign |
| 30–79 | Suspicious |
| 80–100 | Malicious |

Weights are fixed heuristics, **not probabilities**. In this project, Benign means none of the registered rules matched—not that a request is safe.

## Example output

The mixed SQL and shell request above returns:

~~~json
{
  "verdict": "Malicious",
  "risk_score": 100,
  "explanation": "Matched techniques: sql_injection, command_injection. Risk score: 100/100.",
  "findings": [
    {
      "rule_id": "SQL_001",
      "technique": "sql_injection",
      "signal": "boolean_tautology",
      "field": "body.filter",
      "explanation": "A SQL boolean operator is followed by a self-equality comparison.",
      "evidence": {}
    },
    {
      "rule_id": "CMD_001",
      "technique": "command_injection",
      "signal": "shell_operator_with_command",
      "field": "body.host",
      "explanation": "A shell operator is followed by a recognized command.",
      "evidence": {
        "command": "id"
      }
    }
  ]
}
~~~

A harmless `{"method":"GET","path":"/health"}` returns `Benign`, score 0, and an empty `findings` array.

## Tests and evaluation

~~~powershell
uv run --locked python -m unittest discover -s tests -v
uv run --locked python evaluation/evaluate.py
~~~

The unit tests cover detection patterns, boundary cases, scoring and the subprocess CLI. The evaluation uses [28 labeled synthetic requests](evaluation/requests.json) and a [reproducible runner](evaluation/evaluate.py).

| Request-level outcome | Result |
| --- | ---: |
| Attacks flagged (true positives) | **13 / 14** |
| Attacks missed (false negatives) | 1 / 14 |
| Benign requests accepted (true negatives) | **12 / 14** |
| Benign requests flagged (false positives) | 2 / 14 |
| Unit tests | **19 passed** |

This is **92.9% attack recall on the synthetic evaluation set**, not an estimate of real-world accuracy. The missed attack uses a Windows single-ampersand (`& whoami`). The two false positives are support/training text containing genuine SQL or shell attack syntax. Both are retained to show the limits of pattern matching without trusted application context.

See [evaluation methodology and per-rule results](evaluation/README.md) for the fixture labels and evaluation details.

## Code structure

| Location | Purpose |
| --- | --- |
| `src/api_detection_project/models.py` | Validated request and structured result models |
| `src/api_detection_project/rules/` | Detection rules and shared string extraction |
| `src/api_detection_project/registry.py` | Rule registration and execution |
| `src/api_detection_project/scoring.py` | Signal weights and verdict thresholds |
| `src/api_detection_project/detector.py` | End-to-end request analysis |
| `src/api_detection_project/cli.py` | File/stdin interface |
| `tests/` and `evaluation/` | Regression tests and labeled scenarios |

To introduce a new detector, implement `detect(request)` in a rules module, register it in `registry.py`, assign each emitted signal a weight in `scoring.py`, and add positive/negative tests and evaluation cases. Detection, scoring and presentation remain separate.

## Limitations and future work

- Pattern matches lack endpoint, SQL query-construction, shell-execution, and data-flow context; attack examples in plain text can create false positives.
- Coverage is intentionally narrow. Windows single-`&` chaining, broader SQL/shell variations, query/body traversal and deeper encoding are not fully supported.
- SQL and shell string values are not URL-decoded. There is no HTTP interception, history-based correlation, reputation lookup or ML classification.
- Fixed additive weights can produce high scores for separate suspicious fields. They have not been calibrated against representative traffic.
- The tool has no explicit resource limits or evidence redaction, so it is not ready to process arbitrary live traffic safely.

Next iterations could add trusted application context, broader normalization, redaction and resource controls, and evaluation against more representative labeled requests.
