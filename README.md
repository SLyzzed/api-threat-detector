# API Threat Detector

An explainable Python engine for analyzing captured API requests using independent detection rules and a 0–100 risk score. Its objectives are modular detection, deterministic scoring, useful explanations, and reproducible evaluation. This feature-frozen assignment implementation is an offline CLI and Python library: it does not intercept HTTP traffic, execute payloads, or block requests.

## Installation and execution

Run commands from the repository root with uv and Python 3.14 installed. `.python-version` selects 3.14; `pyproject.toml` requires Python >=3.14, declares Pydantic, and uses the `uv_build` backend. `uv.lock` pins dependency resolution. Initial setup may require network access.

```powershell
uv sync --locked
```

Save an example below as UTF-8 `request.json`, then run either supported entry point:

```powershell
uv run --locked api-detection-project request.json
uv run --locked python src/main.py request.json
```

For standard input in PowerShell:

```powershell
'{"method":"GET","path":"/health"}' | uv run --locked api-detection-project -
```

Omitting the input argument also reads stdin. Each invocation accepts one JSON object, not a batch or JSON Lines stream. Valid requests exit with status 0, including flagged requests. Input errors exit with status 2 and a diagnostic on stderr; exit status is not the threat verdict.

### Input contract

| Field | Type / default | Use |
| --- | --- | --- |
| `method` | Required string | Metadata; no method-specific detection |
| `path` | Required string | Inspected by all three rules |
| `sourceIp` | Optional string or null | Metadata; no IP reputation lookup |
| `headers` | Object of string values; `{}` | Values inspected by SQL and command rules |
| `query` | Object; `{}` | Nested string values inspected by SQL and command rules |
| `body` | Any JSON value; null | Nested string values inspected by SQL and command rules |

Additional top-level fields are accepted but not scanned by registered rules. Object keys, numbers, booleans, and nulls are not scanned as payload strings. Pydantic validates the schema, but HTTP method, path syntax, and IP address semantics are not validated. UTF-8 BOM input is accepted; malformed JSON and NaN/Infinity values are rejected.

## Architecture and request-processing pipeline

```text
UTF-8 JSON file / stdin
  -> cli.py: read bytes, parse JSON, validate APIRequest
  -> detector.py: analyze_request(request)
  -> registry.py: run every registered rule in insertion order
  -> rules/*.py: return independent DetectionFinding objects
  -> scoring.py: deduplicate contributions, sum weights, cap at 100
  -> scoring.py: map score to verdict
  -> detector.py: build DetectionResult and overall explanation
  -> cli.py: serialize JSON to stdout
```

| Component | Responsibility |
| --- | --- |
| `src/main.py`, package `__init__.py` | Script and installed CLI entry points |
| `src/api_detection_project/cli.py` | Parsing, validation, errors, output |
| `src/api_detection_project/models.py` | Request, finding, and result schemas |
| `src/api_detection_project/detector.py` | Analysis orchestration and overall explanation |
| `src/api_detection_project/registry.py` | Explicit dictionary of rule callables and aggregation |
| `src/api_detection_project/rules/` | Independent detection modules and shared string traversal |
| `src/api_detection_project/scoring.py` | Weights, contribution deduplication, thresholds |
| `tests/` | Detection, scoring, and subprocess CLI unit tests |
| `evaluation/` | Labeled synthetic fixtures, evaluation runner, notes |

SQL and command rules share `request_fields.request_strings`, which walks path, query, headers, and body strings, including nested objects and arrays. Field locations such as `body.credentials.username` and `body["user.name"][1].value` identify the source. Traversal inspects only `path`. All rules run; a match does not stop later rules. No external detection services or learned models are used.

## Supported detection techniques

| Rule / technique | Signal | Matching behavior | Weight |
| --- | --- | --- | ---: |
| `PATH_001` / `path_traversal` | `parent_directory_segment` | Complete `..` path segment after up to two URL decodes; forward and backslash separators recognized | 65 |
| `SQL_001` / `sql_injection` | `boolean_tautology` | `OR` or `AND` followed by simple integer or quoted-string self-equality | 70 |
| `SQL_001` / `sql_injection` | `union_select` | `UNION` followed by `SELECT` | 70 |
| `CMD_001` / `command_injection` | `shell_operator_with_command` | `&&`, `\|\|`, `;`, `\|`, or `$(` followed by a recognized command, optionally with a Unix absolute path | 75 |

SQL and command patterns are case-insensitive. SQL accepts whitespace and complete `/* ... */` comments between supported tokens. It emits at most one finding per string field, preferring tautology when both SQL signals match. Recognized command names are `whoami`, `id`, `cat`, `curl`, `wget`, `bash`, `sh`, `cmd`/`cmd.exe`, and `powershell`/`powershell.exe`, with a command boundary. The command rule emits at most one finding per string field. Traversal emits at most one finding per request; `report..draft.pdf` is not a parent-directory segment.

SQL and command rules inspect values as supplied, without URL decoding. Only traversal applies decoding. Matches indicate suspicious syntax, not proof of backend execution.

## Risk scoring and verdicts

`calculate_risk` adds a weight once per distinct `(rule_id, signal, field)` tuple and caps the sum at 100. Repeated occurrences in one field do not add weight; the same signal in different fields does. Findings themselves are retained. An unconfigured `(rule_id, signal)` raises `ValueError`, even after earlier contributions reach the cap.

| Score | Verdict |
| --- | --- |
| 0–29 | `Benign` |
| 30–79 | `Suspicious` |
| 80–100 | `Malicious` |

Weights and thresholds are fixed heuristics, not calibrated probabilities. A single current finding yields `Suspicious` (65, 70, or 75); two distinct current contributions reach the capped score of 100. With the current rules and weights, `Benign` means no registered rule matched, not that the request is safe.

## Real input/output examples

Save an input as `request.json` and use either file command above. Outputs are from the current engine. Each finding includes its rule ID, technique, signal, field, explanation, and evidence; evidence may be empty.

### Benign request

Input:

```json
{"method":"GET","path":"/health"}
```

Output:

```json
{
  "verdict": "Benign",
  "risk_score": 0,
  "explanation": "No registered rule matched.",
  "findings": []
}
```

### Suspicious traversal

Input:

```json
{"method":"GET","path":"/api/files/%2e%2e/secrets"}
```

Output:

```json
{
  "verdict": "Suspicious",
  "risk_score": 65,
  "explanation": "Matched techniques: path_traversal. Risk score: 65/100.",
  "findings": [
    {
      "rule_id": "PATH_001",
      "technique": "path_traversal",
      "signal": "parent_directory_segment",
      "field": "path",
      "explanation": "Path contains parent-directory navigation.",
      "evidence": {"decoded_path": "/api/files/../secrets"}
    }
  ]
}
```

### Malicious combined SQL and command patterns

Input:

```json
{"method":"POST","path":"/api/tools/lookup","body":{"filter":"a' OR 8=8 --","host":"example.com; /usr/bin/id"}}
```

Output:

```json
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
      "evidence": {"command": "id"}
    }
  ]
}
```

## Modular rules and future extension

Rules follow `Callable[[APIRequest], list[DetectionFinding]]`. Each module exposes `detect(request)`, returning an empty list for no match and structured findings otherwise. Detection is separate from scoring and CLI presentation. Registration is explicit; adding a file alone does not activate a rule.

After the feature freeze is lifted, additional rules can be introduced by:

1. Adding a module under `src/api_detection_project/rules/` with `detect(request: APIRequest) -> list[DetectionFinding]`. Reuse `request_strings` when its field coverage suits the technique.
2. Assigning a stable rule ID and signal names, precise field locations, explanations, and useful evidence. Keep detection independent of scoring and avoid modifying the request.
3. Importing the module in `registry.py` and adding its callable to `RULES` so it runs for every analysis.
4. Adding a weight for every emitted `(rule_id, signal)` in `scoring.py`'s `SIGNAL_WEIGHTS`; missing weights fail analysis.
5. Adding positive, negative, and boundary unit tests and independently labeled evaluation cases, then rerunning the suite and evaluation and reporting coverage and false positives.

These are extension instructions only; this documentation update leaves the engine, tests, and fixtures frozen.

## Testing and evaluation

Run the full standard-library unittest suite:

```powershell
uv run --locked python -m unittest discover -s tests -v
```

Run the synthetic evaluation:

```powershell
uv run --locked python evaluation/evaluate.py
```

The runner loads `evaluation/requests.json`, validates each request, and calls `analyze_request` in-process. It prints verdicts, scores, expected/observed rules, matched/missed rules, and totals. The fixture array is for this runner and cannot be passed directly to the single-request CLI. No payloads are executed.

Verified results for the current frozen working tree:

| Check | Result |
| --- | --- |
| Unit tests | **19 passing**: 4 CLI, 12 detection, 3 scoring tests; some contain multiple subcases |
| Attacks detected | **13/14** (92.9% request-level recall) |
| False positives | **2/14** benign requests (14.3% false-positive rate) |
| True negatives | 12/14 benign requests |
| Missed attacks | 1/14 attacks |

| Rule | Expected matches detected | Missed | Unexpected matches |
| --- | ---: | ---: | ---: |
| `PATH_001` | 5/5 | 0 | 0 |
| `SQL_001` | 6/6 | 0 | 1 |
| `CMD_001` | 4/5 | 1 | 1 |

Both `Suspicious` and `Malicious` count as flagged. A flagged attack is a request-level true positive even if an expected rule is absent; rule totals measure expected coverage separately. Mixed cases expect two rules, giving 16 expected rule matches across 14 attack requests. The evaluation runner reports results for inspection; a miss or false positive does not itself cause a nonzero exit status.

The missed fixture is `shell-single-ampersand-windows` (`127.0.0.1 & whoami`): `Benign`, score 0. The two false positives are benign support-ticket text quoting `&& curl` and training material quoting `OR 1=1`. Both mixed cases now match both expected rules and score 100; the historical fixture ID `combined-sql-and-shell-partial` remains unchanged. These 28 synthetic requests are a coverage check, not a production accuracy estimate. See [evaluation notes](evaluation/README.md) for label semantics.

Check the tracked diff for whitespace errors:

```powershell
git diff --check
```

## Known limitations and future improvements

- Patterns cannot distinguish attack intent from documentation or training text. No application, endpoint, database, or shell execution context is modeled.
- Traversal inspection covers only `path`, up to two decoding passes, and complete parent-directory segments. Query/body traversal and deeper encoding can evade it.
- SQL coverage is limited to the listed patterns; there is no SQL parser or comprehensive dialect/obfuscation support. Commands use a short name list and selected operators; single `&`, backticks, and other shell syntax are not covered.
- SQL and command strings are not decoded. Metadata, object keys, and unknown top-level fields are not scanned. There is no XSS, SSRF, authentication-abuse, rate-anomaly, reputation, or cross-request correlation detection.
- Fixed additive scores can reach 100 from the same signal in different fields. They are not calibrated against representative traffic.
- No live HTTP integration, persistence, performance benchmark, or explicit input-size/depth limit is provided. Large or deeply nested untrusted inputs need resource controls before operational use. Findings can contain sensitive request content.

Future work could add application-aware handling, broader normalization and shell/SQL coverage, independently reviewed traffic datasets, score calibration, resource limits and performance measurements, and an integration layer with evidence redaction. These are proposals, not implemented capabilities.

## Submission checklist

The repository contains the implementation, unit tests, dependency lockfile, and synthetic evaluation. No assignment brief or marking rubric is included, so additional requirements such as a separate report, presentation, packaging format, or mandated interface cannot be confirmed from the repository alone.

Before submission, compare deliverables with the actual rubric, include `evaluation/` and all intended existing rule/scoring/test changes in the submitted snapshot, and repeat setup, tests, and evaluation from a clean copy. Exclude `.venv`, caches, and secrets. Review the final diff and ensure the submitted snapshot reproduces these results.
