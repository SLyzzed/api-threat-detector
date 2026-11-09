# API Threat Detector

Analyze a captured API request with independent detection rules and a 0-100 risk score. Requires Python 3.14 and uv.

## Run

```sh
uv sync --locked
uv run api-detection-project request.json
uv run api-detection-project -  # reads from stdin
```

`uv run python src/main.py request.json` is also supported. Input is one UTF-8 JSON object with string `method` and `path`. Optional fields include `sourceIp`, `headers` (string values), `query` (an object), and `body` (any JSON value).

Example `request.json`:

```json
{"method":"GET","path":"/api/files/%2e%2e/secrets"}
```

The CLI writes a JSON object with `verdict`, `risk_score`, `explanation`, and `findings` to stdout. The example returns `Suspicious` with score 65 and a `PATH_001` finding containing the decoded path. Each finding includes its rule ID, technique, signal, field, explanation, and evidence. All valid requests exit with status 0. Input errors exit with status 2 and a diagnostic on stderr.

## Rules and scoring

| Rule | Matches | Points |
| --- | --- | ---: |
| `PATH_001` | A `..` path segment after one URL decode | 65 |
| `SQL_001` | SQL boolean operators followed by simple self-equality, such as `OR 1=1` | 70 |
| `CMD_001` | A shell operator followed by a recognized command, such as `&& whoami` | 75 |

SQL and command rules inspect strings in the path, headers, query values, and body, including nested objects and arrays. These rules inspect the values as supplied. Pattern matches and scores are heuristic signals for triage.

Scoring counts each rule/signal/field combination once and caps the sum at 100. Verdicts are Benign (0-29), Suspicious (30-79), and Malicious (80-100). Add a detector under `src/api_detection_project/rules/`, register it in `registry.py`, and configure its signal weights in `scoring.py`.

## Test

```sh
uv run --locked python -m unittest discover -s tests -v
```
