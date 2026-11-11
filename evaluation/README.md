# Synthetic evaluation

Run from the project root:

```powershell
uv run --locked python evaluation/evaluate.py
```

`requests.json` contains 28 synthetic requests: 14 benign and 14 attacks
(four traversal, four SQL, four shell, and two mixed attacks).
Each case has a unique `id`, a `request` accepted by `APIRequest`, and
`expected_rules`. An empty list labels benign traffic; a nonempty list labels
an attack and names every rule we want to catch it. These labels express
desired behavior, including known gaps, rather than copying current output.

| Rule | Expected technique |
| --- | --- |
| PATH_001 | Path traversal |
| SQL_001 | SQL injection |
| CMD_001 | Shell command injection |

The runner validates each request with `APIRequest.model_validate`, then calls
`analyze_request` directly in-process. No HTTP server is started and payloads
are not executed. The detector runs the registered rules, scores their findings,
and returns the verdict, score, and findings. The runner compares the set of
finding rule IDs with the expected set, counting a rule once per request.

Both `Suspicious` and `Malicious` count as flagged:

| Label | Flagged | Unflagged |
| --- | --- | --- |
| Attack (expected rules present) | True positive | False negative (missed attack) |
| Benign (empty expected rules) | False positive | True negative |

For each request, `matched` is the intersection of expected and observed rules;
`missed` is expected minus observed. Rule totals also count unexpected matches
(observed minus expected). A flagged attack counts as a request-level true
positive even if some or all expected rules are absent; rule totals expose that
incomplete coverage separately.

## Follow two requests through the code

`search-apostrophe` is benign: its query contains `O'Connor`, and its expected
rules list is empty. Validation creates an `APIRequest`; none of the registered
rules produces a finding. The score is 0 and verdict is `Benign`, giving a true
negative. An apostrophe alone is not a SQL tautology.

`sql-query-tautology` expects `SQL_001`: its query filter is
`open' OR 7=7 --`. The SQL rule walks the request strings and recognizes the
self-equality comparison. Its finding contributes 70 points, producing
`Suspicious`: a true positive, with `SQL_001` matched and no expected rule missed.

Benign intent can still trigger a pattern: `ticket-command-example` quotes
`&& curl` in a support ticket and `security-training-snippet` quotes `OR 1=1`
in training material. They intentionally remain labeled benign, exposing false
positives without changing detector behavior.

## Current frozen-engine results

| Request outcome | Count |
| --- | ---: |
| True positive | 13 |
| False positive | 2 |
| True negative | 12 |
| False negative | 1 |

| Rule | Expected matches | Missed | Unexpected |
| --- | ---: | ---: | ---: |
| PATH_001 | 5/5 | 0 | 0 |
| SQL_001 | 6/6 | 0 | 1 |
| CMD_001 | 4/5 | 1 | 1 |

The sole unflagged attack is the Windows single-ampersand shell command
(`shell-single-ampersand-windows`). Current rules decode paths up to twice and
recognize both separator styles, SQL tautologies and UNION SELECT with comment
whitespace, and selected shell operators with named or Unix absolute commands.
Request-level recall is 13/14 (92.9%); the false-positive rate is 2/14 benign
requests (14.3%). These are results for the current frozen working tree.

`combined-traversal-and-sql` matches both expected rules and scores 100
(`Malicious`). `combined-sql-and-shell-partial` expects SQL_001 and CMD_001,
and both now match, scoring 100 (`Malicious`). Its historical fixture ID remains
unchanged. There is one missed expected rule match in total. Rule expectations
total 16 because each mixed request expects two. The runner reports results;
misses and false positives do not themselves cause a nonzero exit status.

These fixtures provide a small synthetic coverage check, not a production
accuracy estimate. This submission documentation update does not change the
detector, scoring, tests, evaluation runner, or fixtures. The complete unit suite
passes 19 tests; see the root README for the test command and architecture.
