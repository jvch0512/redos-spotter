# redos-spotter

A regular expression that backtracks exponentially lets one crafted string freeze a service. redos-spotter reads patterns (one per line), parses them, flags nested quantifiers, overlapping alternations and chains of overlapping loops, and then confirms each finding by running a built-in backtracking matcher on a generated attack string and counting steps. You see the evidence, not just a warning.

**Live demo:** https://jvch0512.github.io/redos-spotter/ (A mix of well-known vulnerable patterns and safe ones.)

Common Lisp (SBCL), no libraries. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make test
./bin/redos-spotter examples/patterns.txt
./bin/redos-spotter examples/patterns.txt --tsv
./bin/redos-spotter patterns.txt --fail-on high      # exit 1 in CI
```

Input is a text file with one pattern per line. Lines starting with `#` and empty lines are ignored. To pull patterns out of a codebase, extract them first with `grep`, then feed the list in.

| Rule | Severity | Meaning |
|---|---|---|
| REDOS001 | high | a loop inside a loop whose iterations can split the same text in many ways, for example `(a+)+` or `([a-z]+\s?)+` |
| REDOS002 | high | a loop over an alternation with overlapping branches, for example `(a\|a)*` or `(\w\|\d)+` |
| REDOS003 | medium or high | adjacent loops over overlapping characters, for example `.*.*` (quadratic) or three in a row (cubic) |
| REDOS000 | info | the pattern uses syntax the analyser does not model |

Each finding says whether the built-in matcher confirmed the blow-up and shows the step counts.

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It models the common syntax: literals, classes, `.`, groups, alternation, `* + ? {n,m}`, lazy and possessive suffixes. Backreferences and lookarounds are not modelled and are reported as REDOS000.
- The engine in the probe is a plain backtracking matcher. Real engines differ (some have memoisation or timeouts), so a confirmed pattern is dangerous in a backtracking engine, not necessarily in yours.
- The attack string has no prefix. Patterns that need context before the vulnerable part may show as "not confirmed" even though they are exploitable.
- Equal-length overlapping branches are detected. Overlap between branches of different lengths is not.

## Where it fits

Secure code review and appliance or WAF rule review: a defensible list of patterns that can be used to freeze a service, with evidence a developer can reproduce.

## Tests

```bash
make test    # 75 checks
```

MIT.
