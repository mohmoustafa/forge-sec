# forge-sec

Deterministic security scanner for backend code, database code, dependencies and secrets.
**No AI, no cloud calls required, no per-scan cost.** Designed to run fully offline inside
closed networks (government/ministerial environments) and to plug into CI as a hard gate.

## What it scans

| Layer | Engine | Coverage |
|---|---|---|
| Source (SAST) | built-in rule engine + intra-file taint + cross-file registry | Python (Django/Flask/FastAPI), JS/TS (Node/Express/NestJS/React), C#/.NET, PHP/Laravel, Vue |
| Frontend | built-in React/Vue/browser rules | dangerouslySetInnerHTML, v-html, javascript: URLs, localStorage tokens, postMessage, target=_blank |
| Database | dedicated SQL rules + migration checks | `.sql` files: broad grants, destructive stmts, dynamic SQL, weak users, missing RLS, plaintext passwords |
| Secrets | built-in patterns (+ gitleaks when present) | private keys, AWS tokens, JWTs, conn strings, `.env`, Slack/GitHub/Stripe tokens |
| Dependencies (SCA) | OSV.dev batch API + CISA KEV + FIRST EPSS | `requirements*.txt`, `Pipfile.lock`, `package-lock.json`, `composer.lock`, `*.csproj`, `packages.lock.json`, `pom.xml`, `Gemfile.lock`, `go.mod`, `Cargo.lock` |
| Container / IaC | built-in IaC rules | Dockerfile, docker-compose, nginx.conf, appsettings.json |
| Git history | built-in secrets rules over `git log -p` | secrets committed then "deleted" still living in history |
| External (optional) | bandit, semgrep, gitleaks, trivy | auto-detected; used when installed or Docker is running |

Every finding carries: severity, confidence, CWE, OWASP, file:line, code snippet,
remediation, suggested fix, stable fingerprint, and — for CVEs — KEV exploit status
and EPSS probability. Findings are deduplicated across engines.
High-entropy literals are also flagged (entropy-based secret detection, SEC-ENT-001).

## Honest scope

No scanner finds 100 % of vulnerabilities. This tool maximises deterministic coverage
by combining a rule engine, intra-file taint tracking, a cross-file sink registry and
the public advisory feeds — but security review still matters. Deep inter-procedural
analysis needs Semgrep, which the tool uses automatically when available.

## Install

```bash
pip install -e .          # from this folder (needs Python 3.10+)
# optional extras:
pip install bandit        # deeper Python analysis
# semgrep / gitleaks / trivy binaries or Docker Desktop -> auto-detected
```

## Usage

```bash
forge-sec scan ./my-project                 # full scan -> HTML + JSON + SARIF
forge-sec scan . --format sarif             # CI artifact only
forge-sec scan . --offline                  # no network calls at all
forge-sec scan . --save-baseline            # remember current findings
forge-sec scan . --new-only                 # report only NEW findings vs baseline
forge-sec scan . --fail-on CRITICAL         # exit 1 only on critical+
forge-sec scan . --workers 8                # parallel file scanning
forge-sec scan . --no-cache                 # ignore incremental cache
forge-sec scan . --history                  # find secrets in git history too
forge-sec scan . --confidence high          # only high-confidence findings
forge-sec scan . --deep --history           # + unreachable git objects (fsck)
forge-sec deps .                            # dependency CVE check only (fast)
forge-sec image nginx:latest                # container image scan (needs trivy or Docker)
forge-sec dbcheck --dsn "host=db dbname=app user=ro password=x"  # live Postgres RLS/roles
forge-sec dbcheck --dsn "mysql://u:p@db:3306/app"                  # MySQL checks
forge-sec dbcheck --dsn "u/p@dbhost:1521/svc"                      # Oracle DBA/VPD checks
forge-sec watch . --interval 30             # poll tree, alert only on NEW findings
forge-sec trend .                           # scan history + severity sparkline (sqlite)
forge-sec rules                             # list the built-in rules
```

### Speed

- **Incremental**: files are sha1-cached in `.forge-sec/cache/`; unchanged files are
  skipped, so re-scans and CI runs are near-instant.
- **Literal prefilter**: each rule's required fixed strings are extracted; if the text
  can't contain them the rule is skipped entirely.
- **Cross-file taint**: functions that pass a parameter into a sink are registered
  project-wide; call sites in other files feeding them request data are flagged.
- **Parallel**: `--workers N` (default 4) scans files across CPU processes.
- **.gitignore-aware**: ignored paths are skipped automatically.

### Inline suppression

```python
subprocess.run(cmd, shell=True)   # forge-sec-ignore PY-002
```
`forge-sec-ignore` on the same line (or the line above) suppresses that rule there;
`forge-sec-ignore` alone suppresses all rules on that line; a top-of-file
`forge-sec-ignore-file` comment skips the whole file. Prefer `.forge-sec.yml`
`disabled_rules` for repo-wide decisions.

Exit code is `1` when any finding >= `--fail-on` (default `HIGH`) — a real CI gate.

## Configuration — `.forge-sec.yml` in the repo root

```yaml
excludes: ["docs/*", "*.generated.cs"]
disabled_rules: ["PY-006"]
severity_overrides: {"SQL-005": "LOW"}
offline: false
fail_on: HIGH
```

Custom rules: drop YAML files in `.forge-sec/rules/` — same schema as
`forge_sec/rules_builtin/*.yml` (`pattern`, `taint`, `file`/`absent` types).

## Reports

- **HTML** (`.forge-sec/reports/forge-sec-report.html`): self-contained interactive
  report — severity filters, search, code snippets, suggested fixes, KEV badges.
- **JSON**: machine-readable full detail.
- **SARIF**: standard format — upload to GitHub code scanning / any SAST dashboard.
- **JUnit XML** + **Markdown** (PR comment) via `--format junit|markdown|all`.
- `--new-only` findings get a green **NEW** badge in the HTML report.

## Scheduled threat watch

Run nightly to catch NEW CVEs landing on your existing dependency set:

```bash
forge-sec scan . --new-only --format json
```

OSV/KEV responses are cached 24 h in `.forge-sec/cache/`. In air-gapped networks,
ship the cache directory and run with `--offline`.

## Layout

```
forge_sec/
  cli.py                  commands: scan deps rules image dbcheck watch trend
  models.py               Finding + dedup + fingerprints
  config.py               .forge-sec.yml + .gitignore folding
  scancache.py            incremental sha1 cache
  history.py              git history + fsck unreachable secrets
  dbcheck.py              live Postgres/MySQL/Oracle checks
  trend.py                sqlite scan history + sparkline
  baseline.py             fingerprint diffing for --new-only
  engine/
    walker.py             file discovery + language detect
    rules.py              YAML rule loader (pattern | taint | file/absent)
    pattern_engine.py     rule exec + literal prefilter + entropy + parallel
    crossfile.py          cross-file sink-carrying function registry
    external/engines.py   bandit | semgrep | gitleaks | trivy adapters
  rules_builtin/          secrets python node dotnet php sql iac frontend (102 rules)
  sca/                    manifests (10 ecosystems), osv, kev/epss, cvss scorer
  report/                 html, sarif, junit, markdown
ci/                       github-action.yml + pre-commit hook template
tests/fixtures/vulnapp/   deliberately vulnerable sample (all languages)
```

## Quick self-test

```bash
pip install -e . pytest
pytest tests/                       # 9 tests incl. planted-bug detection
forge-sec scan tests/fixtures/vulnapp   # ~60 findings incl. planted SQLi/RCE/secrets
```
