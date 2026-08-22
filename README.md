[finlite-idor-detection-README.md](https://github.com/user-attachments/files/31337806/finlite-idor-detection-README.md)
# Custom SAST Rules for IDOR/BOLA Detection

Static analysis rules and a CI/CD pipeline that catch IDOR (Insecure Direct Object Reference, also known as Broken Object Level Authorization) before code reaches production. Tested against [FinLite](https://github.com/Ife41/finlite-vulnerable-webapp), a fintech-style app built specifically as a target.

IDOR is one of the most common vulnerabilities in financial applications, and it doesn't follow one detectable pattern. Generic scanners tend to catch injection bugs easily but miss authorization logic almost entirely, since that depends on how a specific app is written. This project takes a different approach: rules written for known-vulnerable patterns found in a real codebase, rather than relying on off-the-shelf detection to catch something it was never designed to catch.

---

## What's in this repo

| File | Purpose |
|---|---|
| `semgrep-rules/idor-missing-ownership-check.yaml` | Flags a record fetched by ID and returned with no check confirming the requesting user owns it |
| `semgrep-rules/header-based-authz-bypass.yaml` | Flags an authorization decision based on a client-controlled HTTP header instead of a server-verified value |
| `.github/workflows/security-scan.yml` | GitHub Actions pipeline that runs both rules on every push and pull request, failing the build if either pattern is found |
| `findings/FINDING-REPORT-idor.md` | Write-up of both vulnerabilities as found in FinLite, including risk, location, vulnerable code, and recommended fix |

---

## The two vulnerabilities, in short

**1. Missing ownership check**
```python
invoice = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
return jsonify(dict(invoice))
```
Any authenticated user can retrieve any record just by changing the ID, since ownership is never checked against the session.

**2. Client-controlled header trusted for authorization**
```python
is_admin_header = request.headers.get("X-Admin", "false").lower() == "true"
if is_admin_header:
    invoices = conn.execute("SELECT * FROM invoices").fetchall()
```
Access level is decided by a header the client fully controls, instead of the role already stored server-side in the session.

Full risk analysis and recommended fixes for both are in [`findings/FINDING-REPORT-idor.md`](findings/FINDING-REPORT-idor.md).

---

## How the rules were validated

Each rule was tested against both the vulnerable version and a safe version of the same function, to confirm it actually tells the two apart rather than just flagging anything that looks roughly similar.

| Rule | Flags vulnerable version | Ignores safe version |
|---|---|---|
| `idor-missing-ownership-check` | Yes | Yes |
| `header-based-authz-bypass` | Yes | Yes |

---

## Running the rules locally

```bash
pip3 install semgrep --break-system-packages
git clone https://github.com/Ife41/finlite-idor-detection.git
cd finlite-idor-detection
semgrep --config semgrep-rules/ --error /path/to/app.py
```

## CI/CD pipeline

The included GitHub Actions workflow (`.github/workflows/security-scan.yml`) runs both rules automatically on every push and pull request. If either pattern shows up, the build fails, so the change can't be merged or deployed until it's fixed.

```yaml
name: IDOR Security Scan

on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Semgrep
        run: |
          python3 -m pip install pipx
          pipx install semgrep
          pipx ensurepath
      - name: Run custom IDOR rules
        run: semgrep --config semgrep-rules/ --error app.py
```

---

## Why two separate rules instead of one

IDOR isn't a single pattern. It's a category of missing or misplaced authorization logic that shows up differently depending on how a route happens to be written. A rule built for one exact code shape will miss other versions of the same underlying flaw. That happened during development here: the first rule, built to catch a missing ownership check, didn't catch the second vulnerability at all, because the two look nothing alike in code even though both are IDOR. Getting real coverage on this vulnerability class means building up a small library of targeted rules over time, not writing one rule and calling it solved.

---

## Related projects

- [enterprise-homelab-pentest](https://github.com/Ife41/enterprise-homelab-pentest): self-built Windows Server infrastructure lab, configured and then penetration tested
- [finlite-vulnerable-webapp](https://github.com/Ife41/finlite-vulnerable-webapp): the application these rules were built and tested against, including its full vulnerability index and code walkthrough

## Roadmap

- [ ] More rules for other IDOR variants as they come up
- [ ] A fixed version of FinLite's vulnerable endpoints, to show the pipeline passing on corrected code
- [ ] Expand detection to cover mass assignment and other authorization-adjacent patterns
