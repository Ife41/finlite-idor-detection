[FINDING-REPORT-idor_1.md](https://github.com/user-attachments/files/31100918/FINDING-REPORT-idor_1.md)
# Security Finding Report

**Application:** FinLite
**Reported by:** Abraham Daodu
**Date:** 15/08/2026
**Severity:** High
**Status:** Open

---

## Finding 1: Insecure Direct Object Reference (IDOR) on Invoice Retrieval

### Summary
The invoice detail endpoint retrieves a record by ID with no check confirming the requesting user actually owns that record. Any authenticated user can view any other user's invoice by changing the ID in the request.

### Location
- `GET /invoices/<invoice_id>` (`get_invoice()` in `app.py`)
- `GET /ui/invoices/<invoice_id>` (`invoice_page()` in `app.py`)

### Vulnerable Code
```python
invoice = conn.execute(
    "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
).fetchone()
...
return jsonify(dict(invoice))
```

### Risk
An authenticated but unauthorized user can access another user's financial data (invoice amount, description, ownership) simply by enumerating or guessing invoice IDs. In a financial application, this directly exposes sensitive customer billing information and constitutes a data confidentiality breach. This maps to **OWASP API Security Top 10, API1:2023 Broken Object Level Authorization**.

### Recommended Fix
Add an explicit ownership check comparing the record's owner to the authenticated session before returning data:

```python
invoice = conn.execute(
    "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
).fetchone()

if not invoice or invoice["owner_id"] != session["user_id"]:
    return jsonify({"error": "Invoice not found"}), 404
```

Returning a generic 404 (rather than a 403) for both "doesn't exist" and "not yours" avoids confirming to an attacker that a given ID exists but simply belongs to someone else.

### Detection
A custom Semgrep rule (`idor-missing-ownership-check`) has been written and validated to catch this pattern automatically in CI/CD. See [finlite-idor-detection](https://github.com/Ife41/finlite-idor-detection).

---

## Finding 2: Authorization Decision Based on Client-Controlled Header

### Summary
The endpoint returning all invoices determines admin-level access based on the presence of a client-supplied `X-Admin` HTTP header, rather than the user's actual role stored server-side. Any authenticated user can escalate to admin-level data access by adding this header to their request.

### Location
- `GET /invoices/all` (`get_all_invoices()` in `app.py`)

### Vulnerable Code
```python
is_admin_header = request.headers.get("X-Admin", "false").lower() == "true"

if is_admin_header:
    invoices = conn.execute("SELECT * FROM invoices").fetchall()
```

### Risk
HTTP headers are fully controlled by the client and carry no inherent trust or verification. Any user, regardless of actual privilege level, can set this header manually (via browser dev tools, curl, or an intercepting proxy) and immediately gain access to every invoice in the system, across all users. This is a privilege escalation vulnerability and maps to the same OWASP category as Finding 1 (Broken Object Level Authorization), compounded by a broken trust boundary.

### Recommended Fix
Remove reliance on the header entirely. Authorization decisions must be based only on server-verified data, in this case the role already stored in the session at login:

```python
if session["role"] == "admin":
    invoices = conn.execute("SELECT * FROM invoices").fetchall()
else:
    invoices = conn.execute(
        "SELECT * FROM invoices WHERE owner_id = ?", (session["user_id"],)
    ).fetchall()
```

### Detection
A custom Semgrep rule (`header-based-authz-bypass`) has been written and validated to catch this pattern automatically in CI/CD. See [finlite-idor-detection](https://github.com/Ife41/finlite-idor-detection).

---

## General Recommendation

Both findings share a root cause: authorization checks were either missing or based on untrusted input rather than server-verified session data. Beyond the individual fixes above, this suggests value in:

1. Establishing a consistent authorization pattern/helper function used across all object-access routes, rather than inline checks repeated per-route, reducing the chance of this class of bug recurring.
2. Enforcing the two custom Semgrep rules above as a required, blocking check in CI/CD (already implemented, see linked repository) so this vulnerability class is caught automatically on every future pull request, not only during periodic manual review.
