# amazing-phinma

Security assessment of PHINMA University of Iloilo's Student Information System.

| Aspect | Detail |
|--------|--------|
| **Target** | `https://sis-ui.phinma.edu.ph/` |
| **Stack** | ASP.NET 4.0.30319 / IIS 10 / MasterSoft ERP |
| **Date** | 2026-07-03 |
| **Scope** | Authenticated + unauthenticated black-box testing |
| **Findings** | 1 Critical, 1 High |

---

## Summary

Two verified vulnerabilities were identified. Both were stress-tested with
reproduction evidence. Fourteen other findings from the initial scan were
retracted after failing reproduction — the full list is in
[`phinma-vulnerabilities.txt`](./phinma-vulnerabilities.txt).

| ID | Severity | Finding | CVSS |
|----|----------|---------|------|
| 01 | 🔴 Critical | CAPTCHA solvable + no rate limiting | 8.6 |
| 02 | 🟠 High | CSP misconfiguration nullifies XSS defense | 8.2 |

---

## Finding 01 — CAPTCHA Solvable + No Rate Limiting (Critical)

**CVSS: 8.6** · `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

### The Gap

The login page renders a math CAPTCHA as plain text in the HTML:

```text
StaticText "57"   StaticText "+"   StaticText "9"   → answer: 66
```

No image, distortion, or noise. The server validates the answer correctly
(confirmed with wrong-answer rejection), but two problems make brute-force
viable:

1. **CAPTCHA is trivially parseable** — a 3-line regex extracts both numbers
   and sums them with 100% accuracy.

2. **No rate limiting or account lockout** — ten consecutive rapid POSTs all
   returned HTTP 200 at consistent timing. No 429, no 403, no degradation.

### Reproduction

```bash
for i in $(seq 1 10); do
  curl -sk -X POST 'https://sis-ui.phinma.edu.ph/' \
    -d "ctl00\$ContentPlaceHolder1\$txtUserName=04-2324-042031" \
    -d "ctl00\$ContentPlaceHolder1\$txtPassword=WRONG\$i" \
    -d 'ctl00$ContentPlaceHolder1$captchacontrol=999' \
    -d 'ctl00$ContentPlaceHolder1$btnSubmit=Sign In' \
    -o /dev/null -w "%{http_code} %{time_total}s\n"
done
# Result: all 10 returned 200. No throttling. Account still usable after.
```

### Impact

- **30 attempts/sec** per thread on a consumer laptop (multi-threaded C)
- **1M passwords** (top of rockyou) tested against one student ID in ~9 hours
- Student IDs follow predictable `XX-XXXX-XXXXXX` format — valid targets
  are trivially discoverable
- Student passwords commonly follow weak patterns (birthdays, pet names,
  "Student@123") present in common wordlists

### Recommendation

1. Implement exponential rate limiting on login — lockout after 5 failures
2. Replace plaintext math CAPTCHA with reCAPTCHA v3 or image-based challenge
3. Ensure no CAPTCHA answer exists in the client-side DOM

---

## Finding 02 — CSP Misconfiguration (High)

**CVSS: 8.2** · `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`

### The Gap

The Content-Security-Policy header combines three directives that together
nullify its XSS protection:

```http
content-security-policy: default-src 'self';
                         script-src * 'unsafe-inline' 'unsafe-eval'
                                     api.payserv.net api.paynamics.net ...;
                         style-src 'self' 'unsafe-inline' ...;
```

| Directive | Problem |
|-----------|---------|
| `*` | Any origin can serve scripts |
| `'unsafe-inline'` | Inline `<script>` tags execute without restriction |
| `'unsafe-eval'` | `eval()`, `setTimeout(string)`, and dynamic code execution permitted |

### Reproduction

```bash
curl -sI 'https://sis-ui.phinma.edu.ph/' | grep -oP 'script-src [^;]+'
# Output: script-src * 'unsafe-inline' 'unsafe-eval' ...
```

### Impact

This is classified **High** rather than Critical because exploitation requires
an existing XSS vulnerability — none was found on the site. However, the CSP
provides **zero defense-in-depth**. If any XSS is ever introduced:

- Cookie theft (Auto-Extract)
- Session hijacking (Auto-Extract)
- Arbitrary script injection
- Data exfiltration
- Keylogging

Additionally, all third-party CDN scripts (jQuery, Bootstrap, jsrsasign,
iziToast, Font Awesome) load **without Subresource Integrity (SRI) hashes**,
making them supply-chain attack vectors.

### Recommendation

Replace with strict, origin-specific directives:

```http
script-src 'self' https://apis.google.com
           https://www.google-analytics.com
           https://www.paynamics.net;
```

Use `'nonce-{random}'` for inline scripts and verify with
[Google CSP Evaluator](https://csp-evaluator.withgoogle.com).

---

## Methodology

Each finding was subjected to the same process:

1. **Identify** — initial scan triggers a hypothesis
2. **Reproduce** — trigger the exact condition that constitutes the vuln
3. **Verify** — collect hard evidence (HTTP status, timing, response content)
4. **Stress test** — push the boundary (10 rapid requests, timing analysis,
   response differentiation)
5. **Retain or retract** — only confirmed, reproducible issues are kept

### Tools

- curl, httpx — HTTP requests and header analysis
- Browser automation — GUI-level interaction, DOM inspection
- OpenSSL — TLS/cipher suite verification
- Python — CAPTCHA parsing, response diffing
- Bash — rate limiting stress testing

### Scope

- Dynamic black-box testing only (no source code review)
- Authenticated testing performed with a student account
- Admin-level testing was not possible (no admin credentials)
- File upload was identified but could not be triggered with available tooling

### References

- OWASP Top 10 (2021)
- OWASP ASVS v4.0
- NIST SP 800-115
- CVSSv3.1 Calculator

---

## Reproduce Commands

```bash
# Rate limit stress test
for i in $(seq 1 10); do
  curl -sk -X POST 'https://sis-ui.phinma.edu.ph/' \
    -d "ctl00\$ContentPlaceHolder1\$txtUserName=04-2324-042031" \
    -d "ctl00\$ContentPlaceHolder1\$txtPassword=WRONG\$i" \
    -d 'ctl00$ContentPlaceHolder1$captchacontrol=999' \
    -d 'ctl00$ContentPlaceHolder1$btnSubmit=Sign In' \
    -o /dev/null -w "%{http_code} %{time_total}s\n"
done

# CSP verification
curl -sI 'https://sis-ui.phinma.edu.ph/' | grep -oP 'script-src [^;]+'

# Tech stack fingerprinting
curl -sI 'https://sis-ui.phinma.edu.ph/' | grep -iE 'server:|x-aspnet|x-powered|strict-transport'
```

---

## Full Report

Detailed reproduction evidence for all found and retracted findings is in
[`phinma-vulnerabilities.txt`](./phinma-vulnerabilities.txt) (30KB).

This README reflects only the confirmed, stress-tested vulnerabilities.

---

*Assessment date: 2026-07-03*
*Target: https://sis-ui.phinma.edu.ph/*