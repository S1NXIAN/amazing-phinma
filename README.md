# phinma-sis-vulnerabilities

Security assessment of PHINMA University of Iloilo's Student Information System.

| Aspect | Detail |
|--------|--------|
| **Target** | `https://sis-ui.phinma.edu.ph/` |
| **Stack** | ASP.NET 4.0.30319 / IIS 10 / MasterSoft ERP |
| **Initial Assessment** | 2026-07-03 |
| **Re-verified** | 2026-07-11 |
| **Scope** | Authenticated + unauthenticated black-box testing |
| **Findings** | 0 Critical, 2 High (1 downgraded: CAPTCHA partially mitigated, rate limiting persists)

---

## Summary

Two verified vulnerabilities were identified. Both were stress-tested with
reproduction evidence. Fourteen other findings from the initial scan were
retracted after failing reproduction — the full list is in
[`phinma-vulnerabilities.txt`](./phinma-vulnerabilities.txt).

| ID | Severity | Finding | CVSS | Status |
|----|----------|---------|------|--------|
| 01 | 🔴 Critical → 🟠 High | CAPTCHA partially mitigated, rate limiting still absent | 8.6 | **Downgraded** — plaintext CAPTCHA removed, but OTP login still has no rate limiting |
| 02 | 🟠 High | CSP misconfiguration nullifies XSS defense | 8.2 | **Unchanged** — same CSP header |

---

## Finding 01 — No Rate Limiting on Login (High) [Downgraded from Critical]

**CVSS: 8.6** · `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**⚠ Re-verified 2026-07-11:** The plaintext math CAPTCHA has been removed — it's now handled via hidden fields (`hdnCaptchaValue`, `hdnCaptchaInput`), likely a client-side JS challenge. This is a meaningful improvement over the old plaintext-in-HTML approach. However, the underlying rate-limiting gap remains.

### The Gap

The login page now uses an OTP-based flow (`btnGetOtp`) instead of direct password submission. Rapid sequential POSTs to the login endpoint all return HTTP 302 with no throttling:

```bash
# Re-verification: 5 rapid OTP requests, all returned 302 (no throttle)
for i in $(seq 1 5); do
  curl -s -X POST 'https://sis-ui.phinma.edu.ph/' \
    -d 'txt_username=04-2324-042031' \
    -d "txt_password=WRONG$i" \
    -d 'hdnCaptchaValue=0' \
    -d 'hdnCaptchaInput=0' \
    -d 'btnGetOtp=Get+OTP' \
    -o /dev/null -w "%{http_code} %{time_total}s\n"
done
# Result: all 5 returned 302. No throttling.
```

The form fields were also redesigned (old naming convention replaced), and an OTP step was added — which changes the attack surface but does not eliminate the brute-force vector.

### Impact (Revised)

- The new hidden-field CAPTCHA may be bypassable via JS analysis (not assessed in depth)
- OTP adds a factor but does not prevent enumeration or rate-limited brute-force
- Student IDs remain predictable (`XX-XXXX-XXXXXX`)
- No account lockout observed after repeated failures

### Recommendation

1. Add server-side rate limiting — exponential backoff after 5 failures per IP/account
2. Replace hidden-field CAPTCHA with a proper challenge (reCAPTCHA v3 or image-based)
3. Consider account lockout after N failed OTP attempts

---

## Finding 02 — CSP Misconfiguration (High) [Unchanged]

**CVSS: 8.2** · `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`

**⚠ Re-verified 2026-07-11:** CSP header is identical — still `script-src * 'unsafe-inline' 'unsafe-eval'`.

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
# Rate limit stress test (new OTP endpoint)
for i in $(seq 1 5); do
  curl -s -X POST 'https://sis-ui.phinma.edu.ph/' \
    -d 'txt_username=04-2324-042031' \
    -d "txt_password=WRONG$i" \
    -d 'hdnCaptchaValue=0' \
    -d 'hdnCaptchaInput=0' \
    -d 'btnGetOtp=Get+OTP' \
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

*Assessment date: 2026-07-03 · Re-verified: 2026-07-11*
*Target: https://sis-ui.phinma.edu.ph/*