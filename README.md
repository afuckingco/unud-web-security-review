# Universitas Udayana (UNUD) — Web Security Review

> ⚠️ **Status: PRIVATE repository (default for safety).** See [Responsible Disclosure](#responsible-disclosure) below.
> Static security analysis of `https://www.unud.ac.id/` (Universitas Udayana public website).  
> **Method**: Static analysis only (HTTP headers, HTML inspection, public endpoint probing). NO active testing, NO login attempts, NO payload submission.  
> **Date**: 18 June 2026

## Quick Summary

UNUD runs **WordPress 6.9** (latest) on nginx/Ubuntu. Has decent security foundation (X-Frame-Options, X-Content-Type-Options, Referrer-Policy), but has **defense-in-depth gaps** and **one notable information disclosure** finding:

| Severity | Count | Key Items |
|---|---|---|
| 🟠 Notable | 1 | **Username enumeration via wp-json** (5 accounts exposed including `admin_unud`) |
| 🟡 Medium | 4 | Missing HSTS, CSP, Permissions-Policy; server version exposed |
| 🟢 Low | 1 | WordPress version disclosure (readme.html) |

**No exploit path verified.** All findings from static analysis.

## Key Finding: WordPress User Enumeration

```bash
curl -s https://www.unud.ac.id/wp-json/wp/v2/users
```

Returns 5 user accounts. This is well-known WordPress behavior (REST API exposed by default since WP 4.7). For a public university site, this enables targeted attacks against admin account.

**Fix** (one line in functions.php):
```php
add_filter('rest_endpoints', function($endpoints) {
    if (!is_user_logged_in()) {
        unset($endpoints['/wp/v2/users']);
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }
    return $endpoints;
});
```

## What This Review Covers

- Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- WordPress security posture
- Information disclosure (readme.html, license.txt, server version)
- REST API exposure
- Quick XSS pattern check (none significant found)

## What This Review Does NOT Cover

- Active testing (XSS, SQLi payloads, brute force)
- Authenticated areas (no login attempted)
- Plugin-specific vulnerabilities (full WPScan audit needed)
- Server-side configuration (we have no access)
- Network infrastructure

## Responsible Disclosure

**This report should be shared with UNUD IT BEFORE making it public.**

If you're a researcher who found this:
1. Contact UNUD IT (look for `security@unud.ac.id`, `admin@unud.ac.id`, or LinkedIn IT staff)
2. Wait for acknowledgment (industry standard: 90 days)
3. Coordinate public release with UNUD
4. **Do NOT publish username enumeration details before fix** — this enables attacks

If you're UNUD IT:
- This report is constructive, not exploit disclosure
- All recommendations are defense-in-depth
- I'd appreciate acknowledgment and (if possible) fix timeline

## Method

- Static analysis (curl + browser DevTools)
- 0 login attempts
- 0 payload submissions
- 0 brute force attempts
- 0 authentication bypass attempts
- All findings reproducible without special access

## License

MIT — feel free to use as template.

## Author

**Afiq Andico** — Mahasiswa Sistem Informasi, STIKOM Bali

- Email: afiqandico13@gmail.com
- GitHub: [@afiqandico13](https://github.com/afiqandico13)
- Contact: Best via email (allow a few days for response)

## Changelog

- **2026-06-18**: Initial review (static analysis)

---

## 🔗 Related Work

Sibling security research repos dari author yang sama:

- **[sion-stikom-security-review](https://github.com/afiqandico13/sion-stikom-security-review)** — Comprehensive pentest 2026 (5 findings + CVSS scoring) untuk `*.stikom-bali.ac.id`
- **[warmadewa-web-security-review](https://github.com/afiqandico13/warmadewa-web-security-review)** — Static review Universitas Warmadewa website

**Methodology**: Both reviews mengikuti OWASP Testing Guide v4 dengan responsible disclosure principles.

---

## 📊 Author Portfolio

**Afiq Andico Pangimpian** — IT Support @ Cube Cafe Jimbaran · S1 Sistem Informasi ITB STIKOM Bali

- Email: afiqandico13@gmail.com
- GitHub: [@afiqandico13](https://github.com/afiqandico13)
- Security portfolio: [github.com/afiqandico13?tab=repositories&q=security-review](https://github.com/afiqandico13?tab=repositories&q=security-review)
