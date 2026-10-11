#!/usr/bin/env python3
"""
Link Security Analyzer - Advanced Edition
Ethical tool for analyzing websites for common security issues.
Only use on websites you own or have permission to test.
"""

import sys
import ssl
import socket
import re
from datetime import datetime
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against protocol downgrade attacks",
    "Content-Security-Policy": "Helps prevent XSS and data injection",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features",
    "X-XSS-Protection": "Legacy XSS filter (still useful)",
}

def print_banner():
    print("=" * 70)
    print("  Link Security Analyzer - Advanced Edition")
    print("  Ethical Security Tool | Authorized testing only")
    print("=" * 70)
    print()

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def check_ssl(hostname):
    print("[+] SSL/TLS Certificate Check")
    result = {"valid": False, "issues": []}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                print(f"    ✓ Certificate is valid")
                print(f"    • Protocol : {version}")
                print(f"    • Cipher   : {cipher[0] if cipher else 'N/A'}")
                print(f"    • Issuer   : {dict(x[0] for x in cert.get('issuer', []))}")
                print(f"    • Valid until: {cert.get('notAfter', 'N/A')}")

                # Check expiry
                not_after = cert.get('notAfter')
                if not_after:
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 30:
                        print(f"    ⚠ Certificate expires in {days_left} days")
                        result["issues"].append("Certificate expiring soon")

                result["valid"] = True
                return result
    except Exception as e:
        print(f"    ✗ SSL check failed: {e}")
        result["issues"].append(str(e))
        return result

def check_security_headers(response):
    print("\n[+] Security Headers Analysis")
    headers = {k.lower(): v for k, v in response.headers.items()}
    score = 0
    max_score = len(SECURITY_HEADERS)
    missing = []

    for header, description in SECURITY_HEADERS.items():
        key = header.lower()
        if key in headers:
            value = headers[key][:70]
            print(f"    ✓ {header}")
            print(f"      Value: {value}{'...' if len(headers[key]) > 70 else ''}")
            score += 1
        else:
            print(f"    ✗ Missing: {header}")
            print(f"      Why it matters: {description}")
            missing.append(header)

    print(f"\n    Header Score: {score}/{max_score}")
    return score, max_score, missing

def check_cookies(response):
    print("\n[+] Cookie Security")
    cookies = response.headers.get("Set-Cookie", "")
    if not cookies:
        print("    • No Set-Cookie header found")
        return

    issues = []
    if "httponly" not in cookies.lower():
        issues.append("Missing HttpOnly flag")
    if "secure" not in cookies.lower():
        issues.append("Missing Secure flag")
    if "samesite" not in cookies.lower():
        issues.append("Missing SameSite attribute")

    if issues:
        for i in issues:
            print(f"    ✗ {i}")
    else:
        print("    ✓ Cookies have good security flags")

def check_https_enforcement(url):
    print("\n[+] HTTPS Enforcement")
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}{parsed.path}"

    try:
        resp = requests.get(http_url, allow_redirects=True, timeout=8, verify=False)
        if resp.url.startswith("https://"):
            print("    ✓ Site forces HTTPS (good)")
            return True
        else:
            print("    ✗ Site does not force HTTPS")
            return False
    except Exception:
        print("    • Could not test HTTP → HTTPS redirect")
        return None

def check_server_info(response):
    print("\n[+] Server Information Disclosure")
    server = response.headers.get("Server", "")
    powered = response.headers.get("X-Powered-By", "")

    if server:
        print(f"    • Server header: {server}")
        if any(x in server.lower() for x in ["apache/", "nginx/", "iis/"]):
            print("    ⚠ Version information exposed (consider hiding it)")
    else:
        print("    ✓ Server header not disclosed")

    if powered:
        print(f"    ⚠ X-Powered-By: {powered} (reveals technology)")

def check_mixed_content_hint(response):
    print("\n[+] Additional Checks")
    content_type = response.headers.get("Content-Type", "")
    print(f"    • Content-Type: {content_type or 'Not set'}")

    # Simple check for common sensitive paths (HEAD only, very light)
    print("    • Basic path check skipped (safe mode)")

def calculate_overall_score(ssl_ok, header_score, header_max, https_forced):
    score = 0
    if ssl_ok:
        score += 30
    score += int((header_score / header_max) * 50) if header_max else 0
    if https_forced:
        score += 20
    return min(score, 100)

def analyze(url):
    print_banner()
    url = normalize_url(url)
    print(f"Target : {url}")
    print(f"Time   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        print("Invalid URL")
        return

    ssl_result = check_ssl(hostname)

    try:
        response = requests.get(
            url,
            timeout=12,
            verify=True,
            allow_redirects=True,
            headers={"User-Agent": "LinkSecurityAnalyzer/2.0 (Educational)"}
        )

        print(f"\n[+] HTTP Response")
        print(f"    • Status : {response.status_code}")
        print(f"    • Final URL: {response.url}")

        if response.history:
            print(f"    • Redirects: {len(response.history)} hop(s)")
            for r in response.history:
                print(f"      {r.status_code} → {r.url}")

        header_score, header_max, missing = check_security_headers(response)
        check_cookies(response)
        https_forced = check_https_enforcement(url)
        check_server_info(response)
        check_mixed_content_hint(response)

        overall = calculate_overall_score(
            ssl_result["valid"], header_score, header_max, https_forced
        )

        print("\n" + "=" * 70)
        print(f"  OVERALL SECURITY SCORE: {overall}/100")

        if overall >= 80:
            print("  Rating: GOOD")
        elif overall >= 50:
            print("  Rating: AVERAGE - Improvements recommended")
        else:
            print("  Rating: WEAK - Multiple issues found")

        print("=" * 70)
        print("Scan completed. Only test systems you own or have permission to test.")
        print("=" * 70)

    except RequestException as e:
        print(f"\n[!] Request failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <url>")
        print("Example: python analyzer.py https://example.com")
        sys.exit(1)

    analyze(sys.argv[1])
