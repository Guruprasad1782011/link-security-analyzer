#!/usr/bin/env python3
"""
Link Security Analyzer
Ethical tool for analyzing websites for common security issues.
Only use on websites you own or have permission to test.
"""

import sys
import ssl
import socket
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException

# Disable insecure request warnings for educational clarity
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

def print_banner():
    print("=" * 60)
    print("  Link Security Analyzer - Ethical Security Tool")
    print("  For authorized testing only")
    print("=" * 60)
    print()

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def check_ssl(hostname):
    print("[+] Checking SSL/TLS certificate...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"    ✓ Certificate is valid")
                print(f"    • Issuer: {cert.get('issuer', 'N/A')}")
                print(f"    • Valid until: {cert.get('notAfter', 'N/A')}")
                return True
    except Exception as e:
        print(f"    ✗ SSL check failed: {e}")
        return False

def check_security_headers(response):
    print("\n[+] Checking Security Headers...")
    headers = response.headers
    missing = []

    for header in SECURITY_HEADERS:
        if header in headers:
            print(f"    ✓ {header}: {headers[header][:80]}...")
        else:
            print(f"    ✗ Missing: {header}")
            missing.append(header)

    if missing:
        print(f"\n    Recommendation: Add the missing headers to improve security.")
    else:
        print("\n    Great! Most important security headers are present.")

def check_redirects(url):
    print("\n[+] Checking redirects...")
    try:
        response = requests.get(url, allow_redirects=True, timeout=10, verify=True)
        if len(response.history) > 0:
            print(f"    • Redirect chain ({len(response.history)} hops):")
            for r in response.history:
                print(f"      {r.status_code} → {r.url}")
            print(f"      Final: {response.url}")
        else:
            print("    ✓ No redirects detected")
        return response
    except RequestException as e:
        print(f"    ✗ Could not follow redirects: {e}")
        return None

def check_https_enforcement(url):
    print("\n[+] Checking HTTPS enforcement...")
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}{parsed.path}"

    try:
        response = requests.get(http_url, allow_redirects=True, timeout=8, verify=False)
        if response.url.startswith("https://"):
            print("    ✓ Site redirects HTTP to HTTPS (good)")
        else:
            print("    ✗ Site does not force HTTPS")
    except Exception:
        print("    • Could not test HTTP → HTTPS redirect")

def analyze(url):
    print_banner()
    url = normalize_url(url)
    print(f"Target: {url}\n")

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        print("Invalid URL")
        return

    # SSL check
    check_ssl(hostname)

    # Main request
    try:
        response = requests.get(url, timeout=10, verify=True, allow_redirects=True)
        print(f"\n[+] HTTP Status: {response.status_code}")
        print(f"[+] Server: {response.headers.get('Server', 'Not disclosed')}")

        check_security_headers(response)
        check_https_enforcement(url)

    except RequestException as e:
        print(f"\n[!] Request failed: {e}")
        return

    print("\n" + "=" * 60)
    print("Scan completed. Review the findings above.")
    print("Remember: Only test systems you own or have permission to test.")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <url>")
        print("Example: python analyzer.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    analyze(target)
