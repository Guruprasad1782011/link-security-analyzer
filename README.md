# 🔍 Link Security Analyzer - Advanced Edition

A powerful **ethical** Python tool that analyzes websites for common security misconfigurations.

> ⚠️ **Important**: Only use on websites you own or have explicit permission to test.

---

## 🎯 What it checks

| Check | Details |
|-------|--------|
| **SSL/TLS** | Certificate validity, expiry, protocol, cipher |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| **Cookies** | HttpOnly, Secure, SameSite flags |
| **HTTPS Enforcement** | Whether HTTP redirects to HTTPS |
| **Server Info** | Exposed Server / X-Powered-By headers |
| **Redirects** | Redirect chain analysis |
| **Overall Score** | 0-100 security rating |

---

## 🚀 Features

- Clean professional output
- Overall security score with rating
- Detailed explanations for missing headers
- Cookie security checks
- Certificate expiry warning
- Lightweight and fast

---

## 📦 Installation

```bash
git clone https://github.com/Guruprasad1782011/link-security-analyzer.git
cd link-security-analyzer
pip install -r requirements.txt
```

---

## 📝 Usage

```bash
python analyzer.py https://example.com
```

---

## 📁 Project Structure

```
link-security-analyzer/
├── analyzer.py          # Advanced analyzer
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🔗 Related Projects

- [protection-from-](https://github.com/Guruprasad1782011/protection-from-) — Phishing email detector
- [security-learning-path](https://github.com/Guruprasad1782011/security-learning-path) — Learning roadmap

---

**Made for learning ethical security practices.**
