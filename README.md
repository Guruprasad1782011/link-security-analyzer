# 🔍 Link Security Analyzer

An **ethical** Python tool that analyzes websites for common security misconfigurations and issues.

> ⚠️ **Important**: This tool is intended **only** for websites you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

---

## 🎯 What it checks

| Check | Description |
|-------|-------------|
| **Security Headers** | Missing or weak HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) |
| **SSL/TLS** | Certificate validity, protocol version |
| **Redirects** | Open redirects and suspicious redirect chains |
| **HTTPS Enforcement** | Whether the site forces HTTPS |
| **Server Information** | Exposed server banners |
| **Basic Fingerprinting** | Technology detection (safe level) |

---

## 🚀 Features

- Clean and readable reports
- Easy to extend with new checks
- Designed for learning and authorized security assessments
- Clear educational purpose

---

## 💻 Tech Stack

- **Python 3**
- `requests`
- `urllib3`
- `ssl`
- `socket`

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

Example output will show:
- Present / Missing security headers
- SSL certificate status
- Redirect behavior
- Recommendations

---

## 📁 Project Structure

```
link-security-analyzer/
├── analyzer.py          # Main analysis script
├── requirements.txt     # Dependencies
├── README.md            # Documentation
└── .gitignore
```

---

## 📚 Learning Goals

This project helps you understand:
- HTTP security headers and why they matter
- How SSL/TLS certificates work
- Safe reconnaissance techniques
- Writing clean security tools in Python

---

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**.

- Only scan websites you own or have written permission to test.
- The author is not responsible for any misuse of this tool.
- Always follow responsible disclosure practices.

---

## 🔗 Related Projects

- [protection-from-](https://github.com/Guruprasad1782011/protection-from-) → Phishing email detector
- [security-learning-path](https://github.com/Guruprasad1782011/security-learning-path) → My learning roadmap

---

**Made for learning ethical security practices** ✨
