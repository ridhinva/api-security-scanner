# API Security Scanner

<p align="center">
  <a href="https://github.com/ridhinva/api-security-scanner/stargazers"><img src="https://img.shields.io/github/stars/ridhinva/api-security-scanner?style=for-the-badge" alt="Stars"></a>
  <a href="https://github.com/ridhinva/api-security-scanner/network/members"><img src="https://img.shields.io/github/forks/ridhinva/api-security-scanner?style=for-the-badge" alt="Forks"></a>
  <a href="https://github.com/ridhinva/api-security-scanner/issues"><img src="https://img.shields.io/github/issues/ridhinva/api-security-scanner?style=for-the-badge" alt="Issues"></a>
  <a href="https://github.com/ridhinva/api-security-scanner/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ridhinva/api-security-scanner?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/ridhinva/api-security-scanner/commits/main"><img src="https://img.shields.io/github/last-commit/ridhinva/api-security-scanner?style=for-the-badge" alt="Last Commit"></a>
  <a href="https://github.com/ridhinva/api-security-scanner/actions"><img src="https://img.shields.io/github/actions/workflow/status/ridhinva/api-security-scanner/ci.yml?style=for-the-badge" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/OWASP-API%20Top%2010%202023-critical?style=for-the-badge" alt="OWASP API">
  <img src="https://img.shields.io/badge/GraphQL-Security-orange?style=for-the-badge" alt="GraphQL">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python">
</p>

---

## 🎯 Overview

**OWASP API Top 10 2023 + GraphQL security scanner** for REST, GraphQL, and gRPC APIs. Detects BOLA/IDOR, BFLA, SSRF, introspection leaks, depth DoS, batching attacks, and auth bypass.

| Check | OWASP API Category | Severity |
|-------|-------------------|----------|
| Broken Object Level Authorization (BOLA) | API1:2023 | 🔴 CRITICAL |
| Broken Authentication | API2:2023 | 🔴 CRITICAL |
| Broken Object Property Level Auth | API3:2023 | 🟠 HIGH |
| Unrestricted Resource Consumption | API4:2023 | 🟠 HIGH |
| Broken Function Level Authorization | API5:2023 | 🔴 CRITICAL |
| Unrestricted Access to Sensitive Flows | API6:2023 | 🟠 HIGH |
| Server Side Request Forgery (SSRF) | API7:2023 | 🟠 HIGH |
| Security Misconfiguration | API8:2023 | 🟡 MEDIUM |
| Improper Inventory Management | API9:2023 | 🟡 MEDIUM |
| Unsafe Consumption of APIs | API10:2023 | 🟡 MEDIUM |

### GraphQL-Specific Checks
| Check | Severity |
|-------|----------|
| Introspection Enabled | 🔴 CRITICAL |
| Depth/Breadth DoS | 🟠 HIGH |
| Batching Attack | 🟠 HIGH |
| Field-Level Auth Bypass | 🔴 CRITICAL |
| Alias Overloading | 🟡 MEDIUM |

---

## 🚀 Quick Start

```bash
git clone https://github.com/ridhinva/api-security-scanner.git
cd api-security-scanner
pip install requests
python3 api_security_scanner.py --target https://api.example.com --mode all
```

---

## ⚖️ Disclaimer

For authorized security testing only.