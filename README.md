# 🛡️ MaliciousURIDetector
This Python tool is designed for Red Teamers, SOC analysts, DevSecOps engineers, incident responders, and security researchers who need to rapidly analyze WAF logs or web traffic for signs of malicious activity. Whether you're triaging alerts, validating attack payloads post-engagement, tuning WAF rules, or integrating into CI/CD pipelines, this utility helps detect over 70+ web attack patterns including SQLi, XSS, RCE, SSRF, JWT tampering, and GraphQL introspection abuse through advanced regex matching and URI decoding, making it a powerful asset for both offense and defense teams.

## 🚀 Tool Highlights
- ✅ **Supports Multiple Log Types:** Works with .xlsx, .csv, .tsv, or .txt files exported from:
  - Azure WAF
  - AWS CloudFront WAF
  - F5 / Citrix WAF
  - ModSecurity / OWASP CRS
  - Custom web logs
- ✅ **Scans request URIs:** Focused on the requestUri_s column or similar
- ✅ **Auto-decodes URI encoding:** Handles obfuscated %2f..%2e and %3d-style payloads
- ✅ **Regex-based detection:** Covers 70+ web attack patterns across 7 domains
- ✅ **Beautiful CLI & Summary:** Uses rich for colorful feedback and progress bars
- ✅ **Excel Report Generation:** Timestamped, color-coded output for incident tracking
- ✅ **Plug-and-Play:** Ready for integration in CI/CD or SOC playbooks

## 📸 Example

<img width="960" alt="image" src="https://github.com/user-attachments/assets/77e6cb02-026c-47ef-94da-f5777bbb94c4" />

## 🧪 Supported Attack Categories

- Injection (SQLi, LDAPi, JSONi, XMLi, XPath, SSTI, etc.)
- Client-side (XSS, DOM Clobbering, Clickjacking, Open Redirect)
- Server-side (RCE, SSRF, Deserialization, XXE, Path Traversal)
- API abuse (GraphQL, BOLA, BFLA, Rate Limit Bypass)
- Auth issues (IDOR, JWT, Credential Stuffing)
- Infra flaws (Request Smuggling, Response Splitting)
- Rare issues (RFD, Cache Poisoning, Dependency Confusion)

## 📋 Pre-requisites
Before running the tool, ensure the following are in place:
- Python 3.8+ installed and accessible from your terminal
- Your WAF or HTTP access logs are in one of the following formats:
  - .xlsx (Excel with a requestUri_s column)
  - .csv, .tsv, or .txt (with URL column named requestUri_s or similar)
- Logs should contain at least one column representing the full request URI, typically extracted from:
  - AWS WAF, Azure WAF, ModSecurity, F5, Citrix, or reverse proxy logs
  - API Gateway logs or GraphQL endpoint traffic
- For Excel export functionality, install openpyxl
- Recommended terminal supports Rich CLI output (color, tables, progress bars)

## 📦 Installation

- git clone https://github.com/yogeshgit0/MaliciousURIDetector.git
- cd MaliciousURIDetector
