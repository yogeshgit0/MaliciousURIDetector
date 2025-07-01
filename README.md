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

<img width="960" alt="image" src="https://github.com/user-attachments/assets/360a2ab7-8dc4-47de-bcad-f5c70e976112" />

## 🧪 Supported Attack Categories

- Injection (SQLi, LDAPi, JSONi, XMLi, XPath, SSTI, etc.)
- Client-side (XSS, DOM Clobbering, Clickjacking, Open Redirect)
- Server-side (RCE, SSRF, Deserialization, XXE, Path Traversal)
- API abuse (GraphQL, BOLA, BFLA, Rate Limit Bypass)
- Auth issues (IDOR, JWT, Credential Stuffing)
- Infra flaws (Request Smuggling, Response Splitting)
- Rare issues (RFD, Cache Poisoning, Dependency Confusion)

## 📦 Installation

- git clone https://github.com/yogeshgit0/MaliciousURIDetector.git
- cd MaliciousURIDetector
