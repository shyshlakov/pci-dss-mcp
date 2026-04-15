# PCI DSS v4.0.1 Coverage Map

pci-dss-mcp checks **14 of 249** PCI DSS v4.0.1 requirements across 10 scanners. This covers Requirements 3, 4, 6, 8, 10, and 11.

## Covered Requirements

| Requirement | Title | Scanner | Detection |
|-------------|-------|---------|-----------|
| 3.2.1 | Account Data Storage Minimized | check_data_retention | Redis/DB storage without TTL, config without retention policy |
| 3.3.1 | SAD Not Retained After Authorization | scan_pan_data, check_data_retention | PAN in logs, CVV storage patterns, memory zeroing issues |
| 3.4.1 | PAN Displayed with Masking | scan_pan_data | PAN variables in HTTP responses, format strings |
| 3.5.1 | PAN Rendered Unreadable in Storage | scan_pan_data | String-typed PAN fields (can't be zeroed), missing memory zeroing |
| 4.2.1 | Strong Cryptography During Transmission | check_encryption, check_tls_config | Plain HTTP URLs, InsecureSkipVerify, weak TLS versions, weak ciphers |
| 6.2.4 | Secure Software Development | check_encryption, check_error_handling | Hardcoded keys, weak hashes, error details leaked to responses |
| 6.3.3 | Security Patches Applied | check_dependencies | Known CVEs in go.mod dependencies via OSV.dev |
| 6.4.3 | Payment Page Script Management | check_payment_page_scripts | Missing CSP headers, unsafe-inline/eval, missing SRI/nonce |
| 8.3.1 | Unique IDs for All Users | check_auth_strength | Hardcoded passwords in source code |
| 8.3.6 | Password Complexity Requirements | check_auth_strength | Password length checks below 12 characters |
| 8.4.2 | MFA for Administrative Access | check_auth_strength | Payment routes without MFA middleware |
| 8.6.2 | Passwords/Passphrases Not Hard-Coded | check_secrets_in_configs | Secrets in .env, .yaml, .json, .toml files |
| 10.2.1 | Audit Logs Capture Details | audit_log_coverage | Payment handlers without audit logging, unstructured logging (fmt/log instead of slog) |
| 11.6.1 | Change Detection for Payment Pages | check_payment_page_scripts | File integrity monitoring requirement flagged |

## Accuracy and Limitations

Each detectable requirement has defined coverage scope and known limitations. The compliance report shows these annotations on PASS findings so users understand exactly what was verified.

**Coverage scope** describes what patterns the scanner checks (e.g., InsecureSkipVerify, weak TLS versions). **Limitations** describe what the scanner cannot check (e.g., network-level encryption). **Not covered** describes aspects that require manual review or QSA assessment.

Sub-requirements that are not directly scanned but have a parent requirement that is scanned are shown with a "Covered by parent" annotation in the compliance report. For example, 3.3.1.1 inherits coverage from 3.3.1.

When a finding satisfies multiple PCI DSS requirements, the report shows "Also satisfies: X.Y.Z" cross-references. For example, a hardcoded password finding (8.3.1) also satisfies 8.6.2.

## NOT_CHECKED Categories

The following PCI DSS requirement categories are **outside the scope** of static analysis and are marked NOT_CHECKED in compliance reports:

| Category | Title | Reason |
|----------|-------|--------|
| 1 | Install and Maintain Network Security Controls | Network architecture and firewall rules -- requires infrastructure review |
| 2 | Apply Secure Configurations to All System Components | System hardening -- requires configuration audit |
| 5 | Protect All Systems from Malicious Software | Anti-malware controls -- requires operational verification |
| 7 | Restrict Access to System Components | Access control policies -- requires organizational review |
| 9 | Restrict Physical Access to Cardholder Data | Physical security -- requires on-site assessment |
| 12 | Support Information Security with Policies | Organizational policies -- requires documentation review |

Additionally, many sub-requirements within covered categories (3, 4, 6, 8, 10, 11) are NOT_CHECKED because they require:
- Manual documentation review (policies, procedures)
- Runtime behavior verification (monitoring, incident response)
- Infrastructure configuration audit (network segmentation, access controls)
- Organizational process verification (training, risk assessments)

## Coverage Disclaimer

**This tool supplements but does not replace a Qualified Security Assessor (QSA) review.**

NOT_CHECKED does not mean non-compliant. It means the requirement cannot be verified through static analysis of source code. A QSA must independently verify all 249 requirements for full PCI DSS compliance.

Static analysis catches code-level violations before they ship. It does not assess:
- Organizational policies and procedures
- Physical security controls
- Network architecture and segmentation
- Runtime behavior and monitoring
- Vendor management and third-party risk
- Incident response procedures
