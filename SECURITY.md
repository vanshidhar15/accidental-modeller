# Security Policy

## Supported Versions

Accidental Modeller is currently an early-stage project.

Security fixes will generally be applied to the latest released version.

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | No        |

## Reporting a Vulnerability

Please do not report suspected security vulnerabilities through a public GitHub issue.

Use GitHub's private vulnerability reporting feature, if available for this repository.

When submitting a report, please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- The affected component or endpoint
- Potential security impact
- Any proof-of-concept details
- Suggested remediation, if available

Please avoid including real secrets, personal data, production credentials, or sensitive third-party information in the report.

## Response Expectations

This project is maintained on a best-effort basis.

I will aim to:

- Acknowledge valid reports within 7 days
- Investigate and assess the impact
- Provide updates when meaningful progress is made
- Publish a fix or mitigation when reasonably possible

Response times may vary depending on the severity and complexity of the issue.

## Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

Where appropriate, security researchers may be credited in the release notes unless they prefer to remain anonymous.

## Scope

Examples of relevant security issues include:

- Authentication or authorization weaknesses
- Command injection or code execution
- Path traversal
- Unsafe file handling
- Sensitive data exposure
- Dependency-related vulnerabilities
- API misuse that creates a meaningful security impact

General feature requests, threat-model accuracy suggestions, and non-security bugs should be reported through regular GitHub issues.

## Safe Harbor

Good-faith security research conducted in accordance with this policy is welcome.

Please avoid:

- Accessing data that does not belong to you
- Disrupting services
- Performing denial-of-service testing
- Using automated testing at excessive volume
- Publicly disclosing an issue before remediation