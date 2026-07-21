# Accidental Modeller

> Lightweight rule-based STRIDE threat modeling for modern applications.

Automatically generate:

- STRIDE threats
- Security requirements
- Security review questions
- Markdown reports

...from a simple description of your system architecture.

![Python](https://img.shields.io/badge/Python-3.14-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Version](https://img.shields.io/badge/version-v0.2.0-orange)

---

## Why Accidental Modeller?

Threat modeling often starts late in the software lifecycle because it is perceived as slow, manual, and dependent on security specialists.

Accidental Modeller aims to make threat modeling:

- Simple
- Repeatable
- Fast
- Developer-friendly

Provide a description of your architecture and receive:

- STRIDE threat analysis
- Security requirements
- Architecture review questions
- Risk summary
- Markdown report

---

## Features

### Threat Generation

- STRIDE-based threat identification
- Authentication analysis
- Trust boundary analysis
- Sensitive data analysis
- Database security analysis
- Internet-facing service analysis
- External integration analysis
- Data flow analysis
- Audit & logging analysis

### Security Guidance

- Actionable recommendations
- Security requirements
- Security review questions
- Risk prioritization

### Reporting

- Executive Summary
- Risk Summary
- STRIDE Coverage
- Threat Register
- Security Requirements
- Security Review Questions
- Markdown report generation

---

## Tech Stack

- Python 3.14+
- FastAPI
- Pydantic
- Uvicorn
- Pytest

---

## Installation

Clone the repository

```bash
git clone https://github.com/vanshidhar15/accidental-modeller.git

cd accidental-modeller
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate it

Windows

```powershell
.venv\Scripts\activate
```

Linux / macOS

```bash
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the API

```bash
uvicorn app.main:app --reload
```

Swagger UI

```
http://127.0.0.1:8000/docs
```

---

## Example Input

```json
{
  "system_name": "Payment Processing Platform",
  "description": "Internet-facing payment platform",
  "components": [
    "Web Application",
    "API Gateway",
    "Payment Service",
    "PostgreSQL Database"
  ],
  "authentication": "OAuth 2.0 with JWT",
  "sensitive_data": [
    "Customer PII",
    "Payment Tokens"
  ]
}
```

---

## Output

Accidental Modeller generates:

- Executive Summary
- STRIDE Coverage
- Risk Summary
- Threat Register
- Security Requirements
- Security Review Questions
- Markdown Report

---

## Project Structure

```
app/
│
├── main.py
├── models.py
├── threat_engine.py
└── report_generator.py

tests/

examples/

requirements.txt
README.md
CHANGELOG.md
LICENSE
```

---

## Running Tests

```bash
python -m pytest
```

Compile check

```bash
python -m compileall app tests
```

---

## Roadmap

### v0.2

- Improved STRIDE engine
- Better security review questions
- Improved Markdown reporting
- Python 3.14 support

### v0.3

- Modular architecture
- HTML reports
- PDF reports
- Plugin-based rule engine
- Optional MITRE ATT&CK mapping
- Optional OWASP ASVS mapping

---

## Contributing

Contributions, issues, feature requests, and suggestions are welcome.

Please open an Issue before submitting large changes.

---

## License

MIT License

---

## Author

**Vanshidhar Singh**

Cybersecurity | Application Security | Threat Modeling | DevSecOps

If this project helped you, consider giving it a ⭐ on GitHub.