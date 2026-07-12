# Accidental Modeller

> AI-assisted threat modeling for engineers.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()

## 🚧 Project Status

**Accidental Modeller** is currently an early-stage prototype under active development.

The core functionality is operational, and the project is evolving rapidly. Features, prompts, and report formats may change as the project matures.

Feedback, suggestions, and contributions are always welcome.

---

# Why Accidental Modeller?

Threat modeling is one of the most valuable security activities during software development.

Unfortunately, it is also one of the least adopted because it is often:

- Time consuming
- Documentation heavy
- Difficult for developers unfamiliar with security
- Dependent on security specialists

Accidental Modeller aims to reduce this friction by using AI to generate practical threat models from application descriptions.

The objective is **not to replace security architects**, but to help engineering teams start meaningful security conversations much earlier in the Software Development Lifecycle.

---

# Features

Current capabilities include:

- AI-assisted threat identification
- STRIDE-inspired threat generation
- Risk prioritization
- Security recommendations
- Markdown report generation
- PDF report generation
- FastAPI backend
- Modular prompt engine

Upcoming features:

- DFD (Data Flow Diagram) support
- OWASP ASVS mapping
- MITRE ATT&CK mapping
- Multi-model LLM support
- Interactive web interface
- Threat model versioning
- Architecture diagram parsing
- Export to Microsoft Threat Modeling Tool

---

# Technology Stack

- Python
- FastAPI
- OpenAI API
- ReportLab
- Docker

---

# Project Structure

```
accidental-modeller/
│
├── app/
│   ├── db.py
│   ├── main.py
│   ├── models.py
│   ├── prompts.py
│   ├── report_generator.py
│   └── threat_engine.py
│
├── examples/
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

---

# Installation

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

```bash
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

# Configuration

Create a `.env` file in the project root.

Example

```env
OPENAI_API_KEY=your_api_key_here
```

---

# Running the Application

Start the FastAPI server

```bash
uvicorn app.main:app --reload
```

Open

```
http://127.0.0.1:8000
```

Swagger documentation

```
http://127.0.0.1:8000/docs
```

---

# Example Workflow

1. Describe your application.
2. Submit the application details.
3. The AI engine analyses the architecture.
4. Threats are identified.
5. Security recommendations are generated.
6. A Markdown and PDF report is produced.

---

# Roadmap

## Version 0.1

- Basic threat generation
- Report generation
- FastAPI backend

## Version 0.2

- Better prompts
- STRIDE categorisation
- Improved report formatting

## Version 0.3

- OWASP ASVS mapping
- MITRE ATT&CK mapping
- Risk scoring improvements

## Version 0.4

- Architecture diagram support
- Mermaid diagrams
- Interactive UI

## Version 1.0

- Complete AI-assisted threat modeling platform
- Multi-model support
- Plugin architecture
- Team collaboration

---

# Screenshots

Coming soon. Screenshots will be added as the project evolves.

---

# Contributing

Contributions are welcome.

If you find a bug, have an idea for improvement, or would like to add a feature, please open an Issue or submit a Pull Request.

---

# Security

If you discover a security vulnerability, please report it responsibly instead of opening a public issue.

---

# License

This project is licensed under the MIT License.

---

# About the Author

Hi, I'm **Vanshidhar**, also known as **The Curious Engineer**.

I'm a cybersecurity professional focused on building practical tools and sharing knowledge around:

- Application Security
- Threat Modeling
- DevSecOps
- AI Security
- Secure Software Engineering

This repository is part of my journey to build engineer-friendly security tooling in the open.

If you find this project useful, consider giving it a ⭐.