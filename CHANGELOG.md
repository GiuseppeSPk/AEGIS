# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- MARL (Multi-Agent Reinforcement Learning) module
- Web Dashboard UI
- PDF report generation
- Continuous monitoring mode

---

## [0.1.0] - 2024-12-16

### Added

#### Core Features
- **CLI Application** - Full-featured command-line interface using Typer
- **REST API** - FastAPI-based API with 22 endpoints
- **LLM Providers** - Support for Ollama, OpenAI, Anthropic, Google Gemini

#### Red Team Capabilities
- **Prompt Injection Agent** - 32 attack payloads
- **Single-Turn Jailbreak Agent** - 12 techniques (DAN, AIM, Developer Mode)
- **Multi-Turn Jailbreak Agent** - SOTA 2025 techniques:
  - Crescendo (Microsoft Research 2024)
  - Tree of Attacks with Pruning (TAP)
  - PAIR (Prompt Automatic Iterative Refinement)
- **System Prompt Leakage Agent** - 12 extraction techniques

#### Blue Team Analysis
- **LLM-as-Judge** - Automated attack evaluation
- **Bootstrap Confidence Intervals** - Statistical ASR analysis
- **Harm Scoring** - Granular severity assessment (1-10)

#### Compliance
- **OWASP LLM Top 10 2025** - Complete vulnerability mapping
- **EU AI Act** - Articles 9, 14, 15 compliance checking

#### Reporting
- **Markdown Reports** - GitHub-compatible format
- **HTML Reports** - Styled with dark theme
- **JSON Reports** - Machine-readable format
- **Jinja2 Templates** - Customizable report generation

#### Documentation
- Installation guide
- Usage guide (CLI, API, SDK)
- API reference
- Attack catalog
- Architecture documentation

### Security
- JWT authentication for API
- API key support
- Rate limiting
- CORS configuration

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.0 | 2024-12-16 | Initial release |

---

## Upgrade Guide

### From 0.0.x to 0.1.0

This is the initial public release. No upgrade path needed.

---

## Contributors

Thanks to all contributors who helped make AEGIS possible!

<!-- Add contributor list here -->
