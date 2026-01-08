# Agentic Reliability Framework — API

The **ARF API** is the control plane and integration layer for the **Agentic Reliability Framework (ARF)**, enabling teams to connect cloud-native systems, ingest telemetry, and expose reliability intelligence to operators, agents, and enterprise workflows.

This repository provides the production-ready API surface for observability, incident detection, and reliability coordination across AI-driven systems.

---

## What This Repository Is

- A **FastAPI-based control plane** for ARF
- A secure interface for:
  - Telemetry ingestion
  - Incident and anomaly signals
  - Reliability state and lifecycle events
- An integration point for cloud platforms, agents, and enterprise systems

This repo focuses on **interfaces, contracts, and execution flow** — not proprietary decision logic.

---

## What This Repository Is Not

- It does **not** implement autonomous remediation logic
- It does **not** contain enterprise policy engines or compliance workflows
- Advanced self-healing and governance features live in the **Enterprise edition**

---

## How It Fits Into ARF

ARF is structured as a layered system:

- **Agentic Reliability Framework (OSS)**  
  Advisory observability and incident intelligence  
  → https://github.com/petterjuan/agentic-reliability-framework

- **ARF API (this repository)**  
  Control plane and integration surface

- **ARF Enterprise (Commercial)**  
  Autonomous remediation, compliance, and production guarantees

This separation ensures openness where it accelerates adoption, and protection where reliability and risk matter.

---

## Use Cases

- Exposing reliability signals to AI agents
- Centralizing incident and anomaly intelligence
- Integrating observability with enterprise workflows
- Providing a stable API for reliability-aware automation

---

## Status

This repository is under active development and is intended for:
- Infrastructure teams
- SREs and platform engineers
- AI teams deploying agent-driven systems in production

---

## License

This repository is released under the Apache 2.0 license.
