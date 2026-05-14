# frameworks/iso42001.py  (identical across all 4 projects)
"""
ISO/IEC 42001:2023 — AI Management System Controls
Mapped to cloud and Kubernetes security checks.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class ISO42001Control:
    control_id: str
    clause: str
    title: str
    description: str
    severity: str
    cloud_relevance: str   # AWS | AZURE | GCP | K8S | ALL


ISO42001_CONTROLS: Dict[str, ISO42001Control] = {

    # ── Clause 6 — Planning ───────────────────────────────────────────────────
    "42001-6.1.2": ISO42001Control(
        "42001-6.1.2", "6.1.2",
        "AI Risk Assessment",
        "Organisation must identify and assess risks associated with AI systems "
        "including data poisoning, model inversion, and adversarial attacks.",
        "HIGH", "ALL"
    ),
    "42001-6.2": ISO42001Control(
        "42001-6.2", "6.2",
        "AI Objectives and Planning",
        "AI system objectives must be documented with measurable outcomes "
        "and security acceptance criteria.",
        "MEDIUM", "ALL"
    ),

    # ── Clause 8 — Operation ──────────────────────────────────────────────────
    "42001-8.4": ISO42001Control(
        "42001-8.4", "8.4",
        "AI Data Management Controls",
        "Training, validation and test data must be protected with appropriate "
        "access controls, encryption, and integrity checks.",
        "CRITICAL", "ALL"
    ),
    "42001-8.5": ISO42001Control(
        "42001-8.5", "8.5",
        "AI System Design Security",
        "AI systems must be designed with security controls including input "
        "validation, output filtering, and adversarial robustness.",
        "HIGH", "ALL"
    ),
    "42001-8.6": ISO42001Control(
        "42001-8.6", "8.6",
        "AI System Verification and Validation",
        "AI systems must undergo security testing including adversarial testing, "
        "bias assessment, and model integrity verification before deployment.",
        "HIGH", "ALL"
    ),

    # ── Clause 9 — Performance Evaluation ────────────────────────────────────
    "42001-9.1": ISO42001Control(
        "42001-9.1", "9.1",
        "AI System Monitoring and Measurement",
        "AI systems must be continuously monitored for model drift, "
        "unexpected outputs, and security anomalies.",
        "HIGH", "ALL"
    ),

    # ── Annex A — Extended Controls ───────────────────────────────────────────
    "42001-A.6.1": ISO42001Control(
        "42001-A.6.1", "A.6.1",
        "AI Transparency and Explainability",
        "AI systems must have documented model cards, lineage tracking, "
        "and resource tags identifying AI workloads.",
        "MEDIUM", "ALL"
    ),
    "42001-A.6.2": ISO42001Control(
        "42001-A.6.2", "A.6.2",
        "AI Accountability — Ownership Tagging",
        "All AI/ML resources must be tagged with owner, model version, "
        "data classification, and purpose.",
        "MEDIUM", "ALL"
    ),
    "42001-A.6.3": ISO42001Control(
        "42001-A.6.3", "A.6.3",
        "AI Data Privacy and Protection",
        "Training data stores must enforce encryption at rest, access logging, "
        "and data minimisation controls.",
        "CRITICAL", "ALL"
    ),
    "42001-A.7.1": ISO42001Control(
        "42001-A.7.1", "A.7.1",
        "AI Incident Response",
        "Organisation must have documented procedures for AI-specific incidents "
        "including model poisoning, prompt injection, and data leakage.",
        "HIGH", "ALL"
    ),
    "42001-A.8.1": ISO42001Control(
        "42001-A.8.1", "A.8.1",
        "Prompt Injection Prevention",
        "AI inference endpoints must validate and sanitise inputs to prevent "
        "prompt injection attacks that manipulate model behaviour.",
        "CRITICAL", "K8S"
    ),
    "42001-A.8.2": ISO42001Control(
        "42001-A.8.2", "A.8.2",
        "Model Artifact Access Control",
        "Model files, weights, and training datasets must be stored with "
        "strict IAM/RBAC controls and access logging enabled.",
        "CRITICAL", "ALL"
    ),
}


def get_control(control_id: str) -> ISO42001Control:
    return ISO42001_CONTROLS.get(control_id, ISO42001Control(
        control_id, "custom", control_id,
        "Custom AI governance check", "MEDIUM", "ALL"
    ))