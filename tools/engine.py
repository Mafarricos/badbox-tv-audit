import os
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

# Caminho para data/rules.json
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE = os.path.join(PROJECT_ROOT, "data", "rules.json")


class VerdictState(str, Enum):
    INFECTED = "INFECTED"
    SUSPICIOUS = "SUSPICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"
    NEUTRALIZED = "NEUTRALIZED"
    CLEAN = "CLEAN"

    @property
    def exit_code(self) -> int:
        mapping = {
            VerdictState.INFECTED: 1,
            VerdictState.SUSPICIOUS: 2,
            VerdictState.INCONCLUSIVE: 4,
            VerdictState.NEUTRALIZED: 0,
            VerdictState.CLEAN: 0,
        }
        return mapping[self]

    def display_name(self, lang: str = "pt") -> str:
        names = {
            "pt": {
                VerdictState.INFECTED: "INFETADO - CRÍTICO",
                VerdictState.SUSPICIOUS: "SUSPEITO",
                VerdictState.INCONCLUSIVE: "INCONCLUSIVO",
                VerdictState.NEUTRALIZED: "NEUTRALIZADO",
                VerdictState.CLEAN: "LIMPO / SEGURO",
            },
            "en": {
                VerdictState.INFECTED: "INFECTED - CRITICAL",
                VerdictState.SUSPICIOUS: "SUSPICIOUS",
                VerdictState.INCONCLUSIVE: "INCONCLUSIVE",
                VerdictState.NEUTRALIZED: "NEUTRALIZED",
                VerdictState.CLEAN: "CLEAN / SECURE",
            }
        }
        return names.get(lang, names["pt"]).get(self, self.value)


class LayerStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    UNSUPPORTED = "UNSUPPORTED"
    TIMEOUT = "TIMEOUT"


@dataclass
class Finding:
    code: str
    severity: str
    layer: str
    subject: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    ioc_ref: Optional[str] = None
    weight: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "layer": self.layer,
            "subject": self.subject,
            "evidence": self.evidence,
            "ioc_ref": self.ioc_ref,
            "weight": self.weight
        }


@dataclass
class LayerResult:
    id: str
    status: LayerStatus
    detail: str = ""
    coverage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "detail": self.detail,
            "coverage": self.coverage
        }


class RuleEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path or RULES_FILE
        self.schema_version = 2
        self.severities: Dict[str, int] = {
            "CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0
        }
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.modes: Dict[str, Dict[str, List[str]]] = {}
        self._load_rules()

    def _load_rules(self):
        if not os.path.exists(self.rules_path):
            return
        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.schema_version = data.get("schema_version", 2)
            self.severities = data.get("severities", self.severities)
            self.rules = data.get("rules", {})
            self.modes = data.get("modes", {})

    def create_finding(
        self,
        code: str,
        layer: str,
        subject: str,
        evidence: Optional[Dict[str, Any]] = None,
        ioc_ref: Optional[str] = None,
        override_severity: Optional[str] = None
    ) -> Finding:
        rule_def = self.rules.get(code, {})
        severity = override_severity or rule_def.get("severity", "INFO")
        weight = self.severities.get(severity, rule_def.get("weight", 0))
        return Finding(
            code=code,
            severity=severity,
            layer=layer,
            subject=subject,
            evidence=evidence or {},
            ioc_ref=ioc_ref,
            weight=weight
        )

    def evaluate(
        self,
        findings: List[Finding],
        layers: List[LayerResult],
        mode: str = "quick_scan"
    ) -> Tuple[VerdictState, int, Dict[str, Any]]:
        """
        Calcula o veredito determinístico seguindo estritamente a precedência de 4.1.
        Retorna (VerdictState, score, metadata_de_resumo).
        """
        mode_cfg = self.modes.get(mode, {"required_layers": [], "optional_layers": []})
        required_layer_ids = set(mode_cfg.get("required_layers", []))

        # Verificar se alguma camada obrigatória falhou
        layers_by_id = {l.id: l for l in layers}
        missing_or_failed_layers = []

        for req_id in required_layer_ids:
            lr = layers_by_id.get(req_id)
            if not lr:
                missing_or_failed_layers.append((req_id, "MISSING"))
            elif lr.status in (LayerStatus.ERROR, LayerStatus.SKIPPED, LayerStatus.TIMEOUT):
                missing_or_failed_layers.append((req_id, lr.status.value))

        # Agrupar findings por severidade
        has_critical = any(f.severity == "CRITICAL" for f in findings)
        has_high = any(f.severity == "HIGH" for f in findings)
        has_medium = any(f.severity == "MEDIUM" for f in findings)
        has_pkg_disabled = any(f.code == "PKG_IOC_DISABLED" for f in findings)

        # Calcular score informativo (soma dos pesos por code + subject únicos)
        seen_keys: Set[Tuple[str, str]] = set()
        score = 0
        for f in findings:
            key = (f.code, f.subject)
            if key not in seen_keys:
                seen_keys.add(key)
                score += f.weight

        summary = {
            "score": score,
            "mode": mode,
            "total_findings": len(findings),
            "missing_or_failed_layers": missing_or_failed_layers,
            "findings_by_severity": {
                "CRITICAL": [f.to_dict() for f in findings if f.severity == "CRITICAL"],
                "HIGH": [f.to_dict() for f in findings if f.severity == "HIGH"],
                "MEDIUM": [f.to_dict() for f in findings if f.severity == "MEDIUM"],
                "LOW": [f.to_dict() for f in findings if f.severity == "LOW"],
                "INFO": [f.to_dict() for f in findings if f.severity == "INFO"],
            }
        }

        # 1. INFECTED (>=1 finding CRITICAL)
        if has_critical:
            return VerdictState.INFECTED, score, summary

        # 2. SUSPICIOUS (>=1 HIGH ou MEDIUM)
        if has_high or has_medium:
            summary["coverage_warning"] = bool(missing_or_failed_layers)
            return VerdictState.SUSPICIOUS, score, summary

        # 3. INCONCLUSIVE (camada obrigatória falhada ou dados ausentes)
        if missing_or_failed_layers:
            return VerdictState.INCONCLUSIVE, score, summary

        # 4. NEUTRALIZED (só INFO/LOW com >=1 PKG_IOC_DISABLED e camadas OK)
        if has_pkg_disabled:
            return VerdictState.NEUTRALIZED, score, summary

        # 5. CLEAN (só INFO/LOW e todas as camadas obrigatórias OK)
        return VerdictState.CLEAN, score, summary


# Instância global do motor
GLOBAL_ENGINE = RuleEngine()


def evaluate_audit(findings: List[Finding], layers: List[LayerResult], mode: str = "quick_scan") -> Tuple[VerdictState, int, Dict[str, Any]]:
    return GLOBAL_ENGINE.evaluate(findings, layers, mode=mode)
