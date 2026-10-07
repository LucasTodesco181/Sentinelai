"""
parsers/grype_parser.py
Processa relatórios JSON gerados pelo Grype (Anchore) — segundo motor de
SCA da ASPM, ao lado do Trivy (ver scanners/grype_scanner.py para o porquê
de ter os dois em vez de escolher um só).

Gerar manualmente com:
    grype dir:<pasta> -o json --file relatorio.json

Ou automaticamente via scanners/grype_scanner.py::GrypeScanner.run().
"""
import uuid
from datetime import datetime
from pathlib import Path

from parsers.base_parser import BaseParser, load_json
from core.models import ScanReport, Vulnerability, Severity, ScanType, Status

SEVERITY_MAP = {
    "critical":   Severity.CRITICAL,
    "high":       Severity.HIGH,
    "medium":     Severity.MEDIUM,
    "low":        Severity.LOW,
    "negligible": Severity.INFO,
    "unknown":    Severity.INFO,
}


class GrypeParser(BaseParser):

    def can_parse(self, file_path: str) -> bool:
        """
        Assinatura do Grype: objeto de topo com a chave 'matches' (lista).
        Nenhum outro parser usado nesta ASPM tem 'matches' na raiz (Semgrep
        usa 'results', ZAP 'site'/'alerts', Snyk 'vulnerabilities', Trivy
        'SchemaVersion', Gitleaks é um array puro) — sem ambiguidade.

        Igual ao Trivy (Results ausente) e ao Gitleaks (array vazio depois
        da correção do bug relatado): um scan limpo é 'matches': [], um
        resultado válido, não um erro de formato — então NÃO exigimos que a
        lista tenha itens pra reconhecer o relatório.
        """
        try:
            data = load_json(file_path)
            if not isinstance(data, dict) or "matches" not in data:
                return False
            matches = data["matches"]
            if not isinstance(matches, list):
                return False
            if len(matches) == 0:
                return True
            first = matches[0]
            return isinstance(first, dict) and "vulnerability" in first and "artifact" in first
        except Exception:
            return False

    def parse(self, file_path: str) -> ScanReport:
        data = load_json(file_path)

        target = (data.get("source", {}) or {}).get("target") or Path(file_path).stem

        vulns: list[Vulnerability] = []

        for match in data.get("matches", []) or []:
            vuln_info = match.get("vulnerability", {}) or {}
            artifact = match.get("artifact", {}) or {}

            vuln_id = vuln_info.get("id", "unknown")
            severity = SEVERITY_MAP.get(str(vuln_info.get("severity", "")).lower(), Severity.MEDIUM)

            pkg = artifact.get("name", "?")
            version = artifact.get("version", "")
            pkg_label = f"{pkg}@{version}" if version else pkg

            locations = artifact.get("locations") or []
            loc_path = None
            if locations and isinstance(locations[0], dict):
                loc_path = locations[0].get("path")
            file_path_field = f"{loc_path} ({pkg_label})" if loc_path else pkg_label

            # Achado por GHSA (npm/pip/maven sem --by-cve): o CVE e o CVSS
            # ficam em relatedVulnerabilities. Procura lá para não perder o
            # cruzamento com KEV/EPSS nem a nota.
            related = [r for r in (match.get("relatedVulnerabilities") or []) if isinstance(r, dict)]
            related_cve = next((r for r in related if str(r.get("id", "")).upper().startswith("CVE-")), None)

            cvss_score = None
            for source in [vuln_info] + ([related_cve] if related_cve else []) + related:
                for cvss in source.get("cvss", []) or []:
                    metrics = cvss.get("metrics", {}) or {}
                    if metrics.get("baseScore") is not None:
                        cvss_score = metrics["baseScore"]
                        break
                if cvss_score is not None:
                    break

            fix = vuln_info.get("fix", {}) or {}
            fix_versions = fix.get("versions") or []
            if fix.get("state") == "fixed" and fix_versions:
                remediation = f"Atualizar {pkg} para a versão {', '.join(fix_versions)}"
            else:
                remediation = "Sem correção disponível ainda."

            # Nem todo achado do Grype é um CVE (pode ser um GHSA-... sem
            # CVE associado ainda) — só preenche cve_id quando é mesmo um
            # CVE, senão o cruzamento com CISA KEV/EPSS (core/threat_intel.py,
            # que espera formato "CVE-AAAA-NNNNN") ficaria tentando buscar
            # um ID que nunca vai bater.
            cve_id = vuln_id if str(vuln_id).upper().startswith("CVE-") else (
                related_cve.get("id") if related_cve else None)

            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title=f"{vuln_id} em {pkg_label}",
                severity=severity,
                scan_type=ScanType.SCA,
                tool="grype",
                file_path=file_path_field,
                cve_id=cve_id,
                cvss_score=cvss_score,
                description=vuln_info.get("description", ""),
                remediation=remediation,
                rule_id=vuln_id,
                status=Status.OPEN,
                found_at=datetime.now(),
            ))

        return ScanReport(
            tool="grype",
            scan_type=ScanType.SCA,
            target=target,
            scanned_at=datetime.now(),
            vulnerabilities=vulns,
            raw_file=file_path,
        )
