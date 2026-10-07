# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
parsers/snyk_parser.py
Processa relatórios JSON gerados pelo Snyk CLI.

Gerar com:
    snyk test --json > snyk_report.json
    snyk test --all-projects --json > snyk_report.json
"""
import uuid
from datetime import datetime
from pathlib import Path

from parsers.base_parser import BaseParser, load_json
from core.models import ScanReport, Vulnerability, Severity, ScanType, Status

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
}


class SnykParser(BaseParser):

    def can_parse(self, file_path: str) -> bool:
        try:
            data = load_json(file_path)
            # Snyk tem 'vulnerabilities' e 'projectName'
            return "vulnerabilities" in data or (
                isinstance(data, list) and "vulnerabilities" in data[0]
            )
        except Exception:
            return False

    def parse(self, file_path: str) -> ScanReport:
        data = load_json(file_path)

        # Snyk pode retornar array (--all-projects) ou objeto único
        reports = data if isinstance(data, list) else [data]

        vulns: list[Vulnerability] = []
        project_name = reports[0].get("projectName", Path(file_path).stem)

        for report in reports:
            for v in report.get("vulnerabilities", []):
                severity = SEVERITY_MAP.get(v.get("severity", "medium"), Severity.MEDIUM)

                # Extrai CVE — Snyk lista múltiplos identifiers
                identifiers = v.get("identifiers", {})
                cve_list = identifiers.get("CVE", [])
                cve_id = cve_list[0] if cve_list else None

                # CVSS score — Snyk fornece cvssScore
                cvss = v.get("cvssScore")
                try:
                    cvss = float(cvss) if cvss is not None else None
                except (ValueError, TypeError):
                    cvss = None

                vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    title=v.get("title", "Snyk Finding"),
                    severity=severity,
                    scan_type=ScanType.SCA,
                    tool="snyk",
                    description=v.get("description", ""),
                    remediation=v.get("fixedIn", [""])[0] if v.get("fixedIn") else "",
                    cve_id=cve_id,
                    cvss_score=cvss,
                    rule_id=v.get("id"),
                    # caminho do pacote vulnerável como file_path
                    file_path=v.get("packageName"),
                    status=Status.OPEN,
                    found_at=datetime.now(),
                )
                vulns.append(vuln)

        return ScanReport(
            tool="snyk",
            scan_type=ScanType.SCA,
            target=project_name,
            scanned_at=datetime.now(),
            vulnerabilities=vulns,
            raw_file=file_path,
        )
