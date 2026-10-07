# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
parsers/semgrep_parser.py
Processa relatórios JSON gerados pelo Semgrep.

Gerar com:
    semgrep scan --json -o semgrep_report.json <diretório>
"""
import uuid
from datetime import datetime
from pathlib import Path

from parsers.base_parser import BaseParser, load_json
from core.models import ScanReport, Vulnerability, Severity, ScanType, Status

SEVERITY_MAP = {
    "error":   Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info":    Severity.LOW,
    # Semgrep extras via metadata
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
}

# Siglas que ficam em maiúsculas no título legível ("Tainted SQL string").
_ACRONYMS = {
    "sql", "xss", "csrf", "ssrf", "xxe", "md5", "sha1", "url", "urls", "jwt",
    "tls", "ssl", "http", "https", "api", "aws", "gcp", "rsa", "des", "ecb",
    "cbc", "os", "id", "ip", "dns", "ldap", "xml", "html", "json", "yaml",
}


def readable_rule_title(check_id: str) -> str:
    """Título legível a partir do ID técnico de uma regra do Semgrep.

    O título era o check_id inteiro — ex.:
    "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected"
    — difícil de ler e que ocupava a coluna toda (P2 #13 da 2ª revisão de UI).
    O último segmento já descreve a regra; o ID completo continua guardado em
    Vulnerability.rule_id e aparece no painel de detalhe de Findings.

    "python.flask.security.xss.reflected-xss"            -> "Reflected XSS"
    "...insecure-hash.insecure-hash-algorithm-md5"       -> "Insecure hash algorithm MD5"
    """
    if not check_id:
        return ""
    last = check_id.rstrip(".").split(".")[-1]
    words = [w for w in last.replace("_", "-").split("-") if w]
    if not words:
        return check_id
    out = [w.upper() if w.lower() in _ACRONYMS else w.lower() for w in words]
    if not words[0].lower() in _ACRONYMS:
        out[0] = out[0].capitalize()
    return " ".join(out)


class SemgrepParser(BaseParser):

    def can_parse(self, file_path: str) -> bool:
        """Detecta se é um relatório Semgrep verificando a chave 'results'."""
        try:
            data = load_json(file_path)
            return "results" in data and "version" in data
        except Exception:
            return False

    def parse(self, file_path: str) -> ScanReport:
        data = load_json(file_path)

        vulns: list[Vulnerability] = []

        for result in data.get("results", []):
            meta = result.get("extra") or {}
            # `or` em vez do default do .get(): um campo presente com valor
            # null (acontece em regras customizadas) devolvia None e o
            # .lower() derrubava a importação inteira.
            severity_raw = (meta.get("severity") or "warning").lower()
            severity = SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)

            check_id = result.get("check_id", "")
            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                title=readable_rule_title(check_id) or "Sem título",
                severity=severity,
                scan_type=ScanType.SAST,
                tool="semgrep",
                file_path=result.get("path"),
                line=result.get("start", {}).get("line"),
                description=meta.get("message", ""),
                # A sugestão de correção do Semgrep vem em extra.fix (regras
                # com autofix); metadata.fix é só o que o autor da regra pôs.
                remediation=meta.get("fix") or (meta.get("metadata") or {}).get("fix", ""),
                rule_id=result.get("check_id"),
                status=Status.OPEN,
                found_at=datetime.now(),
            )
            vulns.append(vuln)

        return ScanReport(
            tool="semgrep",
            scan_type=ScanType.SAST,
            target=Path(file_path).stem,
            scanned_at=datetime.now(),
            vulnerabilities=vulns,
            raw_file=file_path,
        )
