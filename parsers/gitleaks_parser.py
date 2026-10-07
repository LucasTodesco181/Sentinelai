# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
parsers/gitleaks_parser.py
Processa relatórios JSON gerados pelo Gitleaks.

Gerar com:
    gitleaks detect --source . -r gitleaks_report.json -f json
"""
import uuid
from datetime import datetime
from pathlib import Path

from parsers.base_parser import BaseParser, load_json
from core.models import ScanReport, Vulnerability, Severity, ScanType, Status
from core.gitleaks_i18n import translate_description


class GitleaksParser(BaseParser):
    """
    Gitleaks não tem severidade nativa — todo vazamento de segredo
    é tratado como CRITICAL por padrão (segredo exposto = comprometimento direto).
    """

    def can_parse(self, file_path: str) -> bool:
        try:
            data = load_json(file_path)
            # Gitleaks retorna array de objetos com 'RuleID' e 'Commit'.
            # Quando não encontra NENHUM segredo (scan limpo), o relatório é
            # um array vazio '[]' — um resultado válido, não um erro (mesma
            # lógica do 'Results' ausente no Trivy, ver parsers/trivy_parser.py).
            # Exigir len(data) > 0 fazia esse caso (o melhor resultado
            # possível) ser rejeitado como "formato não reconhecido".
            # Nenhum outro parser aceita um array vazio na raiz (Semgrep/ZAP/
            # Snyk esperam um objeto), então não há ambiguidade em tratar
            # '[]' como Gitleaks.
            if not isinstance(data, list):
                return False
            if len(data) == 0:
                return True
            return "RuleID" in data[0] and "Commit" in data[0]
        except Exception:
            return False

    def parse(self, file_path: str) -> ScanReport:
        data = load_json(file_path)

        vulns: list[Vulnerability] = []

        for finding in data:
            rule_id = finding.get("RuleID", "unknown-rule")
            original_description = finding.get("Description", "")
            secret_masked = self._mask_secret(finding.get("Secret", ""))

            # O Gitleaks não tem saída em pt-br — a Description vem fixa em
            # inglês, embutida na própria regra. Traduzimos por RuleID (ver
            # core/gitleaks_i18n.py) e mantemos o texto original da
            # ferramenta logo abaixo, pra quem precisar conferir a fonte
            # exata (auditoria) — a tradução é um resumo, não substitui o
            # dado original.
            description_pt = translate_description(rule_id)

            vuln = Vulnerability(
                id=str(uuid.uuid4()),
                title=f"Segredo exposto: {rule_id}",
                severity=Severity.CRITICAL,          # sempre crítico
                scan_type=ScanType.SECRETS,
                tool="gitleaks",
                file_path=finding.get("File"),
                line=finding.get("StartLine"),
                description=(
                    f"{description_pt}\n"
                    f"Descrição original da ferramenta (inglês): {original_description}\n"
                    f"Commit: {finding.get('Commit', 'N/A')}\n"
                    f"Author: {finding.get('Author', 'N/A')}\n"
                    f"Secret (mascarado): {secret_masked}"
                ),
                remediation=(
                    "1. Revogar a credencial imediatamente.\n"
                    "2. Remover do histórico Git com git-filter-repo.\n"
                    "3. Adicionar ao .gitignore ou usar variáveis de ambiente."
                ),
                rule_id=rule_id,
                status=Status.OPEN,
                found_at=datetime.now(),
            )
            vulns.append(vuln)

        return ScanReport(
            tool="gitleaks",
            scan_type=ScanType.SECRETS,
            target=Path(file_path).stem,
            scanned_at=datetime.now(),
            vulnerabilities=vulns,
            raw_file=file_path,
        )

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Mostra apenas os 4 primeiros caracteres — nunca exibe o segredo completo."""
        if len(secret) <= 4:
            return "****"
        return secret[:4] + "*" * (len(secret) - 4)
