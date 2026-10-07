# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
scanners/grype_scanner.py
Executa o Grype (Anchore) internamente — segundo motor de SCA da ASPM,
convivendo com o Trivy (que já cobre SCA no modo fs — ver
parsers/trivy_parser.py) em vez de substituí-lo.

Por que um segundo motor de SCA e não só confiar no Trivy:
  - Trivy e Grype usam bases de dados de vulnerabilidade parcialmente
    diferentes (Trivy agrega NVD/GHSA/Red Hat/Alpine etc.; o Grype usa a
    própria base da Anchore, também agregando NVD/GHSA/OSV). Nem sempre um
    CVE novo aparece nos dois ao mesmo tempo — rodar os dois aumenta a
    chance de pegar uma dependência vulnerável que só um dos dois já
    catalogou.
  - Onde os dois concordam (mesmo pacote, mesmo CVE), isso é justamente o
    tipo de sinal cruzado que dá mais confiança pra banca/cliente do que
    uma ferramenta isolada.

Diferente do Snyk (que exige conta/token e por isso continua só manual —
ver parsers/snyk_parser.py), o Grype é um binário único, sem
autenticação, com base de dados local — mesma filosofia de instalação do
Trivy.

Requer o binário `grype` instalado e no PATH.
Instalação:
  https://github.com/anchore/grype#installation
  macOS (brew):   brew install grype
  Windows (scoop): scoop install grype
  Linux (script):  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
"""
import shutil
import subprocess
from pathlib import Path

from scanners.base_scanner import BaseScanner, ScannerResult, ScanCancelled


class GrypeScanner(BaseScanner):
    name = "grype"

    def is_installed(self) -> bool:
        return shutil.which("grype") is not None

    def install_hint(self) -> str:
        return (
            "Grype não encontrado no PATH.\n"
            "Instale em: https://github.com/anchore/grype#installation\n"
            "macOS (brew): brew install grype\n"
            "Windows (scoop): scoop install grype"
        )

    def run(self, target: str, timeout: int = 300) -> ScannerResult:
        if not self.is_installed():
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=self.install_hint(),
            )

        report_path = self._new_report_path()  # único por execução (ver BaseScanner)

        cmd = [
            "grype", f"dir:{target}",
            "-o", "json",
            "--file", report_path,
            # npm/pip/maven vêm por padrão com o ID do GitHub (GHSA-...) e o
            # CVE só em relatedVulnerabilities. Com --by-cve o achado sai
            # como CVE-..., que é o que o cruzamento com CISA KEV/EPSS e com
            # o Trivy precisa.
            "--by-cve",
            "-q",  # sem barra de progresso — não interessa no modo automação
        ]

        try:
            proc = self._run_process(cmd, timeout)
        except ScanCancelled:
            raise  # sobe até o ScanWorker, que interrompe os scanners seguintes
        except subprocess.TimeoutExpired:
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=f"Grype excedeu o tempo limite de {timeout}s para o alvo '{target}'.",
            )
        except Exception as e:
            return ScannerResult(tool=self.name, report_path="", success=False, error=str(e))

        # O Grype só retorna código != 0 se --fail-on estiver configurado
        # (não configuramos). Igual Trivy/Semgrep/Gitleaks: o sinal real de
        # sucesso é o relatório ter sido gerado, não o returncode.
        if not Path(report_path).exists():
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=proc.stderr.strip() or "Grype executou mas não gerou relatório.",
            )

        return ScannerResult(tool=self.name, report_path=report_path, success=True)
