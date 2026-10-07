"""
scanners/semgrep_scanner.py
Executa o Semgrep internamente (SAST — análise estática de código-fonte).

Requer o binário `semgrep` instalado e no PATH.
Instalação:
  https://semgrep.dev/docs/getting-started/
  pip install semgrep
  macOS (brew): brew install semgrep

Observação importante (validada com scan real contra Teiko-org/backend):
o código de saída do Semgrep não é confiável como sinal de sucesso — ele
retorna != 0 tanto em erros reais quanto em execuções que apenas
encontraram findings (dependendo da versão/config). Por isso, assim como
no TrivyScanner, quem decide se o scan funcionou é a EXISTÊNCIA do
arquivo de relatório, não o returncode.

Observação 2 (bug real encontrado em teste no Windows, 30/09/2026): o
Semgrep é ele mesmo um programa Python. Em Windows com a página de código
do sistema diferente de UTF-8 (comum em instalação PT-BR, ex. cp1252), o
Python do Semgrep escreve o `--output` na codificação padrão do SISTEMA,
não em UTF-8 — e o JSON de resultado quase sempre tem algum caractere fora
do cp1252 (comentário/string Unicode em algum arquivo escaneado). Isso
derruba o Semgrep no meio da escrita com `UnicodeEncodeError`, o relatório
fica truncado/vazio, e a ASPM reporta "formato não reconhecido" — quando na
real o arquivo nunca terminou de ser escrito. Forçamos UTF-8 via variável
de ambiente só para este subprocesso (ver `_run_process(..., env=...)`
abaixo), sem depender do usuário mudar a configuração regional do Windows.
"""
import os
import shutil
import subprocess
from pathlib import Path

from scanners.base_scanner import BaseScanner, ScannerResult, ScanCancelled


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    def is_installed(self) -> bool:
        return shutil.which("semgrep") is not None

    def install_hint(self) -> str:
        return (
            "Semgrep não encontrado no PATH.\n"
            "Instale com: pip install semgrep\n"
            "macOS (brew): brew install semgrep\n"
            "Mais opções: https://semgrep.dev/docs/getting-started/"
        )

    def run(self, target: str, timeout: int = 300) -> ScannerResult:
        if not self.is_installed():
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=self.install_hint(),
            )

        report_path = self._new_report_path()  # único por execução (ver BaseScanner)

        cmd = [
            "semgrep",
            "--config", "auto",
            "--json",
            "--output", report_path,
            "--quiet",
            target,
        ]

        # PYTHONUTF8/PYTHONIOENCODING forçam o interpretador Python do
        # Semgrep a usar UTF-8 na escrita do --output, independente da
        # página de código do Windows configurada no sistema (ver docstring
        # do módulo — "Observação 2").
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

        try:
            proc = self._run_process(cmd, timeout, env=env)
        except ScanCancelled:
            raise  # sobe até o ScanWorker, que interrompe os scanners seguintes
        except subprocess.TimeoutExpired:
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=f"Semgrep excedeu o tempo limite de {timeout}s para o alvo '{target}'.",
            )
        except Exception as e:
            return ScannerResult(tool=self.name, report_path="", success=False, error=str(e))

        # Não confiamos no returncode (ver docstring) — o sinal real de
        # sucesso é o arquivo de relatório ter sido gerado.
        if not Path(report_path).exists():
            return ScannerResult(
                tool=self.name, report_path="", success=False,
                error=proc.stderr.strip() or "Semgrep executou mas não gerou relatório.",
            )

        return ScannerResult(tool=self.name, report_path=report_path, success=True)
