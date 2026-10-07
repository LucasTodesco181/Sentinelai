# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
scanners/base_scanner.py
Interface abstrata para scanners executados INTERNAMENTE pela ASPM.

Diferença para parsers/base_parser.py:
  - BaseParser  → LÊ um relatório (JSON/XML) já existente e normaliza.
  - BaseScanner → EXECUTA a ferramenta de verdade (subprocess) contra um
                  alvo (pasta, imagem docker, repositório) e GERA esse
                  relatório.

O objetivo é a ASPM não depender mais de o usuário rodar "semgrep --json"
por fora e importar manualmente — a própria ASPM dispara a ferramenta.

Fluxo:
    scanner = TrivyScanner()
    if scanner.is_installed():
        result = scanner.run(target="./meu-projeto")
        if result.success:
            aggregator.import_file(result.report_path)   # reaproveita o parser já existente
    else:
        print(scanner.install_hint())

Importante: um BaseScanner NUNCA interpreta o resultado — ele só gera um
arquivo de relatório no formato nativo da ferramenta. Quem entende esse
arquivo é sempre um parsers/*_parser.py já existente (ou novo, seguindo o
mesmo padrão). Isso mantém os dois papéis separados: "executar" x "entender".
"""
import os
import subprocess
import sys
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass


class ScanCancelled(Exception):
    """O usuário cancelou o scan enquanto a ferramenta rodava."""


@dataclass
class ScannerResult:
    """Resultado de uma execução de scanner. Nunca lança exceção — erros
    vêm sempre aqui dentro, para a UI poder mostrar uma mensagem amigável
    em vez de travar com um traceback."""
    tool: str
    report_path: str      # caminho do relatório gerado (vazio se success=False)
    success: bool
    error: str = ""


class BaseScanner(ABC):
    """
    Cada scanner concreto (Trivy, e futuramente Checkov, Bandit, TruffleHog...)
    precisa saber responder a duas perguntas:
      1. is_installed() — a ferramenta está disponível nesta máquina?
      2. run(target)    — execute o scan e devolva o caminho do relatório.
    """

    #: nome curto usado em logs, na UI e para identificar o scanner
    name: str = "base"

    #: definido por quem dispara o scan (ScanWorker) para permitir cancelar
    #: no meio da execução; None = não cancelável.
    cancel_event: threading.Event | None = None

    def _new_report_path(self) -> str:
        """Caminho de relatório ÚNICO por execução.

        Antes cada scanner escrevia sempre no mesmo arquivo fixo do temp
        (ex.: %TEMP%/semgrep_report.json) e considerava "o arquivo existe"
        como sinal de sucesso. Se a execução atual falhasse sem escrever
        nada, o relatório de um scan ANTERIOR — possivelmente de outro
        projeto — continuava lá e era importado como se fosse deste. Com um
        nome novo por execução (e o arquivo ainda inexistente), só existe
        relatório se esta execução o criou.
        """
        fd, path = tempfile.mkstemp(prefix=f"sentinelai_{self.name}_", suffix=".json")
        os.close(fd)
        os.unlink(path)
        return path

    def _run_process(self, cmd: list[str], timeout: int, cwd: str | None = None,
                      env: dict | None = None) -> subprocess.CompletedProcess:
        """subprocess.run cancelável: espera o processo em fatias curtas e o
        encerra se cancel_event for acionado ou o tempo limite estourar.

        Lança ScanCancelled ou subprocess.TimeoutExpired nesses dois casos.

        `cwd` é opcional — usado pelo ZapScanner na execução nativa (fora do
        Docker), onde o `zap-baseline.py` grava o relatório relativo ao
        diretório de trabalho do processo.

        `env` é opcional — usado pelo SemgrepScanner (ver comentário lá) para
        forçar UTF-8 na saída de uma ferramenta que é ela mesma um programa
        Python, sem depender da codificação padrão do Windows do usuário.
        None (padrão) herda o ambiente do processo atual, igual antes.
        """
        # No .exe empacotado (--windowed) cada subprocesso abriria uma janela
        # preta de console durante o scan; CREATE_NO_WINDOW evita isso. O
        # stdin fechado impede que uma ferramenta que pergunta algo (ex.:
        # confirmação de atualização) fique esperando teclado para sempre.
        extra = {}
        if sys.platform == "win32":
            extra["creationflags"] = subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", cwd=cwd, env=env, **extra,
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                out, err = proc.communicate(timeout=0.3)
                return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
            except subprocess.TimeoutExpired:
                cancelled = self.cancel_event is not None and self.cancel_event.is_set()
                if cancelled or time.monotonic() > deadline:
                    proc.kill()
                    proc.communicate()
                    if cancelled:
                        raise ScanCancelled() from None
                    raise subprocess.TimeoutExpired(cmd, timeout) from None

    @abstractmethod
    def is_installed(self) -> bool:
        """Verifica se o binário/dependência da ferramenta está acessível."""
        ...

    @abstractmethod
    def run(self, target: str, timeout: int = 300) -> ScannerResult:
        """
        Executa o scan contra `target` (caminho local, imagem docker, URL —
        depende da ferramenta) e retorna o caminho do relatório gerado.
        Deve capturar qualquer erro internamente e devolver via
        ScannerResult.error, nunca lançar exceção para quem chamou.
        """
        ...

    def install_hint(self) -> str:
        """Mensagem exibida na UI quando is_installed() retorna False."""
        return f"Ferramenta '{self.name}' não encontrada no PATH desta máquina."
