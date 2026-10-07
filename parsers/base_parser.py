# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
parsers/base_parser.py
Interface abstrata que todos os parsers devem implementar.
"""
import json
from abc import ABC, abstractmethod
from core.models import ScanReport


def load_json(file_path: str):
    """Lê um relatório JSON tolerando as codificações que aparecem no Windows.

    `snyk test --json > arquivo.json` no PowerShell 5.1 grava UTF-16 (com BOM),
    e vários editores salvam UTF-8 com BOM — o json.load(encoding="utf-8")
    recusava os dois e o import dizia "formato não reconhecido" para um
    relatório perfeitamente válido. Lê os bytes e decide pelo BOM.
    """
    raw = open(file_path, "rb").read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    return json.loads(text)


class BaseParser(ABC):
    """
    Cada parser recebe o caminho de um arquivo de relatório
    e retorna um ScanReport normalizado.
    """

    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """
        Verifica se este parser consegue processar o arquivo.
        Usado pela detecção automática de formato.
        """
        ...

    @abstractmethod
    def parse(self, file_path: str) -> ScanReport:
        """Lê o arquivo e retorna um ScanReport com vulnerabilidades normalizadas."""
        ...

    def _safe_severity(self, raw: str, mapping: dict) -> str:
        """Normaliza string de severidade usando um mapeamento customizado."""
        return mapping.get(raw.lower().strip(), "medium")
