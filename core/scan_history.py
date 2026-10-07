# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
core/scan_history.py
Registro leve de execuções de scan — separa o conceito de SCAN (uma
execução/importação) do conceito de FINDING (um problema que pode
aparecer em vários scans, ver core/finding_store.py).

Escopo deliberadamente enxuto (documento de evolução dos Findings, seção 4:
"Não é necessário criar uma UI complexa para isso nesta etapa. A estrutura
precisa apenas ficar preparada para o histórico."): guarda só metadados por
execução, não a lista de findings de cada scan (isso já vive no próprio
Vulnerability.scan_id, ver finding_store.upsert) — evita um segundo lugar
pra manter sincronizado e um JSON que cresce sem necessidade.

Persistido em data/scans.json, mesmo padrão de core/asset.py.
"""
import json
import os
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

if getattr(sys, "frozen", False):
    _DATA_DIR = Path(os.getenv("APPDATA", str(Path.home()))) / "SentinelAI"
else:
    _DATA_DIR = Path(__file__).parent.parent / "data"

SCANS_FILE = _DATA_DIR / "scans.json"

# Quantidade máxima de execuções mantidas no histórico — sem isso, o JSON
# cresceria indefinidamente num app usado por meses. É metadado, não é
# usado para decidir nada de status ou dedupe (isso é por fingerprint,
# ver finding_store.py), então descartar entradas antigas é seguro.
MAX_ENTRIES = 200


@dataclass
class ScanRecord:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    target: str = ""                          # pasta escaneada ou "importação manual"
    tools: list[str] = field(default_factory=list)
    finding_count: int = 0
    status: str = "success"                    # success | partial | failed
    duration_seconds: float | None = None


def load_all() -> list[ScanRecord]:
    try:
        if SCANS_FILE.exists():
            with open(SCANS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return [ScanRecord(**item) for item in data]
    except Exception as e:
        print(f"[scan_history] Erro ao carregar: {e}")
    return []


def _save(records: list[ScanRecord]) -> bool:
    try:
        SCANS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SCANS_FILE, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in records[-MAX_ENTRIES:]], f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[scan_history] Erro ao salvar: {e}")
        return False


def record(target: str, tools: list[str], finding_count: int, status: str = "success",
           duration_seconds: float | None = None, scan_id: str | None = None) -> ScanRecord:
    """Registra uma execução de scan e retorna o ScanRecord criado (já com
    scan_id — usado por quem chamou para marcar Vulnerability.scan_id)."""
    entry = ScanRecord(
        scan_id=scan_id or str(uuid.uuid4()),
        target=target,
        tools=tools,
        finding_count=finding_count,
        status=status,
        duration_seconds=duration_seconds,
    )
    records = load_all()
    records.append(entry)
    _save(records)
    return entry


def clear_all() -> bool:
    """Apaga o histórico de execuções — chamado por ui/main_window.py::
    _on_clear junto com finding_store, já que o botão "Limpar" único do app
    (ver comentário lá) apaga findings E o histórico de scans juntos."""
    return _save([])


def covered_tools() -> set[str]:
    """Ferramentas que já apareceram em algum scan registrado — usado para
    a cobertura do Dashboard (core/coverage.py) continuar correta depois de
    reabrir o app, já que core.aggregator.reports (em memória) volta vazio
    a cada início, mas o histórico persistido não."""
    tools: set[str] = set()
    for r in load_all():
        tools.update(r.tools)
    return tools
