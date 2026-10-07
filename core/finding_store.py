# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
core/finding_store.py
Persistência local dos Findings — data/findings.json.

Antes deste módulo, core/aggregator.py mantinha os achados só em memória
(self._reports = []): fechar o app perdia tudo — findings, status
("Corrigida"/"Risco aceito"), vínculo com Asset. Segue o mesmo padrão de
persistência já usado por core/asset.py e core/company_context.py (JSON em
data/, load/save simples) em vez de introduzir SQLite — não há necessidade
de um banco relacional para o volume de dados de um ASPM local, e manter
tudo em JSON deixa a stack de persistência inteira do projeto consistente.

Responsabilidade deste módulo: I/O em disco + a lógica de merge que impede
duplicação (ver upsert()). NÃO decide nada de UI nem mexe em Dashboard/IA/
Attack Path — eles continuam recebendo list[Vulnerability] normalmente.
"""
import json
import os
import sys
from dataclasses import asdict, fields
from datetime import datetime
from pathlib import Path

from core.models import Vulnerability, Severity, ScanType, Status
from core.finding_identity import fingerprint

if getattr(sys, "frozen", False):
    _DATA_DIR = Path(os.getenv("APPDATA", str(Path.home()))) / "SentinelAI"
else:
    _DATA_DIR = Path(__file__).parent.parent / "data"

FINDINGS_FILE = _DATA_DIR / "findings.json"

_ENUM_FIELDS = {"severity": Severity, "scan_type": ScanType, "status": Status}
_DATETIME_FIELDS = ("found_at", "last_seen")
_KNOWN_FIELDS = {f.name for f in fields(Vulnerability)}


def _to_dict(v: Vulnerability) -> dict:
    d = asdict(v)
    for key in _DATETIME_FIELDS:
        val = d.get(key)
        d[key] = val.isoformat() if isinstance(val, datetime) else val
    # Enums (Severity/ScanType/Status) são subclasses de str — json.dumps já
    # serializa como o valor puro ("critical", não "Severity.CRITICAL"),
    # então não precisam de conversão aqui.
    return d


def _from_dict(d: dict) -> Vulnerability | None:
    """Reconstrói uma Vulnerability a partir do JSON salvo.

    Tolerante a dado incompleto/desatualizado (item 11 do documento de
    evolução — compatibilidade): ignora chaves desconhecidas, usa o default
    do dataclass para qualquer campo ausente, e descarta silenciosamente um
    registro corrompido em vez de derrubar a carga inteira dos findings.
    """
    try:
        clean = {k: v for k, v in d.items() if k in _KNOWN_FIELDS}
        for key, enum_cls in _ENUM_FIELDS.items():
            if key in clean and clean[key] is not None:
                clean[key] = enum_cls(clean[key])
        for key in _DATETIME_FIELDS:
            if key in clean and isinstance(clean[key], str):
                clean[key] = datetime.fromisoformat(clean[key])
        return Vulnerability(**clean)
    except Exception as e:
        print(f"[finding_store] Registro ignorado (dado inválido): {e}")
        return None


def load_all() -> list[Vulnerability]:
    """Carrega todos os findings persistidos. Lista vazia se não existir
    ou se o arquivo estiver corrompido — nunca derruba a inicialização."""
    try:
        if FINDINGS_FILE.exists():
            with open(FINDINGS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            result = [_from_dict(item) for item in data]
            return [v for v in result if v is not None]
    except Exception as e:
        print(f"[finding_store] Erro ao carregar: {e}")
    return []


def save_all(vulns: list[Vulnerability]) -> bool:
    """Salva a lista completa de findings em JSON. Retorna True se sucesso."""
    try:
        FINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
            json.dump([_to_dict(v) for v in vulns], f, ensure_ascii=False, indent=2, default=str)
        return True
    except Exception as e:
        print(f"[finding_store] Erro ao salvar: {e}")
        return False


def upsert(existing: list[Vulnerability], incoming: list[Vulnerability],
           scan_id: str | None = None) -> tuple[list[Vulnerability], dict]:
    """Mescla achados recém-importados/escaneados com o que já está
    persistido, por fingerprint — não por id (o id é um uuid novo a cada
    parse, ver core/finding_identity.py).

    Regras (documento de evolução dos Findings, seções 2/3/5/6/7):
      - fingerprint já existe  -> mesmo finding: atualiza campos técnicos
        (título, severidade, descrição, remediation, last_seen, scan_id),
        PRESERVA status e asset_id (triagem manual nunca é perdida) e
        preserva id/found_at originais.
      - fingerprint novo       -> finding novo: entra como está.
      - existente cujo fingerprint NÃO veio nesta leva -> não é tocado, ou
        seja, seu last_seen não avança. Isso por si só já é o sinal de "não
        apareceu no último scan" (cenário C do documento) sem precisar de
        um campo novo ou de marcar como corrigido automaticamente (a
        decisão de "Corrigida" continua manual, como o documento exige). Se
        ele reaparecer num scan futuro, o merge de novo bate no mesmo
        fingerprint e o last_seen volta a avançar — o próprio histórico de
        last_seen registra o reaparecimento (cenário D), sem lógica extra.

    Retorna (lista_mesclada, stats) — stats = {"new": int, "updated": int},
    só para instrumentação/teste; não é usado por nenhuma tela.
    """
    now = datetime.now()
    by_fp: dict[str, Vulnerability] = {}
    for v in existing:
        fp = v.fingerprint or fingerprint(v)
        v.fingerprint = fp
        by_fp[fp] = v

    stats = {"new": 0, "updated": 0}
    for inc in incoming:
        fp = fingerprint(inc)
        inc.fingerprint = fp
        inc.last_seen = now
        inc.scan_id = scan_id

        match = by_fp.get(fp)
        if match is None:
            by_fp[fp] = inc
            stats["new"] += 1
        else:
            match.title = inc.title
            match.severity = inc.severity
            match.scan_type = inc.scan_type
            match.tool = inc.tool
            match.file_path = inc.file_path
            match.line = inc.line
            match.url = inc.url
            match.cve_id = inc.cve_id
            match.cvss_score = inc.cvss_score
            match.description = inc.description
            match.remediation = inc.remediation
            match.rule_id = inc.rule_id
            match.last_seen = now
            match.scan_id = scan_id
            # NÃO tocados: match.id, match.found_at, match.status, match.asset_id
            stats["updated"] += 1

    return list(by_fp.values()), stats
