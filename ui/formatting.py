# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ui/formatting.py
Formatação de campos de Vulnerability para exibição — um lugar só, para a
tabela de Findings, o painel de detalhe, a lista da aba de IA e os cards de
Priorização mostrarem a mesma coisa do mesmo jeito.
"""
import html
import re
from pathlib import PurePosixPath

from core.models import Vulnerability, Status
from ui import theme

STATUS_LABELS_PT = {
    Status.OPEN:      "Aberta",
    Status.IN_REVIEW: "Em revisão",
    Status.FIXED:     "Corrigida",
    Status.ACCEPTED:  "Risco aceito",
}

# Nome de exibição de cada ferramenta — str.capitalize() dava "Zap" e "Gitleaks".
TOOL_LABELS = {
    "trivy": "Trivy", "semgrep": "Semgrep", "gitleaks": "Gitleaks",
    "zap": "ZAP", "snyk": "Snyk", "grype": "Grype",
}


def tool_label(tool: str) -> str:
    return TOOL_LABELS.get(tool, (tool or "").capitalize())


_TAG = re.compile(r"<[^>]+>")
_BLOCK_END = re.compile(r"</(p|li|div|br)\s*>|<br\s*/?>", re.IGNORECASE)


def plain_text(text: str) -> str:
    """Texto de descrição/remediação pronto para exibir.

    Algumas ferramentas mandam HTML nesses campos (o ZAP devolve
    "<p>...</p>"), que num QLabel apareceria com as tags cruas. Aqui as
    quebras de bloco viram quebra de linha, as demais tags saem e as
    entidades (&amp;, &lt;) são decodificadas. Texto sem HTML passa intacto.
    """
    if not text:
        return ""
    if "<" in text and ">" in text:
        text = _BLOCK_END.sub("\n", text)
        text = _TAG.sub("", text)
    text = html.unescape(text)
    lines = [ln.strip() for ln in text.splitlines()]
    # colapsa linhas vazias repetidas
    out, blank = [], False
    for ln in lines:
        if not ln:
            if not blank and out:
                out.append("")
            blank = True
        else:
            out.append(ln)
            blank = False
    return "\n".join(out).strip()


def severity_label(v: Vulnerability) -> str:
    """Severidade em pt-br ("Crítica", "Alta"...) — antes a aba de IA ainda
    mostrava "[CRITICAL]" enquanto Findings já estava traduzida (P2 #13)."""
    return theme.SEVERITY_LABELS_PT.get(v.severity.value, v.severity.value.upper())


def short_location(v: Vulnerability) -> str:
    """Local curto para colunas e listas: "arquivo.py:42" ou a URL.

    A coluna "Arquivo / URL" mostrava o caminho absoluto inteiro, e o corte
    padrão do Qt (que mantém o começo) deixava só "C:..." — o prefixo do
    Windows, sem o nome do arquivo (P1 #7). O nome do arquivo + linha é o
    que identifica o finding; o caminho completo vai no tooltip e no painel
    de detalhe.
    """
    if v.file_path:
        name = PurePosixPath(v.file_path.replace("\\", "/")).name or v.file_path
        return f"{name}:{v.line}" if v.line else name
    if v.url:
        return v.url
    return "—"


def full_location(v: Vulnerability) -> str:
    """Local completo, para tooltip e painel de detalhe."""
    if v.file_path:
        return f"{v.file_path}:{v.line}" if v.line else v.file_path
    return v.url or ""


def date_br(iso: str | None) -> str:
    """'2021-12-10' -> '10/12/2021' — datas sem horário (ex.: kev_date_added/
    kev_due_date do core/threat_intel.py, que vêm da CISA nesse formato).
    Vazio/formato inesperado -> devolve como veio (nunca lança exceção)."""
    if not iso:
        return ""
    parts = iso.split("-")
    return f"{parts[2]}/{parts[1]}/{parts[0]}" if len(parts) == 3 else iso


def datetime_br(iso: str | None) -> str:
    """'2026-09-24T23:40:12' -> '24/09/2026 23:40'. Vazio/inválido -> ''."""
    if not iso:
        return ""
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return ""
