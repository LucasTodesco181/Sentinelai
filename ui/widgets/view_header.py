# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ui/widgets/view_header.py
Cabeçalho padrão de view (56px, título com ícone vetorial + subtítulo
opcional) — extraído de Ativos/Contexto para as views pararem de reinventar
o mesmo bloco cada uma do seu jeito (uma com emoji, outra sem cabeçalho
nenhum). Usado por AssetsView, ContextView, FindingsView e AIView.
"""
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy
from PyQt6.QtGui import QFont

from ui import theme
from ui.icons import icon


def build_header(icon_name: str, title_text: str, subtitle_text: str = "") -> QFrame:
    header = QFrame()
    # objectName + seletor "#viewHeader" (em vez de propriedades soltas sem
    # seletor) — sem isso o Qt repassava background/border-bottom para todo
    # QLabel filho (ícone, título, subtítulo), que aí cobria a borda de baixo
    # exatamente onde havia texto, fazendo a linha do cabeçalho "sumir" atrás
    # deles (P1 #5 da revisão de UI).
    header.setObjectName("viewHeader")
    header.setStyleSheet(
        f"#viewHeader {{ background:{theme.BG_SURFACE}; border-bottom:1px solid {theme.BORDER}; }}"
    )
    header.setFixedHeight(56)
    hl = QHBoxLayout(header)
    hl.setContentsMargins(20, 0, 20, 0)
    hl.setSpacing(10)

    icon_lbl = QLabel()
    icon_lbl.setPixmap(icon(icon_name, theme.TEXT_PRIMARY, 18).pixmap(18, 18))
    icon_lbl.setStyleSheet("border:none;")
    hl.addWidget(icon_lbl)

    title = QLabel(title_text)
    title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
    title.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; border:none;")
    hl.addWidget(title)

    if subtitle_text:
        subtitle = QLabel(subtitle_text)
        subtitle.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px; border:none;")
        subtitle.setToolTip(subtitle_text)
        # Pode encolher (e ser cortado) quando o cabeçalho também tem botões
        # de ação e a janela está estreita — o título e os botões têm
        # prioridade. Sem isso, o subtítulo empurrava os botões para fora.
        subtitle.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        subtitle.setMinimumWidth(0)
        hl.addWidget(subtitle, 1)
    else:
        hl.addStretch()
    header.content_layout = hl  # o chamador pode addWidget() extra (botões, status) antes de retornar
    return header
