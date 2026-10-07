# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ui/widgets/data_actions.py
Ações de dados (Escanear Pasta / Importar Relatório / Limpar) + progresso do
scan interno, num widget reaproveitável que vai no cabeçalho das telas onde
essas ações fazem sentido (Dashboard e Findings).

Antes essas ações ficavam numa topbar global de 56px, repetida em todas as
telas — inclusive Contexto e Ativos, onde não fazem sentido — e empilhada
em cima do cabeçalho de cada view (mais 56px): 112px antes do conteúdo
(P2 #10 da 2ª revisão de UI).

O mesmo widget mostra o progresso do scan (P1 #9): antes o único sinal de
um scan rodando era um texto de 11px na barra de status, e não dava para
cancelar — com Semgrep em --config auto, parecia travado.
"""
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QPushButton, QLabel, QProgressBar, QStackedWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ui import theme
from ui.icons import icon
from ui.formatting import tool_label


class DataActionsBar(QWidget):
    scan_clicked = pyqtSignal()
    zap_scan_clicked = pyqtSignal()
    import_clicked = pyqtSignal()
    clear_clicked = pyqtSignal()
    cancel_clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dataActions")
        self.setStyleSheet("#dataActions { background:transparent; border:none; }")

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self._pages = QStackedWidget()
        self._pages.setStyleSheet("background:transparent; border:none;")
        outer.addWidget(self._pages)

        # ── Página 0: ações ────────────────────────────────────────────────
        idle = QWidget()
        lay = QHBoxLayout(idle)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        self._btn_scan = QPushButton(" Escanear Pasta")
        self._btn_scan.setIcon(icon("shield", theme.TEXT_PRIMARY, 15))
        self._btn_scan.setToolTip("Roda Trivy, Semgrep, Gitleaks e Grype numa pasta de projeto")
        self._btn_scan.setFixedHeight(32)
        self._btn_scan.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {theme.TEXT_PRIMARY};
                border: 1px solid {theme.ACCENT}; border-radius: 6px;
                padding: 0 12px; font-size: 12px;
            }}
            QPushButton:hover {{ background: {theme.BG_ELEVATED}; }}
        """)
        self._btn_scan.clicked.connect(self.scan_clicked)
        lay.addWidget(self._btn_scan)

        self._btn_zap = QPushButton(" Escanear URL (ZAP)")
        self._btn_zap.setIcon(icon("target", theme.TEXT_PRIMARY, 15))
        self._btn_zap.setToolTip("Roda o OWASP ZAP (baseline scan) contra uma aplicação já rodando")
        self._btn_zap.setFixedHeight(32)
        self._btn_zap.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {theme.TEXT_PRIMARY};
                border: 1px solid {theme.ACCENT}; border-radius: 6px;
                padding: 0 12px; font-size: 12px;
            }}
            QPushButton:hover {{ background: {theme.BG_ELEVATED}; }}
        """)
        self._btn_zap.clicked.connect(self.zap_scan_clicked)
        lay.addWidget(self._btn_zap)

        btn_import = QPushButton(" Importar Relatório")
        btn_import.setIcon(icon("upload", theme.ACCENT_ON, 15))
        btn_import.setToolTip("Importa relatórios JSON/XML de Semgrep, Trivy, Gitleaks, Grype, Snyk ou ZAP")
        btn_import.setFixedHeight(32)
        btn_import.setStyleSheet(theme.button_style(
            theme.ACCENT, theme.ACCENT_HOVER, theme.ACCENT_PRESSED))
        btn_import.clicked.connect(self.import_clicked)
        lay.addWidget(btn_import)

        self._btn_clear = QPushButton(" Limpar")
        self._btn_clear.setIcon(icon("trash", theme.TEXT_MUTED, 15))
        self._btn_clear.setToolTip("Remove todos os findings importados nesta sessão")
        self._btn_clear.setFixedHeight(32)
        self._btn_clear.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {theme.TEXT_MUTED};
                border: 1px solid {theme.BORDER}; border-radius: 6px;
                padding: 0 12px; font-size: 12px;
            }}
            QPushButton:hover {{ color: {theme.TEXT_PRIMARY}; border-color: {theme.BORDER_STRONG}; }}
            QPushButton:disabled {{ color: {theme.BORDER_STRONG}; border-color: {theme.BORDER}; }}
        """)
        self._btn_clear.clicked.connect(self.clear_clicked)
        lay.addWidget(self._btn_clear)
        self._pages.addWidget(idle)

        # ── Página 1: scan em andamento ───────────────────────────────────
        busy = QWidget()
        blay = QHBoxLayout(busy)
        blay.setContentsMargins(0, 0, 0, 0)
        blay.setSpacing(10)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)          # indeterminado: "está trabalhando"
        self._bar.setTextVisible(False)
        self._bar.setFixedSize(90, 6)
        self._bar.setStyleSheet(f"""
            QProgressBar {{ background:{theme.BG_ELEVATED}; border:none; border-radius:3px; }}
            QProgressBar::chunk {{ background:{theme.ACCENT}; border-radius:3px; }}
        """)
        blay.addWidget(self._bar, 0, Qt.AlignmentFlag.AlignVCenter)

        self._progress_lbl = QLabel("")
        self._progress_lbl.setStyleSheet(
            f"color:{theme.TEXT_PRIMARY}; font-size:12px; border:none; background:transparent;")
        blay.addWidget(self._progress_lbl)

        self._btn_cancel = QPushButton(" Cancelar")
        self._btn_cancel.setIcon(icon("x", theme.TEXT_PRIMARY, 13))
        self._btn_cancel.setFixedHeight(32)
        self._btn_cancel.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {theme.TEXT_PRIMARY};
                border: 1px solid {theme.BORDER_STRONG}; border-radius: 6px;
                padding: 0 12px; font-size: 12px;
            }}
            QPushButton:hover {{ background: {theme.BG_ELEVATED}; }}
            QPushButton:disabled {{ color: {theme.TEXT_FAINT}; }}
        """)
        self._btn_cancel.clicked.connect(self.cancel_clicked)
        blay.addWidget(self._btn_cancel)
        self._pages.addWidget(busy)

    # ------------------------------------------------------------------
    def set_has_data(self, has_data: bool):
        """Limpar só faz sentido com algo importado."""
        self._btn_clear.setEnabled(has_data)

    def set_scanning(self, step: int, total: int, tool: str):
        self._progress_lbl.setText(f"Etapa {step} de {total} — {tool_label(tool)}")
        self._btn_cancel.setEnabled(True)
        self._btn_cancel.setText(" Cancelar")
        self._pages.setCurrentIndex(1)

    def set_cancelling(self):
        self._progress_lbl.setText("Cancelando...")
        self._btn_cancel.setEnabled(False)

    def set_idle(self):
        self._pages.setCurrentIndex(0)
