# SentinelAI — ASPM (Application Security Posture Management)
# Copyright (C) 2026 Guilherme Gonçalves Sampaio Santos, Lucas Rufato Todesco,
# Marcos Vinícius Anastacio Miurin, Vinicius de Souza Christovam
#
# SPDX-License-Identifier: GPL-3.0-only
# Licenciado sob a GNU General Public License v3 — veja o arquivo LICENSE.md.

"""
ui/dialogs/settings_dialog.py
Diálogo de Configurações — Groq API Key (P2 #15 da revisão de UX: antes
esse campo morava dentro da aba de IA, no meio da tela de trabalho, e não
era salvo em lugar nenhum) e status/atualização manual da inteligência de
ameaças (CISA KEV + EPSS, ver core/threat_intel.py).
"""
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget,
)

from core import settings as settings_store
from core import threat_intel
from ui import theme
from ui.icons import icon
from ui.formatting import datetime_br


class SettingsDialog(QDialog):
    def __init__(self, provider, parent=None, intel_refresh=None):
        super().__init__(parent)
        self.provider = provider
        self._intel_refresh = intel_refresh
        self.setWindowTitle("Configurações")
        self.setFixedWidth(420)
        self.setStyleSheet(f"QDialog {{ background:{theme.BG_APP}; }}")
        self._build_ui()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)

        title = QLabel("Provedor de IA")
        title.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:14px; font-weight:bold;")
        lay.addWidget(title)

        self.status_icon = QLabel()
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-size:11px; font-family:monospace;")
        status_row = QHBoxLayout()
        status_row.addWidget(self.status_icon)
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        lay.addLayout(status_row)
        self._refresh_status()

        info = QLabel(
            "A SentinelAI usa Ollama local automaticamente quando disponível. "
            "Sem Ollama, configure uma Groq API Key abaixo (gratuita em "
            "console.groq.com)."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px;")
        lay.addWidget(info)

        lbl = QLabel("Groq API Key:")
        lbl.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:12px;")
        lay.addWidget(lbl)

        current = settings_store.load()
        self.key_input = QLineEdit(current.groq_api_key)
        self.key_input.setPlaceholderText("gsk_...")
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setStyleSheet(f"""
            QLineEdit {{
                background:{theme.BG_INPUT}; border:1px solid {theme.BORDER}; border-radius:6px;
                color:{theme.TEXT_PRIMARY}; padding:6px 10px; font-size:12px;
            }}
        """)
        lay.addWidget(self.key_input)

        lay.addSpacing(8)
        lay.addWidget(self._build_intel_section())

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.setFixedHeight(32)
        btn_cancel.setStyleSheet(f"""
            QPushButton {{ background:transparent; color:{theme.TEXT_MUTED};
                border:1px solid {theme.BORDER}; border-radius:6px; padding:0 14px; font-size:12px; }}
            QPushButton:hover {{ color:{theme.TEXT_PRIMARY}; border-color:{theme.BORDER_STRONG}; }}
        """)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_save = QPushButton(" Salvar")
        btn_save.setIcon(icon("save", theme.ACCENT_ON, 14))
        btn_save.setFixedHeight(32)
        btn_save.setStyleSheet(theme.button_style(theme.ACCENT, theme.ACCENT_HOVER, theme.ACCENT_PRESSED))
        btn_save.clicked.connect(self._save)
        btn_row.addWidget(btn_save)

        lay.addLayout(btn_row)

    def _build_intel_section(self) -> QWidget:
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        title = QLabel("Inteligência de ameaças")
        title.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:14px; font-weight:bold;")
        v.addWidget(title)

        info = QLabel(
            "CISA KEV (exploração ativa confirmada) e FIRST EPSS (probabilidade de "
            "exploração em 30 dias) reforçam a priorização de findings com CVE. "
            "Atualiza sozinho a cada 24h; só IDs de CVE saem da máquina."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px;")
        v.addWidget(info)

        st = threat_intel.status()
        when = datetime_br(st["kev_updated_at"])
        if when:
            txt = (f"KEV: {st['kev_count']:,} CVEs no catálogo · atualizado em {when}\n"
                   f"EPSS em cache: {st['epss_count']} CVE(s)").replace(",", ".")
        else:
            txt = "Ainda não baixado — a priorização usa só o score heurístico."
        self.intel_status = QLabel(txt)
        self.intel_status.setWordWrap(True)
        self.intel_status.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:11px; font-family:monospace;")
        v.addWidget(self.intel_status)

        if self._intel_refresh is not None:
            row = QHBoxLayout()
            self.btn_intel = QPushButton(" Atualizar agora")
            self.btn_intel.setIcon(icon("upload", theme.ACCENT, 13))
            self.btn_intel.setFixedHeight(28)
            self.btn_intel.setStyleSheet(theme.button_style(
                theme.ACCENT, theme.ACCENT_HOVER, theme.ACCENT_PRESSED, outline=True))
            self.btn_intel.clicked.connect(self._on_intel_refresh)
            row.addWidget(self.btn_intel)
            row.addStretch()
            v.addLayout(row)
        return box

    def _on_intel_refresh(self):
        self._intel_refresh()
        self.btn_intel.setEnabled(False)
        self.intel_status.setText(
            "Atualização iniciada em segundo plano — o resultado aparece na barra de status.")

    def _refresh_status(self):
        if self.provider.available:
            self.status_icon.setPixmap(icon("check", theme.SUCCESS, 14).pixmap(14, 14))
            self.status_label.setText(f"IA ativa — backend: {self.provider.backend_name.upper()}")
            self.status_label.setStyleSheet(f"color:{theme.SUCCESS}; font-size:11px; font-family:monospace;")
        else:
            self.status_icon.setPixmap(icon("x", theme.DANGER, 14).pixmap(14, 14))
            self.status_label.setText("IA indisponível — configure Ollama ou uma Groq API Key")
            self.status_label.setStyleSheet(f"color:{theme.DANGER}; font-size:11px; font-family:monospace;")

    def _save(self):
        key = self.key_input.text().strip()
        settings_store.save(settings_store.AppSettings(groq_api_key=key))
        if key:
            self.provider.set_groq_key(key)
        self._refresh_status()
        self.accept()
