"""
ui/widgets/finding_detail.py
Painel de detalhe de um finding, mostrado ao lado da tabela de Findings.

Resolve dois achados da 2ª revisão de UI:
  - P0 #3: descrição e remediação vinham preenchidas pelos parsers (o Trivy,
    o ZAP e o Snyk trazem texto de correção pronto), mas nenhuma tela as
    exibia — a única forma de saber como corrigir era pedir para a IA.
  - P2 #16: status e vínculo com ativo, as duas ações centrais da triagem,
    só existiam no clique direito. Aqui ficam visíveis; o clique direito
    continua como atalho para ações em lote.
"""
from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QScrollArea, QWidget, QGridLayout,
)
from PyQt6.QtCore import Qt, pyqtSignal

from core.models import Vulnerability, Status
from core.asset import Asset
from core import threat_intel
from ui import theme
from ui.icons import icon
from ui.formatting import (
    STATUS_LABELS_PT, severity_label, full_location, plain_text,
)


def _section_title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{theme.TEXT_MUTED}; font-size:10px; font-weight:700; "
        f"letter-spacing:1.5px; border:none; background:transparent;"
    )
    return lbl


def _body_label(selectable: bool = True) -> QLabel:
    lbl = QLabel()
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.PlainText)
    lbl.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
    if selectable:
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    lbl.setStyleSheet(
        f"color:{theme.TEXT_PRIMARY}; font-size:12px; border:none; background:transparent;"
    )
    return lbl


def _pill(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        color:{color}; background:{theme.rgba(color, 0.14)};
        border:1px solid {theme.rgba(color, 0.4)}; border-radius:4px;
        padding:1px 8px; font-size:10px; font-weight:700;
    """)
    return lbl


def _tag(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        color:{theme.TEXT_MUTED}; background:{theme.BG_ELEVATED};
        border:none; border-radius:4px; padding:1px 8px; font-size:10px;
    """)
    return lbl


class FindingDetailPanel(QFrame):
    status_requested = pyqtSignal(object)   # Status
    asset_requested = pyqtSignal(object)    # asset_id (str) ou None
    explain_requested = pyqtSignal(object)  # Vulnerability
    close_requested = pyqtSignal()

    _COMBO_STYLE = f"""
        QComboBox {{
            background:{theme.BG_INPUT}; color:{theme.TEXT_PRIMARY};
            border:1px solid {theme.BORDER}; border-radius:6px;
            padding:4px 10px; font-size:12px; min-height:22px;
        }}
        QComboBox::drop-down {{ border:none; }}
        QComboBox QAbstractItemView {{
            background:{theme.BG_ELEVATED}; color:{theme.TEXT_PRIMARY};
            selection-background-color:{theme.ACCENT};
        }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._vuln: Vulnerability | None = None
        self._assets: list[Asset] = []

        self.setObjectName("findingDetail")
        self.setStyleSheet(
            f"#findingDetail {{ background:{theme.BG_SURFACE}; "
            f"border:1px solid {theme.BORDER}; border-radius:10px; }}"
        )
        self.setMinimumWidth(320)
        self.setMaximumWidth(480)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background:transparent; border:none; }")
        outer.addWidget(scroll)

        content = QWidget()
        content.setObjectName("findingDetailContent")
        content.setStyleSheet("#findingDetailContent { background:transparent; }")
        scroll.setWidget(content)

        lay = QVBoxLayout(content)
        lay.setContentsMargins(16, 14, 16, 16)
        lay.setSpacing(10)

        # ── Topo: pílulas + fechar ─────────────────────────────────────────
        top = QHBoxLayout()
        top.setSpacing(6)
        self._pills_box = QHBoxLayout()
        self._pills_box.setSpacing(6)
        top.addLayout(self._pills_box)
        top.addStretch()
        close_btn = QPushButton()
        close_btn.setIcon(icon("x", theme.TEXT_MUTED, 14))
        close_btn.setFixedSize(24, 24)
        close_btn.setToolTip("Fechar detalhe")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet(f"""
            QPushButton {{ background:transparent; border:none; border-radius:4px; }}
            QPushButton:hover {{ background:{theme.BG_ELEVATED}; }}
        """)
        close_btn.clicked.connect(self.close_requested)
        top.addWidget(close_btn)
        lay.addLayout(top)

        # ── Título e ID da regra ───────────────────────────────────────────
        self._title = QLabel()
        self._title.setWordWrap(True)
        self._title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._title.setStyleSheet(
            f"color:{theme.TEXT_PRIMARY}; font-size:14px; font-weight:700; "
            f"border:none; background:transparent;"
        )
        lay.addWidget(self._title)

        self._rule = QLabel()
        self._rule.setWordWrap(True)
        self._rule.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._rule.setStyleSheet(
            f"color:{theme.TEXT_FAINT}; font-size:10.5px; font-family:monospace; "
            f"border:none; background:transparent;"
        )
        lay.addWidget(self._rule)

        # ── Metadados ──────────────────────────────────────────────────────
        meta = QGridLayout()
        meta.setHorizontalSpacing(12)
        meta.setVerticalSpacing(6)
        meta.setColumnStretch(1, 1)
        self._meta_values: dict[str, QLabel] = {}
        self._meta_keys: dict[str, QLabel] = {}
        for row, (key, label) in enumerate([("loc", "Local"), ("cve", "CVE"), ("cvss", "CVSS"),
                                            ("kev", "CISA KEV"), ("epss", "EPSS")]):
            k = QLabel(label)
            k.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px; border:none; background:transparent;")
            k.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            v = _body_label()
            v.setStyleSheet(
                f"color:{theme.TEXT_PRIMARY}; font-size:11px; font-family:monospace; "
                f"border:none; background:transparent;"
            )
            meta.addWidget(k, row, 0)
            meta.addWidget(v, row, 1)
            self._meta_keys[key] = k
            self._meta_values[key] = v
        lay.addLayout(meta)

        lay.addWidget(self._divider())

        # ── Triagem: status e ativo ────────────────────────────────────────
        lay.addWidget(_section_title("TRIAGEM"))
        triage = QGridLayout()
        triage.setHorizontalSpacing(12)
        triage.setVerticalSpacing(8)
        triage.setColumnStretch(1, 1)

        lbl_status = QLabel("Status")
        lbl_status.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px; border:none; background:transparent;")
        self._status_combo = QComboBox()
        self._status_combo.setStyleSheet(self._COMBO_STYLE)
        # Guarda o valor em texto ("open", "fixed"...) e não o enum Status:
        # Status herda de str, e o PyQt pode devolver/comparar esse dado ora
        # como str, ora como objeto Python — findData() podia não achar o
        # item e o combo ficava sempre em "Aberta". Texto puro compara igual
        # em qualquer caso; a conversão de volta é feita em _on_status_changed.
        # (É o mesmo padrão que o filtro de status da aba Findings já usa.)
        for status in Status:
            self._status_combo.addItem(STATUS_LABELS_PT[status], status.value)
        self._status_combo.currentIndexChanged.connect(self._on_status_changed)
        triage.addWidget(lbl_status, 0, 0)
        triage.addWidget(self._status_combo, 0, 1)

        lbl_asset = QLabel("Ativo")
        lbl_asset.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px; border:none; background:transparent;")
        self._asset_combo = QComboBox()
        self._asset_combo.setStyleSheet(self._COMBO_STYLE)
        self._asset_combo.currentIndexChanged.connect(self._on_asset_changed)
        triage.addWidget(lbl_asset, 1, 0)
        triage.addWidget(self._asset_combo, 1, 1)
        lay.addLayout(triage)

        self._asset_hint = QLabel("Nenhum ativo cadastrado — crie um na aba Ativos para vincular.")
        self._asset_hint.setWordWrap(True)
        self._asset_hint.setStyleSheet(f"color:{theme.TEXT_FAINT}; font-size:10.5px; border:none; background:transparent;")
        lay.addWidget(self._asset_hint)

        lay.addWidget(self._divider())

        # ── Descrição e remediação ────────────────────────────────────────
        lay.addWidget(_section_title("DESCRIÇÃO"))
        self._description = _body_label()
        lay.addWidget(self._description)

        lay.addSpacing(4)
        lay.addWidget(_section_title("COMO CORRIGIR"))
        self._remediation = _body_label()
        lay.addWidget(self._remediation)

        lay.addSpacing(6)
        self._explain_btn = QPushButton(" Explicar com IA")
        self._explain_btn.setIcon(icon("chat", theme.ACCENT, 14))
        self._explain_btn.setFixedHeight(32)
        self._explain_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._explain_btn.setStyleSheet(theme.button_style(
            theme.ACCENT, theme.ACCENT_HOVER, theme.ACCENT_PRESSED, outline=True))
        self._explain_btn.clicked.connect(lambda: self._vuln and self.explain_requested.emit(self._vuln))
        lay.addWidget(self._explain_btn)

        lay.addStretch()

    # ------------------------------------------------------------------
    @staticmethod
    def _divider() -> QFrame:
        d = QFrame()
        d.setFixedHeight(1)
        d.setStyleSheet(f"background:{theme.BORDER}; border:none;")
        return d

    def set_assets(self, assets: list[Asset]):
        self._assets = assets
        self._reload_asset_combo()

    def current(self) -> Vulnerability | None:
        return self._vuln

    def show_vulnerability(self, v: Vulnerability):
        self._vuln = v

        # pílulas
        while self._pills_box.count():
            w = self._pills_box.takeAt(0).widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        color = theme.SEVERITY_COLORS.get(v.severity.value, theme.TEXT_MUTED)
        self._pills_box.addWidget(_pill(severity_label(v).upper(), color))
        intel = threat_intel.lookup(v.cve_id)   # None quando não é CVE
        if intel and intel.in_kev:
            # Primeira coisa que o olho vê depois da severidade: exploração
            # ativa confirmada muda a urgência mais que qualquer outro campo.
            kev_pill = _pill("CISA KEV", theme.DANGER)
            kev_pill.setToolTip("Exploração ativa confirmada — catálogo CISA Known Exploited Vulnerabilities")
            self._pills_box.addWidget(kev_pill)
        self._pills_box.addWidget(_tag(v.tool))
        self._pills_box.addWidget(_tag(v.scan_type.value))

        self._title.setText(v.title)
        show_rule = bool(v.rule_id) and v.rule_id != v.title
        self._rule.setText(f"regra: {v.rule_id}" if show_rule else "")
        self._rule.setVisible(show_rule)

        loc = full_location(v)
        self._set_meta("loc", loc)
        self._set_meta("cve", v.cve_id or "")
        self._set_meta("cvss", f"{v.cvss_score:.1f}" if v.cvss_score is not None else "")
        self._set_meta("kev", self._kev_text(intel))
        self._set_meta("epss", self._epss_text(intel))

        self._status_combo.blockSignals(True)
        idx = self._status_combo.findData(v.status.value)
        self._status_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._status_combo.blockSignals(False)
        self._reload_asset_combo()

        desc = plain_text(v.description)
        self._set_body(self._description, desc,
                       "A ferramenta não trouxe descrição para este finding.")
        rem = plain_text(v.remediation)
        self._set_body(self._remediation, rem,
                       "A ferramenta não trouxe orientação de correção. "
                       "Use \"Explicar com IA\" abaixo para gerar uma.")

    # ------------------------------------------------------------------
    @staticmethod
    def _kev_text(intel) -> str:
        """Só para CVEs. Distingue "não está no catálogo" (informação útil)
        de "catálogo nunca baixado" (sem informação)."""
        if intel is None:
            return ""
        if intel.in_kev:
            parts = ["Exploração ativa confirmada"]
            if intel.kev_date_added:
                parts.append(f"no catálogo desde {intel.kev_date_added}")
            if intel.kev_ransomware:
                parts.append("usada em ransomware")
            return " · ".join(parts)
        if threat_intel.status()["kev_updated_at"]:
            return "Não consta no catálogo"
        return "Catálogo ainda não baixado (Configurações → Atualizar agora)"

    @staticmethod
    def _epss_text(intel) -> str:
        if intel is None or intel.epss is None:
            return ""
        txt = f"{intel.epss * 100:.1f}% de chance de exploração em 30 dias"
        if intel.epss_percentile is not None:
            txt += f" (percentil {intel.epss_percentile * 100:.0f})"
        return txt

    def _set_meta(self, key: str, value: str):
        self._meta_values[key].setText(value)
        self._meta_values[key].setVisible(bool(value))
        self._meta_keys[key].setVisible(bool(value))

    @staticmethod
    def _set_body(label: QLabel, text: str, fallback: str):
        if text:
            label.setText(text)
            label.setStyleSheet(
                f"color:{theme.TEXT_PRIMARY}; font-size:12px; border:none; background:transparent;")
        else:
            label.setText(fallback)
            label.setStyleSheet(
                f"color:{theme.TEXT_FAINT}; font-size:12px; font-style:italic; "
                f"border:none; background:transparent;")

    def _reload_asset_combo(self):
        self._asset_combo.blockSignals(True)
        self._asset_combo.clear()
        self._asset_combo.addItem("— sem ativo —", None)
        for a in self._assets:
            self._asset_combo.addItem(a.label, a.id)
        current = self._vuln.asset_id if self._vuln else None
        idx = self._asset_combo.findData(current)
        self._asset_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._asset_combo.setEnabled(bool(self._assets))
        self._asset_combo.blockSignals(False)
        self._asset_hint.setVisible(not self._assets)

    def _on_status_changed(self, _idx: int):
        value = self._status_combo.currentData()
        if value is None:
            return
        # getattr cobre o caso de o PyQt devolver o próprio enum; str(enum)
        # daria "Status.OPEN" em várias versões do Python, não "open".
        status = Status(getattr(value, "value", value))
        if self._vuln is not None and status != self._vuln.status:
            self.status_requested.emit(status)

    def _on_asset_changed(self, _idx: int):
        asset_id = self._asset_combo.currentData()
        if self._vuln is not None and asset_id != self._vuln.asset_id:
            self.asset_requested.emit(asset_id)
