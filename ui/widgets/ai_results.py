"""
ui/widgets/ai_results.py
Widgets para renderizar as saídas de IA (Priorização e Padrões & Anomalias)
como cards estruturados — em vez de despejar o markdown bruto do LLM num
QTextEdit. Mantém a mesma interface mínima (setPlainText) usada pelo runner
genérico de threads em ai_view.py, então funciona como substituto direto de
QTextEdit nesses dois lugares específicos.
"""
import re

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea,
    QSizePolicy, QPushButton,
)
from PyQt6.QtCore import Qt

from ui import theme
from ui.formatting import short_location, full_location, date_br
from core import threat_intel


_MD_SYMBOLS = re.compile(r"[*_`#]+")


def _strip_markdown(text: str) -> str:
    """Remove os símbolos de markdown mais comuns (**, *, #, `) de um texto
    curto — usado no resumo de uma linha (ex.: primeira frase de um texto
    maior), onde não vale a pena renderizar rich text, só não mostrar os
    marcadores crus (P1 #4 da revisão de UI: o resumo cortava a primeira
    frase ANTES de tirar os marcadores, e sobrava algo como \"**1.\")."""
    return _MD_SYMBOLS.sub("", text).strip()


def _set_markdown_body(label: QLabel, text: str):
    """Configura um QLabel para renderizar o texto livre da IA como markdown
    (negrito, listas, etc.) em vez de texto puro — antes os asteriscos e
    marcadores apareciam literais na tela, porque QLabel mostra markdown cru
    como texto simples por padrão (P1 #4 da revisão de UI). A aba "Explicar
    Vuln" já não tinha esse problema por usar QTextEdit.setMarkdown(); aqui o
    equivalente para QLabel é Qt.TextFormat.MarkdownText."""
    label.setTextFormat(Qt.TextFormat.MarkdownText)
    label.setText(text)


def _clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)  # remove visualmente na hora, não só agenda a exclusão
            w.deleteLater()


def severity_pill(severity_value: str) -> QLabel:
    color = theme.SEVERITY_COLORS.get(severity_value, theme.TEXT_MUTED)
    label = theme.SEVERITY_LABELS_PT.get(severity_value, severity_value.upper())
    lbl = QLabel(label)
    lbl.setStyleSheet(f"""
        color:{color}; background:{theme.rgba(color, 0.14)};
        border:1px solid {theme.rgba(color, 0.4)}; border-radius:4px;
        padding:1px 8px; font-size:10px; font-weight:700; letter-spacing:0.5px;
    """)
    return lbl


def kev_pill() -> QLabel:
    """Marca de exploração ativa confirmada (CISA KEV) — ver core/threat_intel.py."""
    lbl = QLabel("CISA KEV")
    lbl.setToolTip("Exploração ativa confirmada — catálogo CISA Known Exploited Vulnerabilities")
    lbl.setStyleSheet(f"""
        color:{theme.DANGER}; background:{theme.rgba(theme.DANGER, 0.14)};
        border:1px solid {theme.rgba(theme.DANGER, 0.4)}; border-radius:4px;
        padding:1px 8px; font-size:10px; font-weight:700; letter-spacing:0.5px;
    """)
    return lbl


def ransomware_pill() -> QLabel:
    """Marca extra dentro do KEV: a CISA registra quando o CVE é usado em
    campanhas de ransomware conhecidas (knownRansomwareCampaignUse) — sinal
    de urgência ainda maior que "só" exploração ativa confirmada."""
    lbl = QLabel("RANSOMWARE")
    lbl.setToolTip("CISA KEV: usado em campanhas de ransomware conhecidas")
    lbl.setStyleSheet(f"""
        color:#ffffff; background:{theme.DANGER};
        border:1px solid {theme.DANGER}; border-radius:4px;
        padding:1px 8px; font-size:10px; font-weight:700; letter-spacing:0.5px;
    """)
    return lbl


def tag_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        color:{theme.TEXT_MUTED}; background:{theme.BG_ELEVATED};
        border-radius:4px; padding:1px 8px; font-size:10px;
    """)
    return lbl


_LEADING_LIST_MARKER = re.compile(r"^\s*(?:\d{1,2}[.)]|[-•])\s+")


def _first_sentence(text: str, max_chars: int = 140) -> str:
    """Primeira frase de um texto longo, cortada com reticências se ainda
    assim passar do limite — usado como resumo quando não há um resumo
    dedicado (ex.: a narrativa livre do LLM em Padrões & Anomalias)."""
    text = text.strip()
    # Quando o texto abre com um marcador de lista ("1. ", "- "), ignora esse
    # marcador antes de procurar o fim da frase — senão o "1." de uma lista
    # numerada já contava como frase inteira e o resumo virava só "1."
    # (P1 #4 da revisão de UI).
    text = _LEADING_LIST_MARKER.sub("", text, count=1)
    cut = text.find(". ")
    if 0 < cut < max_chars:
        return text[:cut + 1]  # frase real, já termina em "." — não mexe
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "…"


def _add_expandable(lay: QVBoxLayout, detail_widget: QWidget,
                     summary_widget: QWidget | None = None,
                     toggle_text: str = "ver detalhes"):
    """Padrão 'resumo sempre visível + texto completo atrás de um toggle'.
    summary_widget (opcional) fica sempre visível; detail_widget começa
    escondido e é revelado ao clicar no botão de toggle."""
    if summary_widget is not None:
        lay.addWidget(summary_widget)

    toggle = QPushButton(f"▸ {toggle_text}")
    toggle.setFlat(True)
    toggle.setCursor(Qt.CursorShape.PointingHandCursor)
    toggle.setStyleSheet(f"""
        QPushButton {{ color:{theme.ACCENT}; background:transparent; border:none;
            text-align:left; font-size:10.5px; padding:2px 0; }}
        QPushButton:hover {{ color:{theme.ACCENT_HOVER}; text-decoration:underline; }}
    """)
    detail_widget.setVisible(False)

    def _on_toggle():
        showing = not detail_widget.isVisible()
        detail_widget.setVisible(showing)
        toggle.setText(f"▾ ocultar {toggle_text}" if showing else f"▸ {toggle_text}")

    toggle.clicked.connect(_on_toggle)
    lay.addWidget(toggle)
    lay.addWidget(detail_widget)


class PriorityCard(QFrame):
    """Um item na lista de priorização: rank, severidade, score e justificativa."""

    def __init__(self, rank: int, pv, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.BG_SURFACE}; border:1px solid {theme.BORDER};
                border-radius:10px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)

        rank_lbl = QLabel(f"#{rank}")
        rank_lbl.setFixedWidth(28)
        rank_lbl.setStyleSheet(f"color:{theme.TEXT_FAINT}; font-size:14px; font-weight:700; border:none; background:transparent;")
        top.addWidget(rank_lbl)

        top.addWidget(severity_pill(pv.vuln.severity.value))

        title = QLabel(pv.vuln.title)
        title.setWordWrap(True)
        title.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:13px; font-weight:600; border:none; background:transparent;")
        top.addWidget(title, 1)

        score = QLabel(f"{pv.final_score:.1f}")
        score.setStyleSheet(f"color:{theme.ACCENT}; font-size:15px; font-weight:700; font-family:monospace; border:none; background:transparent;")
        top.addWidget(score)
        lay.addLayout(top)

        tags = QHBoxLayout()
        tags.setSpacing(6)
        intel = threat_intel.lookup(pv.vuln.cve_id)
        if intel and intel.in_kev:
            tags.addWidget(kev_pill())
        tags.addWidget(tag_label(pv.vuln.tool.upper()))
        tags.addWidget(tag_label(pv.vuln.scan_type.value))
        if pv.ai_rank:
            tags.addWidget(tag_label(f"IA rank #{pv.ai_rank}"))
        # arquivo:linha em vez do caminho absoluto inteiro (P2 #13) — findings
        # da mesma regra em arquivos diferentes ficavam indistinguíveis, e o
        # caminho completo estourava a largura do card. Completo no tooltip.
        loc = short_location(pv.vuln)
        if loc != "—":
            loc_tag = tag_label(loc)
            loc_tag.setToolTip(full_location(pv.vuln))
            tags.addWidget(loc_tag)
        tags.addStretch()
        lay.addLayout(tags)

        if getattr(pv, "score_breakdown", None):
            breakdown_txt = "  ·  ".join(
                f"{c.label}: +{c.value:g}" for c in pv.score_breakdown
            )
            breakdown_lbl = QLabel(breakdown_txt)
            breakdown_lbl.setWordWrap(True)
            breakdown_lbl.setStyleSheet(
                f"color:{theme.TEXT_FAINT}; font-size:10px; font-family:monospace; "
                f"border:none; background:transparent;"
            )
            lay.addWidget(breakdown_lbl)

        # Quando a IA participou, o número do card é 70% técnico + 30% IA —
        # sem esta linha ele não batia com a soma das parcelas logo acima,
        # o que contradiz a proposta de "score transparente".
        ai_weight = getattr(pv, "ai_weight", None)
        if ai_weight is not None:
            if pv.ai_rank is not None:
                ai_part = f"posição #{pv.ai_rank} dada pela IA → {ai_weight:.0f}"
            elif ai_weight > 0:
                ai_part = f"IA não retornou este item, mantida a posição técnica → {ai_weight:.0f}"
            else:
                ai_part = "fora do top 10 avaliado pela IA → 0"
            blend_lbl = QLabel(
                f"Score final {pv.final_score:g} = 70% × {pv.pre_score:g} (técnico) + 30% × IA ({ai_part})"
            )
            blend_lbl.setWordWrap(True)
            blend_lbl.setStyleSheet(
                f"color:{theme.TEXT_FAINT}; font-size:10px; font-family:monospace; "
                f"border:none; background:transparent;"
            )
            lay.addWidget(blend_lbl)

        reason_summary = getattr(pv, "ai_reason_summary", "") or pv.ai_reason
        summary = QLabel(_strip_markdown(reason_summary))
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:12px; font-weight:600; border:none; background:transparent;")

        detail = QLabel()
        _set_markdown_body(detail, pv.ai_reason)
        detail.setWordWrap(True)
        detail.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:12px; border:none; background:transparent;")

        _add_expandable(lay, detail, summary_widget=summary, toggle_text="ver justificativa completa")


class AttackPathCard(QFrame):
    """Uma cadeia de ataque: exposição → vulnerabilidade → impacto, com a
    explicação de por que os elos se conectam."""

    _CHAIN_COLORS = {
        "critical": theme.SEV_CRITICAL,
        "high":     theme.SEV_HIGH,
        "medium":   theme.SEV_MEDIUM,
    }
    _CHAIN_LABELS = {
        "critical": "CAMINHO CRÍTICO",
        "high":     "CAMINHO DE ALTO RISCO",
        "medium":   "CAMINHO DE RISCO MODERADO",
    }

    def __init__(self, path, parent=None):
        super().__init__(parent)
        accent = self._CHAIN_COLORS.get(path.severity, theme.TEXT_MUTED)
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.BG_SURFACE}; border:1px solid {theme.rgba(accent, 0.45)};
                border-radius:10px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        head = QLabel(self._CHAIN_LABELS.get(path.severity, "CAMINHO DE RISCO"))
        head.setStyleSheet(
            f"color:{accent}; font-size:11px; font-weight:700; letter-spacing:0.6px; "
            f"border:none; background:transparent;"
        )
        lay.addWidget(head)

        # A cadeia em si: três elos separados por setas
        chain = QHBoxLayout()
        chain.setSpacing(6)
        for i, (emoji, text) in enumerate([
            ("🌐", path.exposure),
            ("🔓", path.vulnerability),
            ("💥", path.impact),
        ]):
            if i > 0:
                arrow = QLabel("→")
                arrow.setStyleSheet(f"color:{accent}; font-size:14px; font-weight:700; border:none; background:transparent;")
                arrow.setFixedWidth(16)
                chain.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)

            link = QLabel(f"{emoji}  {text}")
            link.setWordWrap(True)
            link.setStyleSheet(f"""
                color:{theme.TEXT_PRIMARY}; background:{theme.BG_ELEVATED};
                border:1px solid {theme.BORDER}; border-radius:6px;
                padding:6px 8px; font-size:11px;
            """)
            link.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            chain.addWidget(link, 1)
        lay.addLayout(chain)

        if path.asset_name:
            tags = QHBoxLayout()
            tags.setSpacing(6)
            tags.addWidget(tag_label(f"Ativo: {path.asset_name}"))
            tags.addWidget(tag_label(f"{len(path.vulns)} achado(s)"))
            tags.addStretch()
            lay.addLayout(tags)

        why = QLabel(path.explanation)
        why.setWordWrap(True)
        why.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11.5px; border:none; background:transparent;")
        _add_expandable(lay, why, toggle_text="por que isso é um caminho de risco")


class InfoBanner(QFrame):
    """Faixa de contexto/aviso no topo de um resultado (substitui o '> blockquote' do markdown)."""

    def __init__(self, text: str, accent: str = None, parent=None):
        super().__init__(parent)
        accent = accent or theme.ACCENT
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.rgba(accent, 0.08)};
                border:1px solid {theme.rgba(accent, 0.35)}; border-radius:8px; }}
        """)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:11px; border:none; background:transparent;")
        lay.addWidget(lbl)


class SectionCard(QFrame):
    """Card com título + lista de itens (usado em Padrões / Hotspots / Correlações)."""

    def __init__(self, title: str, items: list[str], accent: str = None, parent=None):
        super().__init__(parent)
        accent = accent or theme.AI_ACCENT
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.BG_SURFACE}; border:1px solid {theme.BORDER};
                border-radius:10px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        head = QLabel(title)
        head.setStyleSheet(f"color:{accent}; font-size:12px; font-weight:700; letter-spacing:0.5px; border:none; background:transparent;")
        lay.addWidget(head)

        for it in items:
            row = QHBoxLayout()
            row.setSpacing(8)
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{accent}; font-size:8px; border:none; background:transparent;")
            dot.setFixedWidth(12)
            row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
            txt = QLabel(it)
            txt.setWordWrap(True)
            txt.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:12px; border:none; background:transparent;")
            row.addWidget(txt, 1)
            lay.addLayout(row)


class AIAnalysisCard(QFrame):
    """Card específico para a narrativa livre do LLM em Padrões & Anomalias —
    texto sem estrutura prévia (ao contrário das listas de Padrões/Hotspots/
    Correlações, que já são curtas por natureza), então recebe o mesmo
    tratamento de resumo + 'ver detalhes' do PriorityCard."""

    def __init__(self, text: str, accent: str = None, parent=None):
        super().__init__(parent)
        accent = accent or theme.ACCENT
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.BG_SURFACE}; border:1px solid {theme.BORDER};
                border-radius:10px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        head = QLabel("ANÁLISE DA IA")
        head.setStyleSheet(f"color:{accent}; font-size:12px; font-weight:700; letter-spacing:0.5px; border:none; background:transparent;")
        lay.addWidget(head)

        # Tira os marcadores ANTES de extrair a primeira frase — extrair
        # primeiro (como era antes) podia deixar o resumo começando com algo
        # como "**1." quando o texto da IA abre com uma lista numerada.
        summary = QLabel(_first_sentence(_strip_markdown(text)))
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:12px; font-weight:600; border:none; background:transparent;")

        detail = QLabel()
        _set_markdown_body(detail, text)
        detail.setWordWrap(True)
        detail.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:12px; border:none; background:transparent;")

        _add_expandable(lay, detail, summary_widget=summary, toggle_text="ver análise completa")


class KevCard(QFrame):
    """Um finding com CVE confirmado no catálogo CISA KEV — visibilidade
    dedicada pedida pelo time (antes o KEV só influenciava o score final da
    Priorização IA, sem uma lista própria pra conferir rápido "o que já está
    sendo explorado de verdade, hoje")."""

    def __init__(self, vuln, intel, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.BG_SURFACE}; border:1px solid {theme.rgba(theme.DANGER, 0.4)};
                border-radius:10px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(severity_pill(vuln.severity.value))
        top.addWidget(kev_pill())
        if intel.kev_ransomware:
            top.addWidget(ransomware_pill())
        title = QLabel(vuln.title)
        title.setWordWrap(True)
        title.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:13px; font-weight:600; border:none; background:transparent;")
        top.addWidget(title, 1)
        cve_lbl = QLabel(intel.cve)
        cve_lbl.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px; font-family:monospace; border:none; background:transparent;")
        top.addWidget(cve_lbl)
        lay.addLayout(top)

        tags = QHBoxLayout()
        tags.setSpacing(6)
        tags.addWidget(tag_label(vuln.tool.upper()))
        loc = short_location(vuln)
        if loc != "—":
            loc_tag = tag_label(loc)
            loc_tag.setToolTip(full_location(vuln))
            tags.addWidget(loc_tag)
        if intel.kev_date_added:
            tags.addWidget(tag_label(f"no catálogo desde {date_br(intel.kev_date_added)}"))
        if intel.kev_due_date:
            # Prazo de correção do próprio catálogo CISA KEV (usado como
            # referência de urgência mesmo por quem não é órgão federal dos
            # EUA — é a data que a própria CISA considera razoável para
            # corrigir algo já sendo explorado).
            due = tag_label(f"prazo CISA: {date_br(intel.kev_due_date)}")
            due.setStyleSheet(f"""
                color:{theme.DANGER}; background:{theme.rgba(theme.DANGER, 0.14)};
                border-radius:4px; padding:1px 8px; font-size:10px; font-weight:600;
            """)
            tags.addWidget(due)
        tags.addStretch()
        lay.addLayout(tags)


class EpssCard(QFrame):
    """Um finding com CVE e score EPSS — lista própria ordenada por
    probabilidade de exploração, separada da priorização final (que mistura
    EPSS com severidade, tipo de scan e contexto de negócio)."""

    def __init__(self, vuln, intel, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{ background:{theme.BG_SURFACE}; border:1px solid {theme.BORDER};
                border-radius:10px; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(severity_pill(vuln.severity.value))
        if intel.in_kev:
            top.addWidget(kev_pill())
        title = QLabel(vuln.title)
        title.setWordWrap(True)
        title.setStyleSheet(f"color:{theme.TEXT_PRIMARY}; font-size:13px; font-weight:600; border:none; background:transparent;")
        top.addWidget(title, 1)

        pct = intel.epss * 100
        color = theme.DANGER if pct >= 50 else (theme.WARNING if pct >= 10 else theme.ACCENT)
        epss_lbl = QLabel(f"{pct:.1f}%")
        epss_lbl.setStyleSheet(f"color:{color}; font-size:16px; font-weight:700; font-family:monospace; border:none; background:transparent;")
        top.addWidget(epss_lbl)
        lay.addLayout(top)

        tags = QHBoxLayout()
        tags.setSpacing(6)
        tags.addWidget(tag_label(intel.cve))
        tags.addWidget(tag_label(vuln.tool.upper()))
        loc = short_location(vuln)
        if loc != "—":
            loc_tag = tag_label(loc)
            loc_tag.setToolTip(full_location(vuln))
            tags.addWidget(loc_tag)
        if intel.epss_percentile is not None:
            tags.addWidget(tag_label(f"percentil {intel.epss_percentile * 100:.0f}"))
        tags.addStretch()
        lay.addLayout(tags)


class ResultsPanel(QScrollArea):
    """Container rolável para os cards de resultado de IA. Expõe setPlainText()
    para continuar compatível com o runner genérico de threads (loading/erro)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setStyleSheet(f"""
            QScrollArea {{ background:{theme.BG_APP}; border:1px solid {theme.BORDER}; border-radius:10px; }}
        """)
        self._content = QWidget()
        self._content.setStyleSheet(f"background:{theme.BG_APP};")
        self._layout = QVBoxLayout(self._content)
        self._layout.setContentsMargins(12, 12, 12, 12)
        self._layout.setSpacing(10)
        self._layout.addStretch()
        self.setWidget(self._content)
        self.setPlainText("A resposta da IA aparecerá aqui...")

    def _reset(self):
        _clear_layout(self._layout)

    def _add(self, widget: QWidget):
        # Insere antes do stretch final (mantido via addStretch a cada reset)
        self._layout.addWidget(widget)

    def setPlainText(self, text: str):
        """Usado pelo runner de threads para mostrar estado de carregamento/erro."""
        self._reset()
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lbl.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:12px; padding:4px;")
        self._add(lbl)
        self._layout.addStretch()

    def render_priority(self, result: list, ctx=None):
        self._reset()
        if ctx and ctx.preenchido:
            banner = InfoBanner(
                f"Contexto: {ctx.setor} | {ctx.porte} | "
                f"Disponibilidade {ctx.importancia_disponibilidade}/10 · "
                f"Confidencialidade {ctx.importancia_confidencialidade}/10 · "
                f"Integridade {ctx.importancia_integridade}/10",
                accent=theme.ACCENT,
            )
        else:
            banner = InfoBanner(
                "Contexto da empresa não configurado — priorização por critérios técnicos padrão. "
                "Configure em \"Contexto da Empresa\" para resultados personalizados.",
                accent=theme.WARNING,
            )
        self._add(banner)
        for i, pv in enumerate(result, 1):
            self._add(PriorityCard(i, pv))
        self._layout.addStretch()

    def render_kev(self, vulns: list) -> int:
        """Lista dedicada de findings com CVE no catálogo CISA KEV — mesma
        informação que já pesa no score da Priorização IA, mas visível sem
        precisar abrir cada card lá e sem depender de rodar a IA (é dado
        determinístico, vem do cache local). Ordenada pelo prazo de correção
        da própria CISA (kev_due_date) — mais urgente primeiro; sem prazo
        informado vai pro fim da lista. Retorna a contagem, para o rótulo
        da aba em ai_view.py."""
        self._reset()
        items = []
        for v in vulns:
            intel = threat_intel.lookup(v.cve_id)
            if intel and intel.in_kev:
                items.append((v, intel))
        items.sort(key=lambda pair: pair[1].kev_due_date or "9999-99-99")

        if not items:
            self._add(InfoBanner(
                "Nenhum finding aberto com CVE está no catálogo CISA KEV no momento — ou o "
                "catálogo ainda não foi baixado (Configurações → Inteligência de ameaças → "
                "Atualizar agora).",
                accent=theme.TEXT_MUTED,
            ))
        else:
            self._add(InfoBanner(
                f"{len(items)} finding(s) aberto(s) com exploração ativa CONFIRMADA (CISA KEV) — "
                "trate como prioridade de correção acima de qualquer outro sinal técnico, "
                "independente da severidade ou do score final.",
                accent=theme.DANGER,
            ))
            for v, intel in items:
                self._add(KevCard(v, intel))
        self._layout.addStretch()
        return len(items)

    def render_epss(self, vulns: list) -> int:
        """Lista dedicada de findings com CVE e score EPSS, ordenada da
        maior para a menor probabilidade de exploração nos próximos 30 dias.
        Mesma lógica de render_kev(): dado já em cache, não precisa de IA.
        Retorna a contagem, para o rótulo da aba em ai_view.py."""
        self._reset()
        items = []
        for v in vulns:
            intel = threat_intel.lookup(v.cve_id)
            if intel and intel.epss is not None:
                items.append((v, intel))
        items.sort(key=lambda pair: pair[1].epss, reverse=True)

        if not items:
            self._add(InfoBanner(
                "Nenhum finding aberto com CVE tem score EPSS em cache no momento — ou o "
                "catálogo ainda não foi baixado (Configurações → Inteligência de ameaças → "
                "Atualizar agora).",
                accent=theme.TEXT_MUTED,
            ))
        else:
            self._add(InfoBanner(
                f"{len(items)} finding(s) aberto(s) com CVE e score EPSS (FIRST.org) — "
                "probabilidade estimada de exploração nos próximos 30 dias, do mais para o "
                "menos provável.",
                accent=theme.ACCENT,
            ))
            for v, intel in items:
                self._add(EpssCard(v, intel))
        self._layout.addStretch()
        return len(items)

    def render_attack_paths(self, paths: list):
        self._reset()
        if not paths:
            self._add(InfoBanner(
                "Nenhum caminho de ataque identificado. As regras cruzam achados do mesmo módulo "
                "ou do mesmo ativo — vincule vulnerabilidades a ativos na aba Findings para "
                "habilitar as regras que dependem de contexto de exposição.",
                accent=theme.TEXT_MUTED,
            ))
            self._layout.addStretch()
            return

        self._add(InfoBanner(
            f"{len(paths)} caminho(s) identificado(s) por correlação determinística entre achados "
            "e contexto declarado dos ativos. Não são rotas de ataque validadas — são combinações "
            "que elevam o risco quando ocorrem juntas.",
            accent=theme.ACCENT,
        ))
        for p in paths:
            self._add(AttackPathCard(p))
        self._layout.addStretch()

    def render_anomaly(self, report):
        self._reset()
        any_content = False
        if report.patterns:
            self._add(SectionCard("PADRÕES DETECTADOS", report.patterns, accent=theme.AI_ACCENT))
            any_content = True
        if report.hotspots:
            self._add(SectionCard("MÓDULOS DE MAIOR RISCO", report.hotspots, accent=theme.WARNING))
            any_content = True
        if report.correlations:
            self._add(SectionCard("CORRELAÇÕES SUSPEITAS", report.correlations, accent=theme.DANGER))
            any_content = True
        if report.ai_analysis:
            self._add(AIAnalysisCard(report.ai_analysis, accent=theme.ACCENT))
            any_content = True
        if not any_content:
            self._add(InfoBanner("Nenhum padrão relevante encontrado.", accent=theme.TEXT_MUTED))
        self._layout.addStretch()
